import subprocess
import argparse
import timeit
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import queue
import shutil
import os
from datetime import datetime
import configparser
from pathlib import Path

# Read configuration from the file
config = configparser.ConfigParser()
config.read('config.ini')

MOUNT_POINT = config['Configuration']['MOUNT_POINT']
VERACRYPT_EXECUTABLE = config['Configuration']['VERACRYPT_EXECUTABLE']
BACKUP_DIRECTORY = config['Configuration']['BACKUP_DIRECTORY']
FOUND_PASSWORD_FILE = config['Configuration']['FOUND_PASSWORD_FILE']
TESTED_PASSWORDS_FILE = config['Configuration']['TESTED_PASSWORDS_FILE']
MAX_PARALLEL_THREADS = int(config['Configuration']['MAX_PARALLEL_THREADS'])
LOG_FILE = config['Configuration']['LOG_FILE']
LOG_TO_FILE_ENABLED = config['Configuration'].getboolean('LOG_TO_FILE_ENABLED', fallback=True)
BENCHMARK_TEST_ITERATION_NUMBER = int(config['Configuration']['BENCHMARK_TEST_ITERATION_NUMBER'])
BENCHMARK_RESULT_FILE = config['Configuration']['BENCHMARK_RESULT_FILE']
BENCHMARK_MINIMUM_THREADS = int(config['Configuration']['BENCHMARK_MINIMUM_THREADS'])
BENCHMARK_MAXIMUM_THREADS = int(config['Configuration']['BENCHMARK_MAXIMUM_THREADS'])

# Other global variables
PROCESSED_PASSWORDS = 0
START_TIME = timeit.default_timer()  # Variable to store the start time for measuring processing speed
BENCHMARK_MODE = False
file_write_lock = threading.Lock()

def configure_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Remove default logging
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    if LOG_TO_FILE_ENABLED:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

def check_prerequisites(password_file, encrypted_volume, hash_type):
    # Check if the VeraCrypt executable exists
    if not os.path.exists(VERACRYPT_EXECUTABLE):
        logging.error("VeraCrypt executable not found. Please check the path specified in VERACRYPT_EXECUTABLE.")
        raise SystemExit(1)

    # Check if the backup directory exists, create it if not
    if not os.path.exists(BACKUP_DIRECTORY):
        os.makedirs(BACKUP_DIRECTORY)
        logging.info(f"Backup directory created: {BACKUP_DIRECTORY}")

    # Check if the password file exists
    if not os.path.exists(password_file):
        logging.error(f"Password file not found: {password_file}")
        raise SystemExit(1)

    # Check if the encrypted volume file exists
    if not os.path.exists(encrypted_volume):
        logging.error(f"Encrypted volume file not found: {encrypted_volume}")
        raise SystemExit(1)

    # Check if the tested passwords file exists, create it if not
    create_tested_passwords_file(password_file, hash_type)

    #Disable logging in BENCHMARK mode
    if BENCHMARK_MODE:
        LOG_TO_FILE_ENABLED = False

def create_tested_passwords_file(password_file, hash_type):
    global TESTED_PASSWORDS_FILE
    # Determine the suffix based on the hash_type parameter
    suffix = f"_{hash_type}" if hash_type else "_ALL_HASH"

    tested_passwords_file_name, file_extension = os.path.splitext(TESTED_PASSWORDS_FILE)
    TESTED_PASSWORDS_FILE = os.path.join(tested_passwords_file_name + suffix + file_extension)

    if not os.path.exists(TESTED_PASSWORDS_FILE):
        with Path(TESTED_PASSWORDS_FILE).open("w"):
            pass
        logging.info(f"Tested passwords file created: {TESTED_PASSWORDS_FILE}")

def mount_volume(password, encrypted_volume, success_found, hash_type):
    command = [
        VERACRYPT_EXECUTABLE,
        "--text",
        "--non-interactive",
        *(["--hash", hash_type] if hash_type else []),
        "--password",
        password,
        encrypted_volume,
        MOUNT_POINT
    ]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        write_password_to_file(TESTED_PASSWORDS_FILE, password)  # Write the tested password to the file
        success = result.returncode == 0
        if success:
            success_found.set()  # Set the success flag to stop other threads
        return success, None
    except subprocess.CalledProcessError as e:
        write_password_to_file(TESTED_PASSWORDS_FILE, password)  # Write the tested password to the file
        return False, str(e)

def try_password(password, encrypted_volume, success_found, output_queue, total_passwords, hash_type):
    global PROCESSED_PASSWORDS  # Global declaration here
    global START_TIME  # Reference to the global variable

    if not BENCHMARK_MODE:
        logging.debug(f"Trying password: {password}")

        # Calculate the completion percentage
        percentage_completed = (PROCESSED_PASSWORDS / total_passwords) * 100

        # Calculate the remaining passwords
        passwords_remaining = total_passwords - PROCESSED_PASSWORDS

        # Calculate processing speed
        current_time = timeit.default_timer()
        elapsed_time = current_time - START_TIME
        processing_speed = PROCESSED_PASSWORDS / elapsed_time 

        # Calculate estimated remaining time in seconds
        remaining_time_minutes = (passwords_remaining) // processing_speed // 60 if processing_speed > 1 else passwords_remaining // 60
    
        log_message = f"Progress: {PROCESSED_PASSWORDS}/{total_passwords} passwords tried. " \
                    f"Processing speed: {processing_speed:.2f} passwords per second. " \
                    f"({percentage_completed:.2f}%), {passwords_remaining} passwords and {remaining_time_minutes} minutes remaining. "

        logging.info(log_message)
        
    success, error_message = mount_volume(password, encrypted_volume, success_found, hash_type)
    write_password_to_file(FOUND_PASSWORD_FILE, password)  # Write the found password to the file

    PROCESSED_PASSWORDS += 1
    if BENCHMARK_MODE:
        return False, None
    
    if success:
        logging.info(f"Password found: {password}")
        return True, password
    else:
        logging.error(f"Failed with password '{password}': {error_message}")
    
    
    output_queue.put((success, password, error_message))

def try_passwords(passwords, encrypted_volume, success_found, output_queue, hash_type, num_threads):
    global PROCESSED_PASSWORDS
    PROCESSED_PASSWORDS = 0

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(try_password, p, encrypted_volume, success_found, output_queue, len(passwords),
                                   hash_type): p for p in passwords}

        while futures and not success_found.is_set():
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                del futures[future]
                
                if result is not None: 
                    success, value = result
                    correct_password, error_message = value, None
                    if success:
                        return True, correct_password

    return False, None

def create_backup(original_file):
    # Get the file name without extension
    file_name, file_extension = os.path.splitext(original_file)

    # Create a copy with the original name and a timestamp in the specified directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = os.path.join(BACKUP_DIRECTORY, f"{file_name}_{timestamp}{file_extension}")

    shutil.copy(original_file, backup_file)
    logging.info(f"Backup created: {backup_file}")

def write_password_to_file(file_path, password):
    if not BENCHMARK_MODE:
        with file_write_lock:
            with Path(file_path).open("a") as file:
                if file.tell() != 0:
                    file.write("\n")
                file.write(password)

def benchmark_try_passwords(passwords, encrypted_volume, num_threads, hash_type):
    best_time = float('inf')
    best_threads = 0
    benchmark_results = []

    for num_threads in range(BENCHMARK_MINIMUM_THREADS, BENCHMARK_MAXIMUM_THREADS + 1):
        current_iteration = num_threads - BENCHMARK_MINIMUM_THREADS + 1
        total_iterations = BENCHMARK_MAXIMUM_THREADS - BENCHMARK_MINIMUM_THREADS + 1

        logging.info(f"Testing {num_threads} threads (Iteration {current_iteration}/{total_iterations})")

        START_TIME = timeit.default_timer()
        success, _ = try_passwords(passwords, encrypted_volume, threading.Event(), queue.Queue(), hash_type, num_threads)
        elapsed_time = timeit.default_timer() - START_TIME

        passwords_tested_per_second = len(passwords) / elapsed_time
        benchmark_results.append(f"Threads: {num_threads}, Time: {elapsed_time:.2f} seconds, Passwords tested per second: {passwords_tested_per_second:.2f}")

        logging.info(f"Threads: {num_threads}, Total Time: {elapsed_time:.2f} seconds, Total Passwords Tested: {len(passwords)}, Passwords per Second: {passwords_tested_per_second:.2f}")

        # Update the best time if current time is better than the previous one
        if elapsed_time < best_time:
            best_time = elapsed_time
            best_threads = num_threads

    logging.info(f"Benchmark completed. Best time obtained with {best_threads} threads: {best_time:.2f} seconds")

    with open(BENCHMARK_RESULT_FILE, "w") as benchmark_file:
        for result in benchmark_results:
            benchmark_file.write(result + "\n")
        logging.info(f"Benchmark results written to {BENCHMARK_RESULT_FILE}")


def main():
    global MAX_PARALLEL_THREADS
    global START_TIME 
    global BENCHMARK_MODE
    
    parser = argparse.ArgumentParser(description="VeraCrypt BruteForcer is a Python script designed for educational and testing purposes, allowing users to systematically test passwords for VeraCrypt-encrypted volumes. This multi-threaded script leverages the power of parallel processing to test a large set of passwords concurrently, making it faster and more effective.")
    parser.add_argument("--password_file", required=False, help="Path to the file containing passwords to test.")
    parser.add_argument("--encrypted_volume", required=True, help="Path to the encrypted volume.")
    parser.add_argument("--max_threads", type=int, help="Number of max parallel threads execution.")
    parser.add_argument("--hash_type", choices=['BLAKE2s-256', 'SHA-256', 'SHA-512', 'Whirlpool', 'Streebog'],
                        help="Hash algorithm type. If none is specified, all of these will be tested.")
    parser.add_argument("--benchmark", action="store_true", help="Run the script in benchmark mode.")

    args = parser.parse_args()

    if args.max_threads:
        MAX_PARALLEL_THREADS = args.max_threads

    BENCHMARK_MODE = args.benchmark
    #Password file parameter is required when not in benchmark mode
    if not BENCHMARK_MODE and not args.password_file:
        parser.error("--password_file is required when not in benchmark mode.")

    # Configure logging
    configure_logging()

    if not BENCHMARK_MODE:
        # Check prerequisites
        check_prerequisites(args.password_file, args.encrypted_volume, args.hash_type)

        # Read passwords to test from the input file
        with Path(args.password_file).open('r') as file:
            password_to_test_set = {line.strip() for line in file}

        # Read the list of the already tested password
        with Path(TESTED_PASSWORDS_FILE).open('r') as file2:
            tested_password_set = {line.strip() for line in file2}

        # Calculate the difference between the two sets, so that password will contain just untested passwords
        password_to_test_set = password_to_test_set - tested_password_set

        # Log the script configuration
        logging.info(
            f"===== Starting script with the following configuration:===== \n"
            f"PASSWORD FILE: {args.password_file}\n"
            f"TESTED PASSWORD FILE: {TESTED_PASSWORDS_FILE}\n"
            f"ENCRYPTED VOLUME: {args.encrypted_volume}\n"
            f"PARALLEL THREAD NUMBER: {MAX_PARALLEL_THREADS}\n"
            f"HASH TYPE: {'ALL HASH' if not args.hash_type else args.hash_type}\n"
            f"MOUNT POINT: {MOUNT_POINT}\n"
            f"NUMBER OF PASSWORD TO TEST: {len(password_to_test_set)}\n"
            f"NUMBER OF PASSWORD TESTED: {len(tested_password_set)}\n"
            f"LOG TO FILE ENABLED: {LOG_TO_FILE_ENABLED}\n"
            f"=============================================================================================="
        )

        success_found = threading.Event()  # Flag to indicate if the password has been found
        output_queue = queue.Queue()

        # Create a copy of the input file with a timestamp
        with file_write_lock:
            create_backup(TESTED_PASSWORDS_FILE)

        success, correct_password = try_passwords(password_to_test_set, args.encrypted_volume, success_found, output_queue,
                                              args.hash_type, MAX_PARALLEL_THREADS)
        
        elapsed_time = timeit.default_timer() - START_TIME

        logging.info(f"Number of passwords tested: {len(password_to_test_set)}")
        logging.info(f"Total time elapsed: {elapsed_time:.2f} seconds")

        if success:
            logging.info(f"Successfully mounted the volume with password: {correct_password}")
        else:
            logging.info("Unable to mount the volume with any of the provided passwords.")
    else:
        password_to_test_set = ["aaaaa"] * BENCHMARK_TEST_ITERATION_NUMBER
        benchmark_try_passwords(password_to_test_set, args.encrypted_volume, MAX_PARALLEL_THREADS, args.hash_type)

if __name__ == "__main__":
    main()