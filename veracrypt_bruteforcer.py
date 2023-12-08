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

# Other global variables
PROCESSED_PASSWORDS = 0

logging.basicConfig(level=-logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE)])

file_write_lock = threading.Lock()

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

    logging.debug(f"Trying password: {password}")

    # Calculate the completion percentage
    percentage_completed = (PROCESSED_PASSWORDS / total_passwords) * 100

    # Calculate the remaining passwords
    passwords_remaining = total_passwords - PROCESSED_PASSWORDS

    logging.info(f"Progress: {PROCESSED_PASSWORDS}/{total_passwords} passwords tried ({percentage_completed:.2f}%), {passwords_remaining} passwords remaining")

    success, error_message = mount_volume(password, encrypted_volume, success_found, hash_type)
    if success:
        logging.info(f"Password found: {password}")
        write_password_to_file(FOUND_PASSWORD_FILE, password)
        return True, password
    else:
        logging.error(f"Failed with password '{password}': {error_message}")

    PROCESSED_PASSWORDS += 1
    output_queue.put((success, password, error_message))

def try_passwords(passwords, encrypted_volume, success_found, output_queue, hash_type):
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_THREADS) as executor:
        futures = {executor.submit(try_password, p, encrypted_volume, success_found, output_queue, len(passwords),
                                   hash_type): p for p in passwords}

        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                del futures[future]

        while not output_queue.empty():
            success, correct_password, error_message = output_queue.get()
            if success:
                logging.info(f"Password found: {correct_password}")
                write_password_to_file(FOUND_PASSWORD_FILE, correct_password)  # Write the found password to the file
                return True, correct_password
            else:
                logging.error(f"Failed with password '{correct_password}': {error_message}")

    return False, None

def main():
    global MAX_PARALLEL_THREADS
    
    parser = argparse.ArgumentParser(description="VeraCrypt BruteForcer is a Python script designed for educational and testing purposes, allowing users to systematically test passwords for VeraCrypt-encrypted volumes. This multi-threaded script leverages the power of parallel processing to test a large set of passwords concurrently, making it faster and more effective.")
    parser.add_argument("--password_file", required=True, help="Path to the file containing passwords to test.")
    parser.add_argument("--encrypted_volume", required=True, help="Path to the encrypted volume.")
    parser.add_argument("--max_threads", type=int, help="Number of max parallel threads execution.")
    parser.add_argument("--hash_type", choices=['BLAKE2s-256', 'SHA-256', 'SHA-512', 'Whirlpool', 'Streebog'],
                        help="Hash algorithm type. If none is specified, all of these will be tested.")

    args = parser.parse_args()

    if args.max_threads:
        MAX_PARALLEL_THREADS = args.max_threads

    # Check prerequisites
    check_prerequisites(args.password_file, args.encrypted_volume, args.hash_type)

    start_time = timeit.default_timer()

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
        f"=============================================================================================="
    )

    success_found = threading.Event()  # Flag to indicate if the password has been found
    output_queue = queue.Queue()

    # Create a copy of the input file with a timestamp
    with file_write_lock:
        create_backup(TESTED_PASSWORDS_FILE)

    success, correct_password = try_passwords(password_to_test_set, args.encrypted_volume, success_found, output_queue,
                                              args.hash_type)
    elapsed_time = timeit.default_timer() - start_time

    logging.info(f"Number of passwords tested: {len(password_to_test_set)}")
    logging.info(f"Total time elapsed: {elapsed_time:.2f} seconds")

    if success:
        logging.info(f"Successfully mounted the volume with password: {correct_password}")
    else:
        logging.info("Unable to mount the volume with any of the provided passwords.")

def create_backup(original_file):
    # Get the file name without extension
    file_name, file_extension = os.path.splitext(original_file)

    # Create a copy with the original name and a timestamp in the specified directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = os.path.join(BACKUP_DIRECTORY, f"{file_name}_{timestamp}{file_extension}")

    shutil.copy(original_file, backup_file)
    logging.info(f"Backup created: {backup_file}")

def write_password_to_file(file_path, password):
    with file_write_lock:
        with Path(file_path).open("a") as file:
            if file.tell() != 0:
                file.write("\n")
            file.write(password)

if __name__ == "__main__":
    main()