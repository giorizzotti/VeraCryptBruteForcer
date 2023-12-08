# VeraCrypt BruteForcer

## Overview

VeraCrypt BruteForcer is a Python script designed for educational and testing purposes, allowing users to systematically test passwords for VeraCrypt-encrypted volumes. This multi-threaded script leverages the power of parallel processing to test a large set of passwords concurrently, making it faster and more effective.

### Password Input File

The brute-force attempts are conducted using a text file provided as input to the script. This file should contain one password per line, allowing the script to systematically test each password for the encrypted volume.

## Features

- **Multi-Threaded Processing:** The script utilizes multi-threading to test multiple passwords simultaneously, improving performance on multi-core systems. The number of parallel threads can be specified as a parameter.

- **Tested Passwords Tracking:** Successfully tested passwords are recorded in a file, preventing redundant attempts and optimizing the password testing process.

- **Backup Functionality:** Before testing, the script creates a backup of the list of tested passwords, ensuring data integrity and allowing recovery in case of unexpected errors.

- **Algorithm-Specific Hashing:** Users can specify the hash algorithm used on the volume, such as BLAKE2s-256, SHA-256, SHA-512, Whirlpool, or Streebog, to accelerate the execution. If no algorithm is specified as parameter, all of those will be tested during the process.

- **Detailed Logging:** The script provides detailed logs, including progress updates, success/failure information, and timestamps, aiding in analysis and troubleshooting.

## Usage

### Prerequisites

- [VeraCrypt](https://www.veracrypt.fr/) executable properly configured in the `config.ini` file.
- Python 3.x
- Password file with a list of passwords to test (provide as input to the script).
- Encrypted VeraCrypt volume file for password testing.

### Installation

Clone the repository and configure the `config.ini` file with the necessary paths and settings.

```bash
git clone https://github.com/giorizzotti/VeraCryptBruteForcer.git
cd veracrypt-bruteforcer
pip install -r requirements.txt
# Edit config.ini with your settings
```

### Execution
Run the script with the required command-line arguments.

```bash
python veracrypt_bruteforcer.py --password_file path/to/passwords.txt --encrypted_volume path/to/encrypted_volume.vc --hash_type SHA-256 --max_threads 8
```

For additional options, refer to the script's command-line interface.
```bash
python veracrypt_bruteforcer.py --help
```

```bash
options:
  -h, --help            show this help message and exit
  --password_file PASSWORD_FILE
                        Path to the file containing passwords to test.
  --encrypted_volume ENCRYPTED_VOLUME
                        Path to the encrypted volume.
  --max_threads MAX_THREADS
                        Number of max parallel threads execution.
  --hash_type {BLAKE2s-256,SHA-256,SHA-512,Whirlpool,Streebog}
                        Hash algorithm type. If none is specified, all of these will be tested.
```

## Contributions
Contributions are welcome! Feel free to fork the repository, make improvements, and submit a pull request. 

## License
This project is licensed under the GNU General Public License (GPL).

## Contact
Author: Giovanni Rizzotti
Email: giorizzotti@gmail.com