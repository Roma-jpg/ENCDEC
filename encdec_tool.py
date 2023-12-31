import argparse
import os
import ctypes
import sys
from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def read_or_generate_key(key_path):
    try:
        with open(key_path, 'rb') as filekey:
            return filekey.read()
    except FileNotFoundError:
        new_key = generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(new_key)
        return new_key


def encrypt_file(input_file, output_file, key, elevate=False):
    try:
        if os.path.basename(input_file) == "desktop.ini":
            print(f'Skipping encryption for file "{input_file}" (desktop.ini)')
            return

        with open(input_file, 'rb') as file:
            original = file.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(original)

        with open(output_file, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        print(f'File "{input_file}" encrypted successfully.')
    except PermissionError as pe:
        if not elevate:
            choice = input(
                f'Permission error for file "{input_file}". Do you want to elevate to admin to encrypt this file? (yes/no): ')
            if choice.lower() == 'yes':
                elevate_and_encrypt(input_file, output_file, key)
        else:
            print(f'Error processing file "{input_file}": {str(pe)}')

    except Exception as e:
        print(f'Error processing file "{input_file}": {str(e)}')


def decrypt_file(input_file, output_file, key, elevate=False):
    try:
        if os.path.basename(input_file) == "desktop.ini":
            print(f'Skipping decryption for file "{input_file}" (desktop.ini)')
            return

        with open(input_file, 'rb') as enc_file:
            encrypted = enc_file.read()

        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)

        with open(output_file, 'wb') as dec_file:
            dec_file.write(decrypted)

        print(f'File "{input_file}" decrypted successfully.')
    except PermissionError as pe:
        if not elevate:
            choice = input(
                f'Permission error for file "{input_file}". Do you want to elevate to admin to decrypt this file? (yes/no): ')
            if choice.lower() == 'yes':
                elevate_and_decrypt(input_file, output_file, key)
        else:
            print(f'Error processing file "{input_file}": {str(pe)}')

    except Exception as e:
        print(f'Error processing file "{input_file}": {str(e)}')


def process_folder(folder_path, key, action, allowed_extensions=None, elevate=False):
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            if allowed_extensions:
                _, file_extension = os.path.splitext(file_name)
                file_extension = file_extension.lower()
                if file_extension not in allowed_extensions:
                    continue

            action(file_path, file_path, key, elevate)


def elevate_and_encrypt(input_file, output_file, key):
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    encrypt_file(input_file, output_file, key, elevate=True)


def elevate_and_decrypt(input_file, output_file, key):
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    decrypt_file(input_file, output_file, key, elevate=True)


def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file or folder using Fernet encryption.')

    # Optional arguments
    parser.add_argument('-m', '--mode', choices=['enc', 'dec'], help='Encryption mode: "enc" or "dec"')
    parser.add_argument('-k', '--key', help='Key file path')
    parser.add_argument('-e', '--extensions', nargs='+', help='List of file extensions to encrypt')
    parser.add_argument('-GK', '--generate-keyfile', action='store_true',
                        help='Generate a new key and save it to keyfile.key')

    # Positional arguments (if -GK is not specified)
    if not any(arg in sys.argv for arg in ['-GK', '--generate-keyfile']):
        parser.add_argument('path', help='Input file or folder path')
        parser.add_argument('mode', choices=['enc', 'dec'], help='Encryption mode: "enc" or "dec"')
        parser.add_argument('key', help='Key file path')

    args = parser.parse_args()

    if args.generate_keyfile:
        new_key = generate_key()
        with open('keyfile.key', 'wb') as key_file:
            key_file.write(new_key)
        print(f'New key generated and saved to keyfile.key')
        return

    path = args.path
    mode = args.mode
    key_path = args.key
    extensions = args.extensions

    if key_path:
        key = read_or_generate_key(key_path)
    else:
        new_key = generate_key()
        key = new_key
        with open('keyfile.key', 'wb') as key_file:
            key_file.write(new_key)
        print(f'New key generated and saved to keyfile.key')

    if os.path.isfile(path):
        if mode == 'enc':
            encrypt_file(path, path, key)
        elif mode == 'dec':
            decrypt_file(path, path, key)
    elif os.path.isdir(path):
        if mode == 'enc':
            process_folder(path, key, encrypt_file, extensions)
        elif mode == 'dec':
            process_folder(path, key, decrypt_file, extensions)
    else:
        print(f'Invalid input path: "{path}"')


if __name__ == "__main__":
    main()
