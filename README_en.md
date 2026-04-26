# ENCDEC

## Description

**ENCDEC** is a command-line tool for encrypting and decrypting files or folders using the Fernet symmetric encryption algorithm. It is a simple and reliable way to protect sensitive data.

## Features
- Encrypt and decrypt individual files.
- Encrypt and decrypt entire folders.
- Specify the encryption or decryption mode.
- Automatically generate and save a new encryption key or use an existing one.
- Specify file extensions for encryption or decryption.

## Installation

```
# Clone the repository 
git clone https://github.com/Roma-jpg/ENCDEC.git

# Navigate to the project directory
cd ENCDEC

# Install dependencies
pip install -r requirements.txt

# Display the help command
python encdec_tool.py --help
```

Result:

```usage: whatif.py [-h] [-m {enc,dec}] [-k KEY] [-e EXTENSIONS [EXTENSIONS ...]] [-GK] path {enc,dec} key

Encrypt or decrypt a file or folder using Fernet encryption.

positional arguments:
  path                  Input file or folder path
  {enc,dec}             Encryption mode: "enc" or "dec"
  key                   Key file path

options:
  -h, --help            show this help message and exit
  -m {enc,dec}, --mode {enc,dec}
                        Encryption mode: "enc" or "dec"
  -k KEY, --key KEY     Key file path
  -e EXTENSIONS [EXTENSIONS ...], --extensions EXTENSIONS [EXTENSIONS ...]
                        List of file extensions to encrypt
  -GK, --generate-keyfile
                        Generate a new key and save it to keyfile.key

```

## Usage

#### Encrypting a single file:
```
python encdec_tool.py -f "path/to/file.ext" -m enc
```
This will not only encrypt the file itself, but also create a file named "keyfile.key". This file contains the key needed to decrypt your files. Do not lose it, and keep it in a safe place.
Please note that this only works the first time. On subsequent runs, you will need to specify the --key parameter every time to avoid losing your files.

#### Decrypting a single file:
```
python encdec_tool.py -f "path/to/file.ext" -m dec -k keyfile.key
```

Please note that during decryption, we always specify the keyfile used to encrypt the file. Without it, decryption will fail or permanently corrupt the file. Please be careful.
Also note that "enc" has been replaced with "dec" here.
This corresponds to "encrypt" and "decrypt," respectively.

#### Folder Encryption
```
python encdec_tool.py -f ./test_folder/ -m enc -k keyfile.key
```
In this case, we encrypt absolutely all files in the specified folder using the key from keyfile.key. All files will be encrypted with this key.
Note that the program encrypts files recursively, so files in subfolders will also be encrypted.

#### Decrypting a folder
```
python encdec_tool.py -f ./test_folder/ -m dec -k keyfile.key
```

Here, we do the opposite. We use the key from the file to decrypt all the files in the folder. Once the program finishes running, all files will be decrypted.

#### Filtering Files
Suppose you need to encrypt all the videos in a folder but leave the other files alone. In that case, use the file extension filter.

```
python encdec_tool.py -f ./test_folder/ -m enc -k keyfile.key -e .mp4 .mkv
```

By adding "-e .mp4 .mkv", you are telling the program to encrypt only files with the .mp4 and .mkv extensions.

#### Generating the keyfile.key file
If you want to create the key file first, this is the right approach. 
To do this, enter the following:
```
python encdec_tool.py -GK
# Или
python encdec_tool --generate-keyfile
```
You will then have a keyfile.key that you can use.

### Conclusion:
You can use this tool to protect your own files—or someone else’s; that’s up to you. However, the author is not responsible if anyone’s files are damaged as a result of using this program.

### License: MIT
