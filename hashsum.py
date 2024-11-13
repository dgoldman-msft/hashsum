# Define interpreter
#!/usr/bin/env python3

# Imported libraries
import argparse
import hashlib
import hmac
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Function to calculate HMAC's
def hashsum(data, key, hashtype, debug=False):
    if debug:
        print(f"{Fore.RED}Calling display_and_select{Style.RESET_ALL}")

    # Convert the key and data to bytes if they are not already
    if not isinstance(key, bytes):
        if debug:
            print(f"{Fore.RED}Converting key to bytes{Style.RESET_ALL}")
        key = key.encode()
    if not isinstance(data, bytes):
        data = data.encode()

    # Nested function to switch between different hash types
    def switch(hashtype):
        if debug:
            print(f"{Fore.RED}Selecting Hash Type{Style.RESET_ALL}")

        # Using if-elif-else to determine the hash type due to backwards compatibility with Python 3.7 and earlier
        try:
            if hashtype == "MD5":
                return print(f"{Fore.GREEN}HMAC (MD5): {Fore.YELLOW}" + hmac.new(key, data, hashlib.md5).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "SHA1":
                return print(f"{Fore.GREEN}HMAC (SHA1): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha1).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "SHA224":
                return print(f"{Fore.GREEN}HMAC (SHA224): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha224).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "SHA256":
                return print(f"{Fore.GREEN}HMAC (SHA256): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha256).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "SHA384":
                return print(f"{Fore.GREEN}HMAC (SHA384): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha384).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "SHA512":
                return print(f"{Fore.GREEN}HMAC (SHA512): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha512).hexdigest() + f"{Style.RESET_ALL}")
            elif hashtype == "all":
                # Calculate and print all hash types
                mdh5hash = print(f"{Fore.GREEN}HMAC (MD5): {Fore.YELLOW}" + hmac.new(key, data, hashlib.md5).hexdigest() + f"{Style.RESET_ALL}")
                sha1hash = print(f"{Fore.GREEN}HMAC (SHA1): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha1).hexdigest() + f"{Style.RESET_ALL}")
                sha224hash = print(f"{Fore.GREEN}HMAC (SHA224): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha224).hexdigest() + f"{Style.RESET_ALL}")
                sha256hash = print(f"{Fore.GREEN}HMAC (SHA256): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha256).hexdigest() + f"{Style.RESET_ALL}")
                sha384hash = print(f"{Fore.GREEN}HMAC (SHA384): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha384).hexdigest() + f"{Style.RESET_ALL}")
                sha512hash = print(f"{Fore.GREEN}HMAC (SHA512): {Fore.YELLOW}" + hmac.new(key, data, hashlib.sha512).hexdigest() + f"{Style.RESET_ALL}")
                return mdh5hash, sha1hash, sha224hash, sha256hash, sha384hash, sha512hash
            else:
                # Default case if no valid hash type is provided
                return print(f"{Fore.RED}Valid hash types: mdh5, sha1, sha224, sha256, sha384, sha512, all{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

    # Call the switch function to process the HMAC
    switch(hashtype)

# Check command line arguments and call the function
if __name__ == "__main__":
    """
    This script calculates HMAC (Hash-based Message Authentication Code) for a given message and key using various hash algorithms.

    Functions:
        hashsum(data, key, hashtype, debug=False):

        Calculates and prints the HMAC for the given data and key using the specified hash type.

        Parameters:
            data (str): The message to hash.
            key (str): The key to use for hashing.
            hashtype (str): The hash type to use. Valid options are "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "all".
            debug (bool): If True, enables debug logging. Default is False.
    Usage:

        Run the script from the command line with the following arguments:
            message (str): The message to hash.
            key (str): The key to use for hashing.
            hashtype (str): The hash type to use. Valid options are "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "all".
            -dbg, --debug (optional): Enable debug logging.

    Example:
        python hashsum.py "Hello, World!" "secret_key" "SHA256"
    """
    parser = argparse.ArgumentParser(description="Calculate HMAC for a given message and key.")
    parser.add_argument("message", type=str, help="The message to hash.")
    parser.add_argument("key", type=str, help="The key to use for hashing.")
    parser.add_argument("hashtype", type=str, choices=["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "all"], help="The hash type to use.")

    debug_group = parser.add_argument_group('Debug options')
    debug_group.add_argument("-dbg", "--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    hashsum(args.message, args.key, args.hashtype)
