# hashsum
Hash-based Message Authentication Code Generator

## Getting Started with hashsum

This script was created in python

### DESCRIPTION
This script calculates HMAC (Hash-based Message Authentication Code) for a given message and key using various hash algorithms.

Functions: Calculates and prints the HMAC for the given data and key using the specified hash type.

    hashsum(data, key, hashtype, debug=False):

Parameters:

        data (str): The message to hash.
        key (str): The key to use for hashing.
        hashtype (str): The hash type to use. Valid options are "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "all".
        debug (bool): If True, enables debug logging. Default is False.

Usage: Run the script from the command line with the following arguments:

    message (str): The message to hash.
    key (str): The key to use for hashing.
    hashtype (str): The hash type to use. Valid options are "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "all".
    -dbg, --debug (optional): Enable debug logging.

Example:

    python hashsum.py "Hello, World!" "secret_key" "SHA256"