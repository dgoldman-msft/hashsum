# Define interpreter
#!/usr/bin/env python3

# Imported libraries
import hashlib
import hmac
import sys

# Uncomment the following lines for interactive debugging
# import pdb
# pdb.set_trace()

# Function to calculate HMAC's
def sumhmac(data, key, hashtype):
    # Convert the key and data to bytes if they are not already
    if not isinstance(key, bytes):
        key = key.encode()
    if not isinstance(data, bytes):
        data = data.encode()

    # Nested function to switch between different hash types
    def switch(hashtype):
        match hashtype:
            case "MD5":
                return print("HMAC (MD5): " + hmac.new(key, data, hashlib.md5).hexdigest())
            case "SHA1":
                return print("HMAC (SHA1): " + hmac.new(key, data, hashlib.sha1).hexdigest())
            case "SHA224":
                return print("HMAC (SHA224): " + hmac.new(key, data, hashlib.sha224).hexdigest())
            case "SHA256":
                return print("HMAC (SHA256): " + hmac.new(key, data, hashlib.sha256).hexdigest())
            case "SHA384":
                return print("HMAC (SHA384): " + hmac.new(key, data, hashlib.sha384).hexdigest())
            case "SHA512":
                return print("HMAC (SHA512): " + hmac.new(key, data, hashlib.sha512).hexdigest())
            case "all":
                # Calculate and print all hash types
                mdh5hash = print("HMAC (MD5): " + hmac.new(key, data, hashlib.md5).hexdigest())
                sha1hash = print("HMAC (SHA1): " + hmac.new(key, data, hashlib.sha1).hexdigest())
                sha224hash = print("HMAC (SHA224): " + hmac.new(key, data, hashlib.sha224).hexdigest())
                sha256hash = print("HMAC (SHA256): " + hmac.new(key, data, hashlib.sha256).hexdigest())
                sha384hash = print("HMAC (SHA384): " + hmac.new(key, data, hashlib.sha384).hexdigest())
                sha512hash = print("HMAC (SHA512): " + hmac.new(key, data, hashlib.sha512).hexdigest())
                return mdh5hash, sha1hash, sha224hash, sha256hash, sha384hash, sha512hash
            case _:
                # Default case if no valid hash type is provided
                return print( "Valid hash types: mdh5, sha1, sha224, sha256, sha384, sha512, all")

    # Call the switch function to process the HMAC
    switch(hashtype)

# Check command line arguments and call the function
if len(sys.argv) != 4:
    print("Usage: python sumhmac.py <message> <key> <hashtype>")
    print("hash types: mdh5, sha1, sha224, sha256, sha384, sha512, all")
else:
    print("Creating HMAC's…")
    message = sys.argv[1]
    key = sys.argv[2]
    hashtype = sys.argv[3]
    sumhmac(message, key, hashtype)