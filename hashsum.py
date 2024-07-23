#!/usr/bin/env python3
import hashlib
import sys

def hashsum(data, hashtype):
    def switch_case(hashtype):
    if hashtype.lower() == "md5" or hashtype.upper() == "MD5":
	    return hashlib.md5(data.encode()).hexdigest()
	elif hashtype.lower() == "sha1" or hashtype.upper() == "SHA1":
            return hashlib.sha1(data.encode()).hexdigest()
	elif hashtype.lower() == "sha224" or hashtype.upper() == "SHA224":
            return hashlib.sha224(data.encode()).hexdigest()
	elif hashtype.lower() == "sha256" or hashtype.upper() == "SHA256":
            return hashlib.sha256(data.encode()).hexdigest()
	elif hashtype.lower() == "sha512" or hashtype.upper() == "SHA512":
            return hashlib.sha512(data.encode()).hexdigest()
	elif hashtype == "all":
            md5sum = hashlib.md5(data.encode()).hexdigest()
            sha1sum = hashlib.sha1(data.encode()).hexdigest()
            sha224sum = hashlib.sha224(data.encode()).hexdigest()
            sha256sum = hashlib.sha256(data.encode()).hexdigest()
            sha512sum = hashlib.sha512(data.encode()).hexdigest()
            return md5sum, sha1sum, sha224sum, sha256sum, sha512sum
        else:
            return "You did not specify a valid hash type to return!"

    # Call the switch_case function
    return switch_case(hashtype)

# Call the function with a message and a hash type from command line arguments
if len(sys.argv) != 3:
    print("Usage: python hashsum.py <message> <hashtype>")
    print("hash types: MD5, SHA1, SHA224, SHA256, SHA512, all")
else:
    print("Creating hashes...")
    message = sys.argv[1]
    hashtype = sys.argv[2]
    result = hashsum(message, hashtype)
    if hashtype == "all":
        for hash_type, hash_value in zip(["MD5", "SHA1", "SHA224", "SHA256", "SHA512"], result):
            print(f"HASH ({hash_type}): {hash_value}")
    else:
        print(f"HASH ({hashtype}): {result}")