#! /usr/bin/env python3

import sys
import os
import stat
import argparse
import nacl.utils
import nacl.public
import nacl.signing


def get_name(suffix):
    filename = args.name + suffix
    return os.path.join(args.output_directory, filename)


parser = argparse.ArgumentParser(description="Generate keys to encrypt OAuth token secrets and to sign cookies")
parser.add_argument("name", help="name of the key (used in the file name)")
parser.add_argument("output_directory", help="output directory")
args = parser.parse_args()

if not stat.S_ISDIR(os.stat(args.output_directory).st_mode):
    sys.stderr.write("ERROR: {} is not a directory\n".format(args.output_directory))
    exit(1)

key = nacl.public.PrivateKey.generate()
with open(get_name(".encryptionkey"), "wb") as out:
    out.write(key.encode())

signing_key = nacl.signing.SigningKey.generate()
with open(get_name(".signkey"), "wb") as out:
    out.write(signing_key.encode())

verify_key = signing_key.verify_key
with open(get_name(".verifykey"), "wb") as out:
    out.write(verify_key.encode())
