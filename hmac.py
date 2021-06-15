#!/bin/python3
import hashlib
import os, sys

size = 0
def adjust_key(key: bytearray):
    length = len(key)
    if length < size:
        key +=  bytearray((size - length))
    elif length > size:
        key = hash_msg(key)
    return key


def hash_msg(message: bytearray):
    if size == 64:
        sha256 = hashlib.sha256(message)
        return sha256.digest()
    elif size == 128:
        sha512 = hashlib.sha512(message)
        return sha512.digest()


def calculate_key(key: bytearray, ipad=False):
    key_bytes = []
    pad = 0x00

    if ipad:
        pad = 0x36
    else:
        pad = 0x5c

    for x in range(len(key)):
        key_bytes.append(int(key[x]) ^ pad)
    
    return bytearray(key_bytes)


def hmac(key: bytearray, message: bytearray):
    ikey = calculate_key(key, True)
    okey = calculate_key(key, False)

    inner_hash = hash_msg(ikey + message)
    return hash_msg(okey + inner_hash)


def get_message():
    res = input("\u001b[0m[+] Do You want to authunticate a message or file [m/f]: ")
    if res in "mM" :
        data = bytearray(input("[+] Enter Your message: "), encoding="ascii")
        print("[+] Data length is {} bytes".format(len(data)))
        return data
    elif res in "Ff":
        print("\u001b[32m[+] Make sure size isn't too large to avoid memory hogs")
        path = input("\u001b[0m[+] Enter Your relative or absolute file path: ")
        try:
            file = open(path, "rb")
            data = bytearray(file.read())
            print("[+] Data length is {} bytes".format(len(data)))
            file.close()
            return data
        except (FileNotFoundError, FileExistsError) as e:
            print("[+] Error {}".format(e.args))
            sys.exit(1)
    else:
        print("\u001b[31m[+] UNVALID selection")
        sys.exit(1)


def get_key():
    if input("[+] Do you want to generate random key(recommended) [y/yes]: ") in "yes":
            key = bytearray(os.urandom(16))
            print("Key: {}".format(key.hex()))
            return adjust_key(key)
    else:
        key = bytearray(input("[+] Enter Your own key: "), encoding="ascii")
        return adjust_key(key)


if __name__ == "__main__":

    hash = input("""[+] Please Select which hash function to use by entering number:
1 -sha-256
2 -sha-512
==> """)

    if hash == "1":
        size = 64
    elif hash == "2":
        size = 128
    else:
        print("\u001b[31m Error wrong input Number")
        sys.exit(1)


    message = get_message()
    key = get_key()

    mac = hmac(key, message)
    print("HMAC: {}".format(mac.hex()))
