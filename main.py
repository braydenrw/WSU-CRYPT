from Encrypt import *
from Decrypt import *
from os import path
from time import time


if __name__ == '__main__':
    plain_file = "plaintext.txt"
    cipher_file = "ciphertext.txt"

    encrypt = raw_input("Encrypting or decrypting [e/d]: ")

    if encrypt == 'e':
        assert path.exists('./'+plain_file)
        yn = raw_input("Use a pre-existing key saved in 'key.txt'? (will generate random 64-bit key if no) [y/n]: ")

        start = time()
        Encrypt(plain_file, True) if yn == 'y' else Encrypt(plain_file, False)
        end = time()

        with open("key.txt", "r") as f:
            key_string = f.read()
            f.close()

        print "Encrypting", plain_file, "with key", key_string
        with open(cipher_file, "r") as f:
            cipher_string = f.read()
            f.close()

        print "\n===Resulting encrypted hex===\n", cipher_string, "\nEncrypted in ", end-start, "seconds"

    elif encrypt == 'd':
        assert path.exists('./' + cipher_file)
        with open("key.txt", "r") as f:
            key_string = f.read()
            f.close()

        print "\nDecrypting", cipher_file, "with key", key_string, "\n\n===Resulting decrypted text==="
        start = time()
        Decrypt(cipher_file)
        end = time()

        print "\nDecrypted in", end-start, "seconds"

    else:
        print "Invalid input please re-run"
