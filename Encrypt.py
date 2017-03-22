from os import urandom
from Subroutines import *


class Encrypt(Subroutines):
    def __init__(self, text_file, read):
        Subroutines.__init__(self, text_file)
        self.key = ''
        self.main(read)

    def generate_key(self):
        """
        Generates a 'random' 64-bit key, writes this key to 'key.txt'
        and stores for future use in the class.
        """
        key = hexlify(urandom(8))
        self.key = format(int(key, 16), '064b')
        Subroutines.key = self.key
        with open("key.txt", "w") as f:
            f.write(key)
            f.close()

    @staticmethod
    def to_hex(bin_str):
        """
        Writes cipher-text to ciphertext.txt

        :param bin_str: Binary string to be converted to hex
        """
        with open("ciphertext.txt", "w") as f:
            f.write(format(int(bin_str, 2), 'x'))
            f.close()

    def encrypt(self, plain_bin):
        """
        Performs encryption on the plaintext.  The plaintext is encrypted 64-bits at a time,
        each 64-bit block is divided into four 16-bit words to be encrypted.

        :param plain_bin: Plaintext as a binary string
        """
        cipher = ""
        k0 = self.key[0:16]
        k1 = self.key[16:32]
        k2 = self.key[32:48]
        k3 = self.key[48:64]

        while plain_bin:
            w0, w1, w2, w3 = plain_bin[0:16], plain_bin[16:32], plain_bin[32:48], plain_bin[48:64]
            r0 = format(int(w0, 2) ^ int(k0, 2), '016b')
            r1 = format(int(w1, 2) ^ int(k1, 2), '016b')
            r2 = format(int(w2, 2) ^ int(k2, 2), '016b')
            r3 = format(int(w3, 2) ^ int(k3, 2), '016b')

            for i in range(16):
                f0, f1 = self.f(r0, r1, i, True)
                r0_temp, r1_temp = r0, r1

                r0 = format(int(r2, 2) ^ int(f0, 2), '016b')
                r0 = r0[-1:] + r0[:-1]

                r1 = format(int((r3[1:] + r3[:1]), 2) ^ int(f1, 2), '016b')
                r2 = r0_temp
                r3 = r1_temp

            y0, y1, y2, y3 = r2, r3, r0, r1

            c0 = format(int(y0, 2) ^ int(k0, 2), '016b')
            c1 = format(int(y1, 2) ^ int(k1, 2), '016b')
            c2 = format(int(y2, 2) ^ int(k2, 2), '016b')
            c3 = format(int(y3, 2) ^ int(k3, 2), '016b')

            cipher = cipher + c0 + c1 + c2 + c3
            plain_bin = plain_bin[64:]
        self.to_hex(cipher)

    def main(self, read):
        """
        Calls appropriate functions to start encrypting.

        :param read: Boolean to read from existing 'key.txt' file or not.
        """
        if read:
            self.key = self.read_key()
        else:
            self.generate_key()
        plain_bin = self.to_bin(True)
        self.encrypt(plain_bin)
