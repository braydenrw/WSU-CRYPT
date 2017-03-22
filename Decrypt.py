from Subroutines import *
from binascii import unhexlify


class Decrypt(Subroutines):
    def __init__(self, text_file):
        Subroutines.__init__(self, text_file)
        self.key = ''
        self.rnd = 0
        self.main()

    @staticmethod
    def print_plain(plain_bin):
        """
        Prints plaintext from a binary string.

        :param plain_bin: Plaintext as a binary string
        """
        plain_hex = format(int(plain_bin, 2), 'x')
        x = plain_hex.__len__()
        if x % 2 != 0:
            x = x + 2 - x % 2
        print unhexlify(format(int(plain_hex, 16), '0' + str(x) + 'x'))

    def decrypt(self, cipher_bin):
        """
        Performs decryption on the cipher-text.  The cipher-text is decypted 64-bits at a time,
        each 64-bit block is divided into four 16-bit words to be decrypted.

        :param cipher_bin: Cipher-text as a binary string
        """
        plain = ""
        k0 = self.key[0:16]
        k1 = self.key[16:32]
        k2 = self.key[32:48]
        k3 = self.key[48:64]

        while cipher_bin:
            w0, w1, w2, w3 = cipher_bin[0:16], cipher_bin[16:32], cipher_bin[32:48], cipher_bin[48:64]
            r0 = format(int(w0, 2) ^ int(k0, 2), '016b')
            r1 = format(int(w1, 2) ^ int(k1, 2), '016b')
            r2 = format(int(w2, 2) ^ int(k2, 2), '016b')
            r3 = format(int(w3, 2) ^ int(k3, 2), '016b')

            for i in range(16):
                f0, f1 = self.f(r0, r1, self.rnd, False)
                r0_temp, r1_temp = r0, r1

                r2 = r2[1:] + r2[:1]
                r0 = format(int(r2, 2) ^ int(f0, 2), '016b')

                r1 = format(int(r3, 2) ^ int(f1, 2), '016b')
                r1 = r1[-1:] + r1[:-1]
                r2 = r0_temp
                r3 = r1_temp

                self.rnd += 1
                pass

            y0, y1, y2, y3 = r2, r3, r0, r1

            c0 = format(int(y0, 2) ^ int(k0, 2), '016b')
            c1 = format(int(y1, 2) ^ int(k1, 2), '016b')
            c2 = format(int(y2, 2) ^ int(k2, 2), '016b')
            c3 = format(int(y3, 2) ^ int(k3, 2), '016b')

            plain = plain + c0 + c1 + c2 + c3
            cipher_bin = cipher_bin[64:]

        self.print_plain(plain)

    def main(self):
        """
        Calls appropriate functions to start decrypted.

        """
        self.key = self.read_key()
        cipher_bin = self.to_bin(False)
        self.decrypt(cipher_bin)
