import sys
from cipher import CipherWrapper

class Decryptor(object):

    def __init__(self, f, k, sk=None):
        self.cipher = CipherWrapper(k, sk)
        self.f = f
        f = open(self.f, 'rb')
        self.plaintext = f.read()
        f.close()

    def decrypt(self):
        ciphertext = self.cipher.decrypt(self.plaintext)
        f = open(self.f, 'wb')
        f.write(ciphertext)
        f.close()

def main():
    args = sys.argv
    l = len(args)
    decryptor = Decryptor('test_file', args[1], None if l < 3 else args[2])
    decryptor.decrypt()

if __name__ == "__main__":
    main()
