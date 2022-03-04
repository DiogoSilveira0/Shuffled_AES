import sys
from cipher import CipherWrapper

import os

class Speed(object):
    
    def __init__(self):
        self.buffer = os.urandom(4 * 1024)
        self.saes_enc_elapsed_time = None
        self.saes_dec_elapsed_time = None
        self.aes_enc_elapsed_time = None
        self.aes_dec_elapsed_time = None

    def saes(self):
        for i in range(100000):
            c = CipherWrapper(os.urandom(16), os.urandom(16))
            enc = c.encrypt(self.buffer)
            if c.decrypt(enc) != self.buffer:
                print("FAIL\n")
                exit()
            if self.saes_enc_elapsed_time is None or c.enc_elapsed_time < self.saes_enc_elapsed_time:
                self.saes_enc_elapsed_time = c.enc_elapsed_time
            if self.saes_dec_elapsed_time is None or c.dec_elapsed_time < self.saes_dec_elapsed_time:
                self.saes_dec_elapsed_time = c.dec_elapsed_time
            print("S-AES tests: " + str(i+1)
                + "; Encryption Time: " 
                + str(self.saes_enc_elapsed_time)
                + "; Decryption Time: "
                + str(self.saes_dec_elapsed_time), end='\r')
        return self.saes_enc_elapsed_time, self.saes_dec_elapsed_time

    def aes(self):
        for i in range(100000):
            c = CipherWrapper(os.urandom(16))
            enc = c.encrypt(self.buffer)
            if c.decrypt(enc) != self.buffer:
                print("FAIL\n")
                exit()
            if self.aes_enc_elapsed_time is None or c.enc_elapsed_time < self.aes_enc_elapsed_time:
                self.aes_enc_elapsed_time = c.enc_elapsed_time
            if self.aes_dec_elapsed_time is None or c.dec_elapsed_time < self.aes_dec_elapsed_time:
                self.aes_dec_elapsed_time = c.dec_elapsed_time
            print("AES tests: " + str(i+1) 
                + "; Encryption Time: " 
                + str(self.aes_enc_elapsed_time)
                + "; Decryption Time: "
                + str(self.aes_dec_elapsed_time), end='\r')
        return self.aes_enc_elapsed_time, self.aes_dec_elapsed_time
    
    def run(self):
        saes_enc_time, saes_dec_time = self.saes()
        print('\n----------------------------------------------------------------------------')
        aes_enc_time, aes_dec_time = self.aes()
        print('\n----------------------------------------------------------------------------')
        print("SUCCESS\nResults:")
        print(" S-AES encryption time: " + str(saes_enc_time))
        print(" S-AES decryption time: " + str(saes_dec_time))
        print(" AES encryption time: " + str(aes_enc_time))
        print(" AES decryption time: " + str(aes_dec_time))

def main():
    speed = Speed()
    speed.run()

if __name__ == "__main__":
    main()