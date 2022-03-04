import const

import random
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hashlib import shake_128

from itertools import permutations
from copy import copy

class S_AES(object):

    def __init__(self, k, sk):
        self.enc_elapsed_time = None
        self.dec_elapsed_time = None
        self.sk = sk
        # Get the key schedule:
        # (expand the key)
        self.k = self.k_expansion(k)
        # This will save the cipher's state:
        self.state = None
        # Get some lookup tables:
        self.sbox = const.SBOX
        self.rcon = const.RCON
        self.inv_sbox = const.INV_SBOX
        # Get shuffle values on setup to increase speed
        # (That's why @property was not used)
        self.sk_sum = self.get_sk_sum()
        self.s_round = self.get_s_round()
        self.s_rk = self.get_s_rk()
        self.s_sbox = self.get_s_sbox()
        self.s_inv_sbox = self.get_s_inv_sbox()
        self.s_shift_offsets = self.get_s_shift_offset()
        self.s_mix_columns_offset = self.get_s_mix_columns_offset()

    def encrypt(self, plaintext):
        plaintext = self.padding(plaintext)
        plaintext = self.split(plaintext)
        ciphertext = b''
        start = time.clock_gettime(time.CLOCK_MONOTONIC)
        for block in plaintext:
            self.state = self.pre_round(block)
            round = 0
            for round in range(1, self.s_round):
                self.state = self.standard_round(round)
            round += 1
            self.state = self.sh_round()
            for round in range(round + 1, len(self.k) - 1):
                self.state = self.standard_round(round)
            self.state = self.last_round()
            ciphertext += self.state
        elapsed_time = time.clock_gettime(time.CLOCK_MONOTONIC) - start
        if self.enc_elapsed_time is None or elapsed_time < self.enc_elapsed_time:
            self.enc_elapsed_time = elapsed_time
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = self.split(ciphertext)
        plaintext = b''
        start = time.clock_gettime(time.CLOCK_MONOTONIC)
        for block in ciphertext:
            self.state = block
            self.state = self.inv_last_round()
            round = 10
            for round in reversed(range(self.s_round + 1, len(self.k) - 1)):
                self.state = self.inv_standard_round(round)
            round -= 1
            self.state = self.inv_sh_round()
            for round in reversed(range(1, round)):
                self.state = self.inv_standard_round(round)
            self.state = self.pre_round(self.state)
            plaintext += self.state
        elapsed_time = time.clock_gettime(time.CLOCK_MONOTONIC) - start
        if self.dec_elapsed_time is None or elapsed_time < self.dec_elapsed_time:
            self.dec_elapsed_time = elapsed_time
        return self.unpadding(plaintext)

    # Elementary operations:

    # XOR two byte strings:
    @staticmethod
    def bytewise_xor(a, b):
        return bytes([a ^ b for a, b in zip(a, b)])

    # Converts a 16-byte array into a 4x4 matrix:
    @staticmethod
    def vector_2_matrix(vector):
        return [bytes([vector[i + j] for j in range(4)]) for i in range(0, len(vector), 4)]

    # Pads the text so that it gets a length multiple of 16:
    @staticmethod
    def padding(text):
        # NOTE: 16 - len(text) % 16 gives the difference between
        # the text length and the next multiple of 16
        return text + chr(16 - len(text) % 
            16).encode() * (16 - len(text) % 16)

    # Unpads the padded text:
    @staticmethod
    def unpadding(text):
        return text[:-text[-1]]

    @staticmethod
    def rotate(text, offset):
        return text[offset:] + text[0:offset]

    @staticmethod
    def split(text):
        temp = []
        for i in range(len(text) // 16):
            block = text[i * 16 : i * 16 + 16]
            temp.append(block)
        return temp
    
    # Galois multiplication:
    @staticmethod
    def galois_multiplication(a, b):
        return const.GALOIS[b][a] if b != 1 else a

    # Gets permutations using itertools.permutations then converts it to a list:
    @staticmethod
    def get_permutations(l):
        p = permutations(l)
        return [i for i in p]

    # Sums all bytes of sk:
    def get_sk_sum(self):
        sum = 0
        for i in self.sk:
            sum += i
        return sum

    def s_rot_offset(self):
        return self.sk_sum % 16

    def get_s_round(self):
        return self.sk_sum % 9 + 1

    def get_s_rk(self):
        return self.rotate(self.k[self.s_round], self.s_rot_offset())

    def get_s_sbox(self):
        s_sbox = list(copy(const.SBOX))
        seed = self.sk_sum
        random.Random(seed).shuffle(s_sbox)
        return s_sbox

    def get_s_inv_sbox(self):
        inv_s_sbox = [None for _ in range(len(self.s_sbox))]
        for i in range(len(inv_s_sbox)):
            inv_s_sbox[self.s_sbox[i]] = i
        return inv_s_sbox

    def get_s_shift_offset(self):
        p = self.get_permutations([0, 1, 2, 3,])
        index = self.sk_sum % 24
        return p[index]

    def get_s_mix_columns_offset(self):
        return self.sk_sum % 4

    # AES steps:

    # Rijndael Key Schedule:
    def k_expansion(self, k):
        k = self.vector_2_matrix(k)
        # Fill the 44-word list:
        while len(k) < 44:
            # Copy previous 4-byte word:
            # (If first round, it's the last word from the key itself)
            w = list(k[-1])
            # For each round:
            if len(k) % 4 == 0:
                # RotWord:
                self.rotate(w, 1)
                # Replace bytes using SBOX :
                w = [const.SBOX[b] for b in w]
                # XOR with respective byte of RCON:
                # (Other bytes in RCON are 0, so XOR not needed)
                w[0] ^= const.RCON[len(k) // 4 - 1] # NOTE: // is over - in ops order
            # XOR with respective word from previous iteration:
            # (e.g.: if 4th iteration XOR w/ 1st(index 0); if 15th XOR w/ 11th(index(10)); etc)
            w = self.bytewise_xor(w, k[-4])
            # Append new word to the pretended 44-word list:
            k.append(w)
        # Transform generated 44-word list into an array of 11 keys:
        temp = []
        for i in range(len(k)):
            if i % 4 == 0:
                temp.append(k[i])
            else:
                temp[-1] += k[i]
        return temp

    def add_round_key(self, round, block):
        return self.bytewise_xor(self.k[round], block)

    @staticmethod
    def sub_bytes(block):
        temp = b''
        for i in range(len(block)):
            temp += bytes([const.SBOX[block[i]]])
        return temp

    @staticmethod
    def inv_sub_bytes(block):
        temp = b''
        for i in range(len(block)):
            temp += bytes([const.INV_SBOX[block[i]]])
        return temp

    def shift_rows(self, block):
        temp = b''
        for i in range(len(block) // 4):
            temp += self.rotate(block[i * 4 : i * 4 + 4], i)
        return temp

    def inv_shift_rows(self, block):
        temp = b''
        for i in range(len(block) // 4):
            temp += self.rotate(block[i * 4 : i * 4 + 4], -i)
        return temp

    # Based on code from https://gist.github.com/raullenchai/2920069:
    def mix_column(self, column):
        temp = copy(column)
        column[0] = self.galois_multiplication(temp[0],2) ^ self.galois_multiplication(temp[3],1) ^ \
                    self.galois_multiplication(temp[2],1) ^ self.galois_multiplication(temp[1],3)
        column[1] = self.galois_multiplication(temp[1],2) ^ self.galois_multiplication(temp[0],1) ^ \
                    self.galois_multiplication(temp[3],1) ^ self.galois_multiplication(temp[2],3)
        column[2] = self.galois_multiplication(temp[2],2) ^ self.galois_multiplication(temp[1],1) ^ \
                    self.galois_multiplication(temp[0],1) ^ self.galois_multiplication(temp[3],3)
        column[3] = self.galois_multiplication(temp[3],2) ^ self.galois_multiplication(temp[2],1) ^ \
                    self.galois_multiplication(temp[1],1) ^ self.galois_multiplication(temp[0],3)

    # Based on code from https://gist.github.com/raullenchai/2920069:
    def inv_mix_column(self, column):
        temp = copy(column)
        column[0] = self.galois_multiplication(temp[0],14) ^ self.galois_multiplication(temp[3],9) ^ \
                    self.galois_multiplication(temp[2],13) ^ self.galois_multiplication(temp[1],11)
        column[1] = self.galois_multiplication(temp[1],14) ^ self.galois_multiplication(temp[0],9) ^ \
                    self.galois_multiplication(temp[3],13) ^ self.galois_multiplication(temp[2],11)
        column[2] = self.galois_multiplication(temp[2],14) ^ self.galois_multiplication(temp[1],9) ^ \
                    self.galois_multiplication(temp[0],13) ^ self.galois_multiplication(temp[3],11)
        column[3] = self.galois_multiplication(temp[3],14) ^ self.galois_multiplication(temp[2],9) ^ \
                    self.galois_multiplication(temp[1],13) ^ self.galois_multiplication(temp[0],11)

    # Based on code from https://gist.github.com/raullenchai/2920069:
    def mix_columns(self, state):
        state = list(state)
        for i in range(4):
            column = []
            # Get the current column:
            for j in range(4):
                column.append(state[j*4+i])
            self.mix_column(column)
            # 'Paste' into the new table:
            for j in range(4):
                state[j*4+i] = column[j]
        return bytes(state)

    # Based on code from https://gist.github.com/raullenchai/2920069:
    def inv_mix_columns(self, state):
        state = list(state)
        for i in range(4):
            column = []
            # Get the current column:
            for j in range(4):
                column.append(state[j*4+i])
            self.inv_mix_column(column)
            # 'Paste' into the new table:
            for j in range(4):
                state[j*4+i] = column[j]
        return bytes(state)

    def s_add_round_key(self, block):
        return self.bytewise_xor(self.s_rk, block)

    def s_sub_bytes(self, block):
        temp = b''
        for i in range(len(block)):
            temp += bytes([self.s_sbox[block[i]]])
        return temp

    def s_inv_sub_bytes(self, block):
        temp = b''
        for i in range(len(block)):
            temp += bytes([self.s_inv_sbox[block[i]]])
        return temp

    def s_shift_rows(self, block):
        temp = b''
        for i in range(len(block) // 4):
            temp += self.rotate(block[i * 4 : i * 4 + 4], self.s_shift_offsets[i])
        return temp

    def s_inv_shift_rows(self, block):
        temp = b''
        for i in range(len(block) // 4):
            temp += self.rotate(block[i * 4 : i * 4 + 4], -self.s_shift_offsets[i])
        return temp

    def s_mix_columns(self, state):
        state = list(state)
        for i in range(4):
            column = []
            # Get the current column:
            # (j selects the column itself, i selects within the column)
            for j in range(4):
                # Applies offset before operation:
                column.append(state[(((j + self.s_mix_columns_offset) % 4)*4+ i)])
            self.mix_column(column)
            # 'Paste' into the new table:
            # (here, j selects within the column)
            for j in range(4):
                state[j*4+i] = column[j]
        return bytes(state)

    def s_inv_mix_columns(self, state):
        state = list(state)
        for i in range(4):
            column = []
            # Get the current column:
            # (j selects the column itself, i selects within the column)
            for j in range(4):
                column.append(state[j*4+i])
            self.inv_mix_column(column)
            # 'Paste' into the new table:
            # (here, j selects within the column)
            for j in range(4):
                # Applies offset after operation:
                state[(((j + self.s_mix_columns_offset) % 4)*4+ i)] = column[j]
        return bytes(state)

    # S_AES rounds:
    def pre_round(self, block):
        return self.add_round_key(0, block)

    def standard_round(self, round):
        state = self.sub_bytes(self.state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(round, state)
        return state

    def inv_standard_round(self, round):
        state = self.add_round_key(round, self.state)
        state = self.inv_mix_columns(state)
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        return state

    def sh_round(self):
        state = self.s_sub_bytes(self.state)
        state = self.s_shift_rows(state)
        state = self.s_mix_columns(state)
        state = self.s_add_round_key(state)
        return state

    def inv_sh_round(self):
        state = self.s_add_round_key(self.state)
        state = self.s_inv_mix_columns(state)
        state = self.s_inv_shift_rows(state)
        state = self.s_inv_sub_bytes(state)
        return state

    def last_round(self):
        state = self.sub_bytes(self.state)
        state = self.shift_rows(state)
        state = self.add_round_key(10, state)
        return state

    def inv_last_round(self):
        state = self.add_round_key(10, self.state)
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        return state

# Standard AES using cryptography lib:
class StandardAES(object):

    def __init__(self, k):
        self.enc_elapsed_time = None
        self.dec_elapsed_time = None
        self.k = k
        self.backend = default_backend()

    def encrypt(self, text):
        cipher = Cipher(algorithms.AES(self.k), modes.ECB(), backend=self.backend)
        padder = padding.PKCS7(128).padder()
        text = padder.update(text) + padder.finalize()
        encryptor = cipher.encryptor()
        start = time.clock_gettime(time.CLOCK_MONOTONIC)
        c_text = encryptor.update(text)
        elapsed_time = time.clock_gettime(time.CLOCK_MONOTONIC) - start
        text += encryptor.finalize()
        if self.enc_elapsed_time is None or elapsed_time < self.enc_elapsed_time:
            self.enc_elapsed_time = elapsed_time
        return c_text

    def decrypt(self, c_text):
        cipher = Cipher(algorithms.AES(self.k), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        start = time.clock_gettime(time.CLOCK_MONOTONIC)
        text = decryptor.update(c_text)
        elapsed_time = time.clock_gettime(time.CLOCK_MONOTONIC) - start
        text += decryptor.finalize()
        if self.dec_elapsed_time is None or elapsed_time < self.dec_elapsed_time:
            self.dec_elapsed_time = elapsed_time
        unpadder = padding.PKCS7(128).unpadder()
        text = unpadder.update(text) + unpadder.finalize()
        return text

class CipherWrapper(object):

    def __init__(self, k, sk=None):
        # Get the 128-bit key from the given key using SHAKE128:
        hash = shake_128()
        hash.update(k.encode('utf-8') if type(k) is str else k)
        k = hash.digest(16)
        if sk is None:
            self.cipher = StandardAES(k)
        else:
            # Get the 128-bit key from the given key using SHAKE128:
            hash.update(sk.encode() if type(sk) is str else sk)
            sk = hash.digest(16)
            self.cipher = S_AES(k, sk)
        self.enc_elapsed_time = None
        self.dec_elapsed_time = None

    def encrypt(self, text):
        text = self.cipher.encrypt(text.encode() if type(text) is str else text)
        if self.enc_elapsed_time is None or self.cipher.enc_elapsed_time < self.enc_elapsed_time:
            self.enc_elapsed_time = self.cipher.enc_elapsed_time
        return text

    def decrypt(self, text):
        text = self.cipher.decrypt(text)
        if self.dec_elapsed_time is None or self.cipher.dec_elapsed_time < self.dec_elapsed_time:
            self.dec_elapsed_time = self.cipher.dec_elapsed_time
        return text
