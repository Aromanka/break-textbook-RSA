import binascii
from Cryptodome.Cipher import AES
from Cryptodome import Random
import base64
import sys

import utils
from utils import b64padding


AES_KEY_DIR = '.\\data\\AES_Key.txt'
DEFAULT_AES_MODE = AES.MODE_ECB


class AESKey():
    def __init__(self, key=None, size=16, mode=DEFAULT_AES_MODE):
        # size=16, mode=AES.MODE_CFB
        if key is None:
            self.key = build_aes_key(size)
        else:
            self.key = key
            # self.key = utils.padding_aes_hex(key)
        self.block_size = AES.block_size
        self.mode = mode


    def encrypt(self, plain):
        self.aes = AES.new(self.key, self.mode)
        plain = utils.padding(plain, self.block_size)
        cipher = self.aes.encrypt(plain.encode('utf-8'))
        return base64.b64encode(cipher)

    def decrypt(self, cipher):
        self.aes = AES.new(self.key, self.mode)
        bin_cipher = base64.b64decode(cipher)
        plaintext = self.aes.decrypt(bin_cipher)
        plain = plaintext.strip(b'\0')#.decode('utf-8')
        return plain

    def encode_key(self):
        return base64.b64encode(self.key)

    def save_key(self):
        with open(AES_KEY_DIR, 'wb') as file:
            file.write(self.key.hex().encode())


def encrypt(key, plain, block_size = AES.block_size):
    """
    :param key: 16 bytes data for MODE_CFB, the key
    :param plaintext: plaintext
    :return: ciphertext
    """
    aes = AES.new(key, DEFAULT_AES_MODE)
    plain = utils.padding(plain, block_size)
    cipher = aes.encrypt(plain.encode('utf-8'))
    return binascii.b2a_hex(cipher)


def decrypt(key, cipher):
    bin_cipher = binascii.a2b_hex(cipher)
    aes = AES.new(key, DEFAULT_AES_MODE)
    plain = aes.decrypt(bin_cipher)
    plain = plain.strip(b'\0').decode('utf-8')
    return plain


def build_aes_key(size):
    key = Random.get_random_bytes(size)
    return key


def load_aes_key():
    with open(AES_KEY_DIR, 'rb') as file:
        key = file.read()
    return key


def main():
    plaintext = '12345234 345'
    aes = AESKey(key=None, size=16, mode=DEFAULT_AES_MODE)
    aes.save_key()
    # print(sys.getsizeof(aes.key)-sys.getsizeof(bytes()))
    ciphertext = aes.encrypt(plaintext)
    res = aes.decrypt(ciphertext)
    print(AES.block_size)
    print('Key: {}\nEncoded Key: {}\nCiphertext: {}\nPlaintext: {}'.format(aes.key, aes.encode_key(), ciphertext, res))


if __name__=='__main__':
    main()