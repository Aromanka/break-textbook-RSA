import gmpy2
import random
import math
from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
import base64
import utils


DefaultE = 65537

PublicKeyOutDir = '.\\RSA_FILE\\public_out.txt'
PrivateKeyOutDir = '.\\RSA_FILE\\private_out.txt'
RSA_PUBLIC_KEY_DIR = '.\\data\\RSA_Public_Key.txt'
RSA_PRIVATE_KEY_DIR = '.\\data\\RSA_Private_Key.txt'


def get_prime(size):
    x = get_random_odd(size)
    while not gmpy2.is_prime(x):
        x = get_random_odd(size)
    return x


def get_random_odd(size):
    return random.randrange((1<<(size-1))+1, 1<<size, 2)


class RSA(object):
    # public key: (n, e)
    # private key: (n, d)
    def __init__(self, p, q, e=DefaultE):
        self.e = e
        assert gmpy2.is_prime(p), 'p is not a prime!'
        assert gmpy2.is_prime(q), 'q is not a prime!'
        self.p = p
        self.q = q
        self.n = self.p * self.q
        if self.p!=self.q:
            self.phi = (self.p-1) * (self.q-1)
        else:
            self.phi = self.p ** 2 - self.p
        self.d = gmpy2.invert(self.e, self.phi)

    def get_public_key(self):
        return PublicKey(self.n, self.e)

    def get_private_key(self):
        return PrivateKey(self.n, self.d)

    def save_parameters(self, filedir_moduler, filedir_p, filedir_q):
        with open(filedir_moduler, 'w') as file:
            file.write(str(self.n))
        with open(filedir_p, 'w') as file:
            file.write(str(self.p))
        with open(filedir_q, 'w') as file:
            file.write(str(self.q))


class Key(object):
    def __init__(self, n, x):
        self.n = n
        self.x = x
        self.chunk_size = math.ceil(self.n.bit_length() / 8 - 1)
        self.seq = univ.Sequence()
        self.seq.setComponentByPosition(0, univ.Integer(self.n))
        self.seq.setComponentByPosition(1, univ.Integer(self.x))

    def print(self):
        # print('n={}, x={}'.format(self.n, self.x))
        print(self.seq)

    def encode(self):
        return base64.b64encode(encoder.encode(self.seq))

    def export_to(self, filedir):
        with open(filedir, 'wb+') as file:
            file.write(self.encode())

    def save_number(self, filedir):
        with open(filedir, 'w') as file:
            file.write(str(self.n) + '\n' + str(self.x))


class PrivateKey(Key):
    def export_to(self, filedir):
        with open(filedir, 'wb+') as file:
            file.write(self.encode())

    @staticmethod
    def import_from(filedir):
        with open(filedir, 'rb') as file:
            params = decoder.decode(base64.b64decode(file.read()))
        return PrivateKey(params[0][0]._value, params[0][1]._value)

    @staticmethod
    def decode_from(data):
        params = decoder.decode(base64.b64decode(data))
        return PrivateKey(params[0][0]._value, params[0][1]._value)

    def decrypt_data(self, data):
        res = b''
        cipher_blocks = data.split('\n')
        for cipher in cipher_blocks:
            if not cipher: continue
            res_1 = gmpy2.powmod(int(cipher), self.x, self.n)
            hex_res = f'{res_1:08x}'
            # print("RSA_PROCESS::hex_res {}".format(hex_res))
            hex_bytes = bytes.fromhex(utils.hex_padding(hex_res))
            res += hex_bytes
        return res


class PublicKey(Key):
    def export_to(self, filedir):
        with open(filedir, 'wb+') as file:
            file.write(self.encode())

    @staticmethod
    def import_from(filedir):
        with open(filedir, 'rb') as file:
            params = decoder.decode(base64.b64decode(file.read()))
        return PublicKey(params[0][0]._value, params[0][1]._value)

    @staticmethod
    def decode_from(data):
        params = decoder.decode(base64.b64decode(data))
        return PublicKey(params[0][0]._value, params[0][1]._value)

    def encrypt_data(self, data, encoding='ascii'):
        cipher_blocks = []
        cur_index = 0
        while cur_index<len(data):
            end = min(cur_index+self.chunk_size, len(data))
            # print(cur_index+self.chunk_size, len(data))
            chunk = data[cur_index: cur_index+self.chunk_size]
            cur_index = end
            hex_chunk = base64.b64decode(chunk)
            _chunk_encoded = int(hex_chunk.hex(),16)
            cipher = gmpy2.powmod(_chunk_encoded, self.x, self.n)
            cipher_blocks.append(str(cipher))
            if end==len(data):
                break
        content = '\n'.join(cipher_blocks)
        return content


def main():
    dir = '.\\RSA_FILE\\'
    filedir = '.\\RSA_FILE\\test.txt'
    size = 1024
    p = get_prime(size)
    q = get_prime(size)
    rsa = RSA(p, q)
    public_key = rsa.get_public_key()
    private_key = rsa.get_private_key()
    data = 'We demonstrate inheritance in a very simple example. We create a Person class with the two attributes "firstname" and "lastname". This class has only one method, the Name method, essentially a getter, but we dont have an attribute name. This method is a further example for a "getter", which creates an output by creating it from more than one private attribute. Name returns the concatenation of the first name and the last name of a person, separated by a space. It goes without saying that a useful person class would have additional attributes and further methods.'
    ciphertext = public_key.encrypt_data(data)
    print(ciphertext)
    plaintext = private_key.decrypt_data(ciphertext)
    print(plaintext)



if __name__=='__main__':
    main()