import base64


def b64padding(b64_str):
    num_padding = 4 - (len(b64_str) % 4)
    if num_padding < 4:
        b64_str += "=" * num_padding
    return b64_str


def padding(data, block_size):
    while len(data) % block_size != 0:
        # data += b'\x00'
        data += '='
    return data


def unwrap_message(message):
    # remove all the '=' in the most significant bits of string message
    return message.rstrip('=')


def hex_padding(data):
    while len(data) % 4 != 0:
        data = '0'+data
    return data

def padding_aes_hex(key):
    add = 32-len(key)+2
    res = '0'*add + key[2:]
    return res

def int2hex(in_x):
    hex_x = hex(in_x)[2:]
    res = bytes.fromhex(hex_padding(hex_x))
    return res


def hex_to_bin(hex):
    decimal_number = int(hex.hex(), 16)
    binary_number = bin(decimal_number)
    return binary_number[2:]


def chop_aes_key(rsa_dec_res):
    bin_res = hex_to_bin(rsa_dec_res)
    # print('len: {}, original bin: {}'.format(len(bin_res), bin_res))
    chopped_res = bin_res[-128:]
    # print('len: {}, chopped bin: {}'.format(len(chopped_res), chopped_res))
    res = bytes.fromhex(padding_aes_hex(hex(int(chopped_res, 2))))
    return res


def int_to_aes_key(x):
    hex_x = padding_aes_hex(hex(x))
    aes_x = bytes.fromhex(hex_x)
    return aes_x
