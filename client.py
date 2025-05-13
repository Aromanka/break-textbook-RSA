import base64
import socket
import AES
import RSA
import threading
import struct
import gmpy2
import logging

import utils

# existing problem: cannot correctly process number
RSA_PUBLIC_KEY_DIR = '.\\data\\_RSA_Public_Key.txt'
DECODE_WUP_FAIL_MESSAGE = "FAILED_TO_DECODE"
BUFFER_SIZE = 1024
IP = (127, 0, 0, 1)
PORT = 8080

def bytes_to_line(in_x):
    return in_x+b'\n'

def encode_WUP(rsa_public_key, aes_key, message):
    ip_info = struct.pack('BBBBH', IP[0], IP[1], IP[2], IP[3], PORT)
    encoded_ip_info = base64.b64encode(ip_info).decode('utf-8')
    _ip_info = aes_key.encrypt(encoded_ip_info)
    _message = aes_key.encrypt(message)
    # encode aes_key
    encoded_aes_key = base64.b64encode(aes_key.key)
    # print("--1: {}".format(encoded_aes_key))
    _aes_key = base64.b64encode(rsa_public_key.encrypt_data(encoded_aes_key, encoding='utf-8').encode('utf-8'))
    # print(len(_aes_key), len(_ip_info), len(_message))
    return bytes_to_line(_aes_key), bytes_to_line(_ip_info+_message)

def encode_attack_WUP(aes_key, aes_cipher):
    wup1 = base64.b64encode(aes_cipher.encode('utf-8'))
    ip_info = struct.pack('BBBBH', IP[0], IP[1], IP[2], IP[3], PORT)
    encoded_ip_info = base64.b64encode(ip_info).decode('utf-8')
    _ip_info = aes_key.encrypt(encoded_ip_info)
    # print("enc ip info: {}".format(_ip_info))
    # encode aes_key
    return bytes_to_line(wup1), bytes_to_line(_ip_info)


def decode_WUP(message, aes_key):
    decrypt_message = aes_key.decrypt(message)
    try:
        _message = decrypt_message.decode('utf-8')
    except UnicodeDecodeError:
        return DECODE_WUP_FAIL_MESSAGE
    return _message


def send_thread(s, rsa_public_key, aes_key):
    while True:
        message = input('#:')
        logging.info("CLIENT::Input Message: {}".format(message))
        wup1, wup2 = encode_WUP(rsa_public_key, aes_key, message)
        s.send(wup1)
        print('CLIENT::send wup1 {}'.format(wup1))
        logging.info('CLIENT::send wup1 {}'.format(wup1))
        s.send(wup2)
        print('CLIENT::send wup2 {}'.format(wup2))
        logging.info('CLIENT::send wup2 {}'.format(wup2))
        if message=='close':
            break


def recv_thread(s, aes_key):
    while True:
        buff = s.recv(BUFFER_SIZE)
        recv = buff.decode('utf-8')
        logging.info("CLIENT::receive message: {}".format(recv))
        message = decode_WUP(recv, aes_key)
        message = utils.unwrap_message(message)
        logging.info("CLIENT::encrypted message: {}".format(message))
        if message=='shutdown':
            print('client receiver shut down!')
            break
        elif message=='correct':
            print('sent messages are correct!')
        elif message=='wrong':
            print('sent messages are wrong!')
        else:
            print('unrecognizable message: {}'.format(message))



def start(socket_params):
    '''
    :param socket_params: a tuple of (ip address, port)
    :return: nothing
    '''
    # initialize log
    logging.basicConfig(filename='.\\log\\client.log', filemode='w', format='%(asctime)s %(name)s:%(levelname)s:%(message)s', datefmt='%d-%m-%Y %H:%M:%S', level=logging.DEBUG)
    # generate AES session key
    aes_key_size = 16
    aes_key = AES.AESKey(key=None, size=aes_key_size)
    aes_key.save_key()
    aes_key_num = int(aes_key.key.hex(), 16)
    print("CLIENT::Finished generating AES key.\nAES key: {}".format(bin(aes_key_num)[2:]))
    logging.info("CLIENT::Generated AES key: {}".format(aes_key_num))
    # load RSA public key
    rsa_public_key = RSA.PublicKey.import_from(RSA_PUBLIC_KEY_DIR)
    # open socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(socket_params)
    thread1 = threading.Thread(target=send_thread, args=(client_socket, rsa_public_key, aes_key))
    thread1.start()
    '''
    wup1 = send_thread(client_socket, rsa_public_key, aes_key)
    buff = client_socket.recv(BUFFER_SIZE)
    print('recv of the first connect...')
    cracked_aes_num = crack(client_socket=client_socket, wup1=wup1)
    print("Cracked AES key is: {}\nbin: {}".format(cracked_aes_num, bin(cracked_aes_num)[2:]))
    print('True AES key is:    {}\nbin: {}'.format(aes_key_num, bin(aes_key_num)[2:]))
    if aes_key_num==cracked_aes_num:
        print('Same as the true key, cracking succeeded.')
    else:
        print('Different to the true key, cracking failed.')
    '''
    thread2 = threading.Thread(target=recv_thread, args=(client_socket, aes_key))
    thread2.start()


# def crack(client_socket, wup1):
#     # decode WUP to get the RSA-encrypted AES Key
#     C = base64.b64decode(wup1).decode('utf-8')
#     # print("C: {}".format(C))
#     # load RSA-public Key
#     rsa_public_key = RSA.PublicKey.import_from(RSA_PUBLIC_KEY_DIR)
#     known_aes = 0
#     for i in range(127,-1,-1):
#         print('CRACK_CLIENT::current i: {}, known aes: {}'.format(i, bin(known_aes)[2:]))
#         fac = gmpy2.powmod(2, (i)*rsa_public_key.x, rsa_public_key.n)
#         b_cipher = gmpy2.f_mod(fac*gmpy2.mpz(C), rsa_public_key.n)
#         test_aes = (known_aes<<i) + (1<<127)
#         print('test bin: {}'.format(bin(test_aes)[2:]))
#         hex_test_aes = utils.padding_aes_hex(hex(test_aes))
#         encoded_test_aes = bytes.fromhex(hex_test_aes)
#         test_aes_key = AES.AESKey(encoded_test_aes)
#         attack_wup1, attack_wup2 = encode_attack_WUP(test_aes_key, str(b_cipher))
#         client_socket.send(attack_wup1)
#         print("CRACK_CLIENT::send attack_wup1 {}".format(attack_wup1))
#         client_socket.send(attack_wup2)
#         print("CRACK_CLIENT::send attack_wup2 {}".format(attack_wup2))
#         # recv reaction
#         buff = client_socket.recv(BUFFER_SIZE)
#         recv = buff.decode('utf-8')
#         message = decode_WUP(recv, test_aes_key)
#         message = utils.unwrap_message(message)
#         if message=='correct':
#             known_aes = known_aes+(1<<(127-i))
#         else:
#             known_aes = known_aes
#     return known_aes
#

def main():
    socket_params = ('127.0.0.1', 8081)
    start(socket_params)


if __name__=='__main__':
    main()