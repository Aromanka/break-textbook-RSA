import binascii
import socket, threading
import AES
import RSA
import base64
import utils
import struct
import logging
import os


BUFFER_SIZE = 2048
_RSA_PUBLIC_KEY_DIR = '.\\data\\_RSA_Public_Key.txt'
_RSA_PRIVATE_KEY_DIR = '.\\data\\_RSA_Secret_Key.txt'
RSA_PUBLIC_KEY_DIR = '.\\data\\RSA_Public_Key.txt'
RSA_PRIVATE_KEY_DIR = '.\\data\\RSA_Secret_Key.txt'
CLIENT_SOCK_IP=(127,0,0,1)


def decode_WUP(wup1, wup2, rsa_private_key):
    # print("SERVER_DECODE_WUP::wup1: {}, wup2: {}".format(wup1, wup2))
    encrypted_aes_key = base64.b64decode(wup1).decode('utf-8')
    ip_info = wup2[:24]
    # print('ip_info: {}'.format(ip_info))
    encoded_message = wup2[24:]
    # print(encrypted_aes_key)
    encoded_aes_key = rsa_private_key.decrypt_data(encrypted_aes_key)
    # print(encoded_aes_key)
    _aes_key = utils.chop_aes_key(encoded_aes_key)
    aes_key = AES.AESKey(key=_aes_key)
    try:
        message = aes_key.decrypt(encoded_message).decode('utf-8')
    except Exception as e:
        message = ""
        print("SERVER::failed to decrypt message: {}".format(e))
        '''
    try:
        _ip_info = aes_key.decrypt(ip_info)
        # print("_ip_info: {}".format(_ip_info))
        packed_ip_info = base64.b64decode(_ip_info)
        # print("packed ip info: {}".format(packed_ip_info))
        real_ip_info = struct.unpack('BBBBH', packed_ip_info)
    except Exception as e:
        print("SERVER::ip_info: {}".format(ip_info))
        real_ip_info = None
        print("SERVER::failed to decrypt ip_info: {}".format(e))
        '''

    _ip_info = aes_key.decrypt(ip_info)
    # padded_ip_info = utils.b64padding(_ip_info)
    try:
        packed_ip_info = base64.b64decode(_ip_info)
    except binascii.Error as e:
        packed_ip_info = b''
        print("SERVER::failed to decrypt ip_info: {}".format(e))
    # print("packed ip info: {}".format(packed_ip_info))
    # print(packed_ip_info)
    try:
        real_ip_info = struct.unpack('BBBBH', packed_ip_info)
    except struct.error as e:
        real_ip_info = None
        print("SERVER::failed to decrypt ip_info: {}".format(e))

    # print("encoded result: {}, {}, {}".format(aes_key.key, real_ip_info, message))
    return aes_key, real_ip_info, message


def encode_WUP(message, aes_key):
    _message = aes_key.encrypt(message)
    return _message


def recv_thread(s, rsa_private_key):
    print('SERVER::Connected to client.')
    with s.makefile('r') as s_file:
        while True:
            if s is not None:
                # buff = s.recv(BUFFER_SIZE)
                buff = s_file.readline().strip()
                # wup1 = buff.decode('utf-8') # aes
                wup1 = buff
                print('wup1: {}'.format(wup1))
                logging.info("SERVER::Received wup1: {}".format(wup1))
                # buff = s.recv(BUFFER_SIZE)
                buff = s_file.readline().strip()
                # wup2 = buff.decode('utf-8') # message
                wup2 = buff
                print('wup2: {}'.format(wup2))
                logging.info("SERVER::Received wup2: {}".format(wup2))
                aes_key, ip_info, message = decode_WUP(wup1, wup2, rsa_private_key)
                message = utils.unwrap_message(message)
                if message=="close":
                    print('SERVER::Connection shut down by the client.')
                    logging.info('SERVER::Connection shut down by the client.')
                    send(s, 'shutdown', aes_key)
                    break
                # elif message=='':
                #     break
                else:
                    print("SERVER::received message: {}".format(message))
                    logging.info("SERVER::received message: {}".format(message))
                    if ip_info is None:
                        send(s, 'wrong', aes_key)
                    elif ip_info[:4]==CLIENT_SOCK_IP:
                        send(s, 'correct', aes_key)
                    else:
                        send(s, 'wrong', aes_key)
            else:
                break


# sends 'correct' if receive the correct message; otherwise sends 'wrong'.
def send(s, message, aes_key):
    s.send(encode_WUP(message, aes_key))
    print("SERVER::send message: {}".format(message))
    logging.info("SERVER::send message: {}".format(message))


def start(socket_params):
    # generate RSA key
    RSA_dir = '.\\RSA_FILE\\'
    RSA_size = 1024
    p = RSA.get_prime(RSA_size)
    q = RSA.get_prime(RSA_size)
    rsa = RSA.RSA(p, q)
    public_key = rsa.get_public_key()
    private_key = rsa.get_private_key()
    public_key.save_number(RSA_PUBLIC_KEY_DIR)
    private_key.save_number(RSA_PRIVATE_KEY_DIR)
    public_key.export_to(_RSA_PUBLIC_KEY_DIR)
    private_key.export_to(_RSA_PRIVATE_KEY_DIR)
    print('Finished generating RSA keys.')
    # initialize socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(socket_params)
    s.listen(1)
    # initialize log
    logging.basicConfig(filename='.\\log\\server.log', filemode='w', format='%(asctime)s %(name)s:%(levelname)s:%(message)s', datefmt='%d-%m-%Y %H:%M:%S', level=logging.DEBUG)
    while True:
        print('SERVER::Waiting for connection...')
        connect, address = s.accept()
        th = threading.Thread(target=recv_thread, args=(connect, private_key,))
        th.start()
        print('SERVER::Connected to {},{}.'.format(connect, address))
        logging.info('SERVER::Connected to {},{}.'.format(connect, address))

    s.close()

    return private_key


def main():
    # file check
    if not os.path.exists('log'): os.mkdir('log')
    if not os.path.exists('data'): os.mkdir('data')
    if not os.path.exists('data'): os.mkdir('data')
    socket_params = ('127.0.0.1', 8080)
    start(socket_params)


if __name__=='__main__':
    main()