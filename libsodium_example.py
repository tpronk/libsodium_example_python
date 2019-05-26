# -*- coding: utf-8 -*-
import sys
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.encoding import Base64Encoder

def write_file(file_name, data, base64 = False):
    if base64:
        data = Base64Encoder.encode(data).decode('ascii')
    f = open(file_name, 'w')
    f.write(data)
    f.close()
    
def read_file(file_name, base64 = False):
    f = open(file_name, 'r')
    data = f.read()
    if base64:
        data = Base64Encoder.decode(data)
    f.close()
    return data

def generate_keypair():
    key_pair = PrivateKey.generate()
    secret_key_bin = key_pair._private_key
    public_key_bin = key_pair.public_key._public_key
    write_file('secret_key.txt', secret_key_bin, True)
    write_file('public_key.txt', public_key_bin, True)

def encrypt():
    decrypted_utf8 = read_file('decrypted.txt')
    decrypted_bin = bytes(decrypted_utf8, 'utf-8')
    public_key_bin = read_file('public_key.txt', True)
    public_key = PublicKey(public_key_bin)
    sealed_box = SealedBox(public_key)
    encrypted_bin = sealed_box.encrypt(decrypted_bin)
    write_file("encrypted.txt", encrypted_bin, True)

def decrypt():
    encrypted_bin = read_file('encrypted.txt', True)
    secret_key_bin = read_file('secret_key.txt', True)
    secret_key = PrivateKey(secret_key_bin)
    sealed_box = SealedBox(secret_key)
    decrypted_bin = sealed_box.decrypt(encrypted_bin)
    decrypted_utf8 = decrypted_bin.decode('utf-8')
    write_file("decrypted.txt", decrypted_utf8)


# Depending on script argument, generate keypair, encrypt, or decrypt
def execute_command(command):
    switcher = {
        'g': generate_keypair,
        'e': encrypt,
        'd': decrypt
    }
    func = switcher.get(command)
    func()
    
if len(sys.argv) > 1:
    execute_command(sys.argv[1])
