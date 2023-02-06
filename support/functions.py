import binascii
import hashlib
import logging

import cryptography.fernet
from django.apps import apps
from Cryptodome import Random
from Cryptodome.Cipher import AES
from cryptography.fernet import Fernet


# def encrypt_string(string, encryption_key):
#     m = hashlib.sha256()
#     m.update(encryption_key.encode("utf8"))
#     keyhard = m.digest()
#     if len(keyhard) == 32:
#         iv = Random.new().read(15)
#         ctr = AES.new(keyhard, AES.MODE_OCB, nonce=iv)
#         ciphertext, tag = ctr.encrypt_and_digest(str(string).encode("utf8"))
#         encrypted_string = binascii.hexlify(iv + tag + ciphertext).decode("utf-8")
#         return encrypted_string
#     logging.error(msg="Encryption error")
#     return None

def encrypt_string(decrypted_string, aes_key):
    aes_encrypted_string = aes_encrypt_string(decrypted_string, aes_key)
    fernet_encrypted_string = fernet_encrypt_string(aes_encrypted_string)
    return fernet_encrypted_string


def decrypt_string(encrypted_string, encryption_key):
    fernet_decrypted_string = fernet_decrypt_string(encrypted_string)
    if fernet_decrypted_string:
        aes_decrypted_string = aes_decrypt_string(fernet_decrypted_string, encryption_key)
        return aes_decrypted_string
    return None


def reencrypt_string(encrypted_string, old_encryption_key, new_encryption_key):
    decrypted_string = decrypt_string(encrypted_string, old_encryption_key)
    if decrypted_string:
        return encrypt_string(decrypted_string, new_encryption_key)
    return None


def fernet_reencrypt_string(fernet_encrypted_string):
    decrypted_string = fernet_decrypt_string(fernet_encrypted_string)
    encrypted_string = fernet_encrypt_string(decrypted_string)
    return encrypted_string


def aes_encrypt_string(decrypted_string, aes_key):
    m = hashlib.sha256()
    m.update(aes_key.encode("utf8"))
    keyhard = m.digest()
    iv = Random.new().read(15)
    ctr = AES.new(keyhard, AES.MODE_OCB, nonce=iv)
    ciphertext, tag = ctr.encrypt_and_digest(str(decrypted_string).encode())
    aes_encrypted_string = binascii.hexlify(iv + tag + ciphertext).decode()
    return aes_encrypted_string


def fernet_encrypt_string(decrypted_string):
    fernet_key_model = apps.get_model("store", "FernetKey")
    fernet_key = fernet_key_model.get_current_fernet_key()
    fernet = Fernet(fernet_key)
    encrypted_token = fernet.encrypt(decrypted_string.encode()).decode()
    return encrypted_token


def aes_decrypt_string(encrypted_string, aes_key):
    m = hashlib.sha256()
    m.update(aes_key.encode("utf8"))
    keyhard = m.digest()
    if len(keyhard) == 32:
        datoscifrados = binascii.unhexlify(encrypted_string)
        iv = datoscifrados[0:15]
        tag = datoscifrados[15:31]
        tail = datoscifrados[31:]
        ctr = AES.new(keyhard, AES.MODE_OCB, nonce=iv)
        try:
            string = ctr.decrypt_and_verify(tail, tag).decode('utf-8')
            return string
        except Exception as e:
            logging.error(msg=f"Integridad del mensaje rota: {e}")
            return None
    logging.error(msg="Decryption error")
    return None


def fernet_decrypt_string(encrypted_string):
    def _decrypt(_enc, _fk):
        fernet = Fernet(_fk)
        try:
            _dec = fernet.decrypt(_enc.encode())
            return _dec.decode()
        except cryptography.fernet.InvalidToken:
            return None
    decrypted_string = None
    fernet_key_model = apps.get_model("store", "FernetKey")
    fernet_keys = fernet_key_model.get_possible_fernet_keys()
    for fernet_key in fernet_keys:
        decrypted_string = _decrypt(encrypted_string, fernet_key)
        if decrypted_string:
            return decrypted_string
    return decrypted_string
