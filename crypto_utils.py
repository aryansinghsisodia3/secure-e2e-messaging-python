# crypto_utils.py

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# ---------------- RSA ---------------- #

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# ---------------- Diffie-Hellman ---------------- #

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    return derived_key

# ---------------- AES ---------------- #

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()
