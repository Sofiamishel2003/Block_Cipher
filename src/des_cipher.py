from Crypto.Cipher import DES
from utils import pkcs7_pad, pkcs7_unpad

DES_BLOCK = 8


def des_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key debe ser de 8 bytes.")
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pkcs7_pad(plaintext, DES_BLOCK)
    return cipher.encrypt(padded)


def des_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key debe ser de 8 bytes.")
    if len(ciphertext) == 0 or len(ciphertext) % DES_BLOCK != 0:
        raise ValueError("Ciphertext inválido para DES ECB.")
    cipher = DES.new(key, DES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded)

if __name__ == "__main__":
    # Ejemplo de uso
    key = b"8bytekey"
    plaintext = b"Mensaje secreto para DES"
    ciphertext = des_encrypt_ecb(plaintext, key)
    decrypted = des_decrypt_ecb(ciphertext, key)
    assert decrypted == plaintext