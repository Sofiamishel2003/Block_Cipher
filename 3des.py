
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """

    return True


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    # TODO: Implementar
    # 1. Validar longitud de clave y IV
    # 2. Crear cipher: DES3.new(key, DES3.MODE_CBC, iv=iv)
    # 3. Descifrar
    # 4. Eliminar padding usando unpad() de Crypto.Util.Padding
    # 5. Retornar
    return True

