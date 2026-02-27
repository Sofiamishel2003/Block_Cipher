
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from generacion_llaves import generate_3des_key, generate_iv


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

    # Validar que el IV tenga 8 bytes y la clave tenga 16 o 24 bytes
    if len(iv) != 8:
        raise ValueError("IV inválido: debe ser de 8 bytes para 3DES-CBC.")
    if len(key) not in (16, 24):
        raise ValueError("Clave inválida: 3DES requiere 16 o 24 bytes.")

    # Crea el cipher con la libreria
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    # Le aplicamos el padding PKCS#7 al tamaño de bloque (8)
    padded = pad(plaintext, 8)

    # De ahí ya solo lo desciframos
    return cipher.encrypt(padded)



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
    # 1. Validar longitud de clave y IV
    if len(iv) != 8:
        raise ValueError("IV inválido: debe ser de 8 bytes para 3DES-CBC.")
    if len(key) not in (16, 24):
        raise ValueError("Clave inválida: 3DES requiere 16 o 24 bytes.")
    if len(ciphertext) == 0 or (len(ciphertext) % 8) != 0:
        raise ValueError("Ciphertext inválido: debe ser no-vacío y múltiplo de 8 bytes.")
    # 2. Crear cipher: DES3.new(key, DES3.MODE_CBC, iv=iv)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    # 3. Descifrar
    padded_plain = cipher.decrypt(ciphertext)
    # 4. Eliminar padding usando unpad() de Crypto.Util.Padding
    plain = unpad(padded_plain, 8)
    # 5. Retornar
    return plain

if __name__ == "__main__":
    # con la función generamos la clave de 3DES
    key_option = 2
    key = generate_3des_key(key_option)

    # Generar IV aleatorio con 8 bytes (tamaño de bloque de DES) usando la función generate_iv()
    iv = generate_iv(8)

    plaintext = b"Mensaje secreto para laboratorio de criptografia 3DES"

    print(f"Key ({len(key)} bytes): {key.hex()}")
    print(f"IV  ({len(iv)} bytes): {iv.hex()}")
    print(f"Plaintext: {plaintext}")
    # Ciframos como buenas girly pops
    ciphertext = encrypt_3des_cbc(plaintext, key, iv)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Desciframos como chicas lindas
    decrypted = decrypt_3des_cbc(ciphertext, key, iv)
    print(f"Decrypted: {decrypted}")