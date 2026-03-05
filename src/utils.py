"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """

    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.   

    """
    if key_option == 1:
        return secrets.token_bytes(24)  # 3 claves independientes (24 bytes)
    elif key_option == 2:
        return secrets.token_bytes(16)  # 2 claves independientes (16 bytes)
    elif key_option == 3:
        return secrets.token_bytes(8)   # 1 clave repetida 3 veces (8 bytes)
    else:         raise ValueError("Opción de clave 3DES inválida. Use 1, 2 o 3.")

def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
   
    """
    # Convertir bits a bytes: key_size // 8
    if key_size not in (128, 192, 256):
        raise ValueError("Tamaño de clave AES inválido. Use 128, 192 o 256 bits.")
    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """
    return secrets.token_bytes(block_size)
"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8):
    """
    Implementa padding PKCS#7 según RFC 5652.
    
    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).
    
    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.
    
    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'  # HOLA + 4 bytes con valor 0x04
        
        >>> pkcs7_pad(b"12345678", 8).hex()  # Exactamente 8 bytes
        '31323334353637380808080808080808'  # + bloque completo
    """
    # Primero es ver cuantos bytes me faltan para completar el bloque
    padding_length = block_size - (len(data) % block_size)
    # Ahora que ya tenemos el largo del padding, ahora creamos el padding
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.
    
    Examples:
        >>> padded = pkcs7_pad(b"HOLA", 8)
        >>> pkcs7_unpad(padded)
        b'HOLA'
    """
    if not data:
        raise ValueError("Data cannot be empty")
    # Según investigué el último byte te inda cuanto hay de padding 
    padding_length = data[-1]
    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Invalid padding length")
    # Verificar que los bytes de padding sean correctos
    padding = data[-padding_length:]
    if any(p != padding_length for p in padding):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_length]

    
if __name__ == "__main__":
    # ejemplo de generación de claves e IVs
    des_key = generate_des_key()
    print(f"DES key (8 bytes):          {des_key.hex()}  [{len(des_key)} bytes]")

    key3des_op1 = generate_3des_key(1)
    print(f"3DES key opción 1 (24 b):   {key3des_op1.hex()}  [{len(key3des_op1)} bytes]")

    key3des_op2 = generate_3des_key(2)
    print(f"3DES key opción 2 (16 b):   {key3des_op2.hex()}  [{len(key3des_op2)} bytes]")

    key3des_op3 = generate_3des_key(3)
    print(f"3DES key opción 3 (8 b):    {key3des_op3.hex()}  [{len(key3des_op3)} bytes]")

    aes128 = generate_aes_key(128)
    print(f"AES-128 key (16 bytes):     {aes128.hex()}  [{len(aes128)} bytes]")

    aes192 = generate_aes_key(192)
    print(f"AES-192 key (24 bytes):     {aes192.hex()}  [{len(aes192)} bytes]")

    aes256 = generate_aes_key(256)
    print(f"AES-256 key (32 bytes):     {aes256.hex()}  [{len(aes256)} bytes]")

    iv_des = generate_iv(8)
    print(f"IV DES (8 bytes):           {iv_des.hex()}  [{len(iv_des)} bytes]")

    iv_aes = generate_iv(16)
    print(f"IV AES (16 bytes):          {iv_aes.hex()}  [{len(iv_aes)} bytes]")
    ## Ejemplo de uso de padding PKCS#7
    ejemplo_1 = pkcs7_pad(b"HOLA", 8)
    print(f"pkcs7_pad(b'HOLA', 8):  {ejemplo_1.hex()}")

    ejemplo_2 = pkcs7_pad(b"12345678", 8)
    print(f"pkcs7_pad(b'12345678', 8): {ejemplo_2.hex()}")

    unpadded = pkcs7_unpad(ejemplo_1)
    print(f"pkcs7_unpad(ejemplo_1): {unpadded}")

    unpadded2 = pkcs7_unpad(ejemplo_2)
    print(f"pkcs7_unpad(ejemplo_2): {unpadded2}")