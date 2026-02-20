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
    ejemplo_1 = pkcs7_pad(b"HOLA", 8)
    print(f"pkcs7_pad(b'HOLA', 8):  {ejemplo_1.hex()}")

    ejemplo_2 = pkcs7_pad(b"12345678", 8)
    print(f"pkcs7_pad(b'12345678', 8): {ejemplo_2.hex()}")

    unpadded = pkcs7_unpad(ejemplo_1)
    print(f"pkcs7_unpad(ejemplo_1): {unpadded}")

    unpadded2 = pkcs7_unpad(ejemplo_2)
    print(f"pkcs7_unpad(ejemplo_2): {unpadded2}")