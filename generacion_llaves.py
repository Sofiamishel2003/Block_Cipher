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

if __name__ == "__main__":

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

