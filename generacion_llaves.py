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
    # TODO: Implementar
    # Convertir bits a bytes: key_size // 8
    pass


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """
    # TODO: Implementar
    pass

if __name__ == "__main__":

    des_key = generate_des_key()
    print(f"DES key (8 bytes):          {des_key.hex()}  [{len(des_key)} bytes]")

    key3des_op1 = generate_3des_key(1)
    print(f"3DES key opción 1 (24 b):   {key3des_op1.hex()}  [{len(key3des_op1)} bytes]")

    key3des_op2 = generate_3des_key(2)
    print(f"3DES key opción 2 (16 b):   {key3des_op2.hex()}  [{len(key3des_op2)} bytes]")

    key3des_op3 = generate_3des_key(3)
    print(f"3DES key opción 3 (8 b):    {key3des_op3.hex()}  [{len(key3des_op3)} bytes]")
