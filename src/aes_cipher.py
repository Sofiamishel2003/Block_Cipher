from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from utils import generate_aes_key


def split_ppm(file_path: str):
    """
    Divide un archivo PPM en header y body.
    El header de PPM normalmente son las primeras 3 líneas:
        P6
        width height
        maxcolor
    """
    with open(file_path, "rb") as f:
        lines = f.readlines()

    header = lines[:3]
    body = b"".join(lines[3:])

    return header, body


def save_ppm(path: str, header: bytes, body: bytes):
    """
    Guarda un archivo PPM reconstruyendo header + body.
    """
    with open(path, "wb") as f:
        f.writelines(header)
        f.write(body)


def encrypt_ecb(body: bytes, key: bytes) -> bytes:
    """
    ECB: cada bloque se cifra de forma independiente.
    Bloques iguales -> ciphertext igual -> patrones visibles.
    """
    cipher = AES.new(key, AES.MODE_ECB)

    encrypted = cipher.encrypt(pad(body, AES.block_size))

    # truncamos para mantener tamaño original de imagen
    return encrypted[:len(body)]


def encrypt_cbc(body: bytes, key: bytes) -> bytes:
    """
    CBC: cada bloque depende del anterior.
    IV aleatorio -> los patrones desaparecen.
    """
    cipher = AES.new(key, AES.MODE_CBC)

    encrypted = cipher.encrypt(pad(body, AES.block_size))

    return encrypted[:len(body)]


def encrypt_ctr(body: bytes, key: bytes) -> bytes:
    """
    CTR: convierte AES en cifrado de flujo.
    No requiere padding.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"")

    return cipher.encrypt(body)


def encrypt_image():
    """
    Función principal que cifra tux.ppm en 3 modos
    y genera nuevas imágenes cifradas.
    """

    key = generate_aes_key(256)

    print("AES Key:", key.hex())

    header, body = split_ppm("images/tux.ppm")

    print("Header size:", len(header))
    print("Body size:", len(body))

    # ECB
    ecb_body = encrypt_ecb(body, key)
    save_ppm("images/aes/aes_ecb.ppm", header, ecb_body)

    # CBC
    cbc_body = encrypt_cbc(body, key)
    save_ppm("images/aes/aes_cbc.ppm", header, cbc_body)

    # CTR
    ctr_body = encrypt_ctr(body, key)
    save_ppm("images/aes/aes_ctr.ppm", header, ctr_body)

    print("Encrypted images generated:")
    print(" - images/aes/aes_ecb.ppm")
    print(" - images/aes/aes_cbc.ppm")
    print(" - images/aes/aes_ctr.ppm")


if __name__ == "__main__":
    encrypt_image()