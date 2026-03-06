
# 🔐 Block Cipher Lab

**Universidad del Valle de Guatemala**
**Curso:** Cifrados de Información

Implementación y análisis de **DES, 3DES y AES** con distintos modos de operación, junto con experimentos que muestran sus propiedades de seguridad y vulnerabilidades.

---

# 1. Instalación y Uso

## Requisitos

* Python **3.10+**
* pip
* Librería cryptográfica

Instalar dependencias:

```bash
pip install pycryptodome pytest
```

---

## Estructura del Proyecto

```
Block_Cipher/
│
├── src/
│   ├── aes_cipher.py
│   ├── des_cipher.py
│   ├── tripledes_cipher.py
│   └── utils.py
│
├── tests/
│   ├── Resultados.png
│   └── test_ciphers.py
│
├── images/
│   ├── tux.png
│   ├── ppm_to_png.py
│   ├── aes_ecb.pmm
│   ├── aes_ctr.pmm
│   ├── aes_cbc.pmm
│   ├── tux.pmm
│   ├── tux_ecb.png
│   ├── tux_ctr.png
│   └── tux_cbc.png
│
├── requirements.txt
└── README.md
```

---

# 2. Ejecución

## Ejecutar los tests

Desde la raíz del proyecto:

```bash
python -m pytest tests/test_ciphers.py -v
```

Resultado esperado:

```
54 passed in 0.35s
```

Ejemplo de ejecución real:

[Resultados tests](tests/Resultado.png)

---

# 3. Ejemplos de Uso

---

# 3.1 DES en modo ECB

Implementado en:

[des_cipher](src/des_cipher.py)


### Ejemplo

```python
from des_cipher import des_encrypt_ecb, des_decrypt_ecb
from utils import generate_des_key

key = generate_des_key()
plaintext = b"Mensaje secreto DES"

ciphertext = des_encrypt_ecb(plaintext, key)

decrypted = des_decrypt_ecb(ciphertext, key)

print(ciphertext.hex())
print(decrypted)
```

---

# 3.2 Triple DES en modo CBC

Implementado en:

[tripledes_cipher](src/tripledes_cipher.py)

### Ejemplo

```python
from tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc
from utils import generate_3des_key, generate_iv

key = generate_3des_key(2)
iv = generate_iv(8)

plaintext = b"Mensaje secreto 3DES"

ciphertext = encrypt_3des_cbc(plaintext, key, iv)

decrypted = decrypt_3des_cbc(ciphertext, key, iv)
```

---

# 3.3 AES (ECB, CBC, CTR)

Implementado en:

[aes_cipher](src/aes_cipher.py)

Ejemplo:

```python
from aes_cipher import encrypt_ecb, encrypt_cbc, encrypt_ctr
from utils import generate_aes_key

key = generate_aes_key(256)

plaintext = b"Mensaje para AES"

ct_ecb = encrypt_ecb(plaintext, key)
ct_cbc = encrypt_cbc(plaintext, key)
ct_ctr = encrypt_ctr(plaintext, key)
```

---

# 4. Proceso de Testing
Se solicitó a claude una batería de test que cubrieran:

* generación de claves
* cifrado
* descifrado
* padding
* vulnerabilidad ECB
* comportamiento de CBC
* propiedades de CTR
* análisis de rendimiento

Archivo principal de tests:

[test_ciphers](tests/test_ciphers.py)

Los tests incluyen:

| Categoría   | Tests                                           |
| ----------- | ----------------------------------------------- |
| DES ECB     | generación de clave, cifrado, bloques idénticos |
| 3DES CBC    | IV, claves, roundtrip                           |
| AES Modes   | ECB, CBC, CTR                                   |
| Padding     | PKCS7 pad/unpad                                 |
| Análisis    | ECB vs CBC                                      |
| Performance | CTR vs CBC                                      |

Resultado final:

```
54 tests passed
```

---

# 5. Comparación Visual ECB vs CBC vrs CTR

Las imágenes muestran cómo ECB revela patrones del plaintext y luego cómo CBC y CTR son más seguros.

| Original                             | ECB                        | CBC                        | CTR                        |
| ------------------------------------ | -------------------------- | -------------------------- | -------------------------- |
| ![original](images/tux.png) | ![ecb](images/tux_ecb.png) | ![cbc](images/tux_cbc.png) | ![ctr](images/tux_ctr.png) |


### Observación

En **ECB**:

* patrones visibles

En **CBC** y **CTR**:

* patrones desaparecen y es irreconocible

---

# 6. Análisis

---

# 6.1 Análisis de Tamaños de Clave

## DES

* Tamaño: **64 bits (8 bytes)**
* Seguridad efectiva: **56 bits**

Snippet de generación de clave:

```python
def generate_des_key():
    return secrets.token_bytes(8)
```

Implementado en:



### Por qué DES es inseguro

DES fue diseñado en los años 70.
Su espacio de claves es demasiado pequeño para hardware moderno.

Total claves posibles:

```
2^56 ≈ 7.2e16
```

Un cluster moderno puede probar aproximadamente:

```
10^12 claves por segundo
```

Tiempo estimado:

```
7.2e16 / 10^12 = 72000 segundos
≈ 20 horas
```

Por esta razón DES es considerado **obsoleto**.

---

## 3DES

Opciones de clave:

| Tipo     | Bytes | Bits |
| -------- | ----- | ---- |
| 2 claves | 16    | 128  |
| 3 claves | 24    | 192  |

Ejemplo de generación:

```python
generate_3des_key(2)
```

---

## AES

Tamaños soportados:

| AES     | Bytes | Bits |
| ------- | ----- | ---- |
| AES-128 | 16    | 128  |
| AES-192 | 24    | 192  |
| AES-256 | 32    | 256  |

Ejemplo:

```python
generate_aes_key(256)
```

---

# 6.2 Comparación de Modos de Operación

| Modo | Descripción                            |
| ---- | -------------------------------------- |
| ECB  | cada bloque cifrado independientemente |
| CBC  | cada bloque depende del anterior       |
| CTR  | convierte el cifrado en stream cipher  |

Diferencias clave:

| Propiedad       | ECB | CBC |
| --------------- | --- | --- |
| IV              | este no   | este si   |
| Determinista    | este si   | este no   |
| Oculta patrones | este no  | este si   |

---

# 6.3 Vulnerabilidad de ECB

Ejemplo:

```python
plaintext = b"ATAQUE ATAQUE ATAQUE"
```

### ECB

```
block1 -> A1B2C3
block2 -> A1B2C3
block3 -> A1B2C3
```

### CBC

```
block1 -> F7A22C
block2 -> 91CCDA
block3 -> 44AD22
```

Los bloques repetidos generan **ciphertext repetido**.

Esto filtra información como:

* estructura de archivos
* patrones de texto
* imágenes

---

# 6.4 Vector de Inicialización (IV)

El **IV** introduce aleatoriedad en CBC.

Experimento:

### Mismo IV

```python
ct1 = encrypt_3des_cbc(msg, key, iv)
ct2 = encrypt_3des_cbc(msg, key, iv)
```

Resultado:

```
ct1 == ct2
```

### IV diferente

```python
ct1 = encrypt_3des_cbc(msg, key, generate_iv(8))
ct2 = encrypt_3des_cbc(msg, key, generate_iv(8))
```

Resultado:

```
ct1 != ct2
```

Si un atacante observa mensajes con **IV reutilizado**, puede detectar:

* mensajes repetidos
* patrones en comunicación

---

# 6.5 Padding

PKCS7 asegura que el plaintext tenga tamaño múltiplo del bloque.

Ejemplo con bloque de **8 bytes**

### Mensaje de 5 bytes

```
HELLO
```

Padding:

```
HELLO 03 03 03
```

### Mensaje de 8 bytes

```
12345678
```

Padding agregado:

```
08 08 08 08 08 08 08 08
```

### Mensaje de 10 bytes

```
0123456789
```

Padding:

```
06 06 06 06 06 06
```

Implementación:



---

# 6.6 Recomendaciones de Uso

| Modo | Uso recomendado  | Problemas                   |
| ---- | ---------------- | --------------------------- |
| ECB  | nunca usar       | filtra patrones             |
| CBC  | cifrado general  | vulnerable a padding oracle |
| CTR  | alto rendimiento | requiere nonce único        |
| GCM  | recomendado      | autenticado                 |

---

## Ejemplo seguro en Python

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)

cipher = AES.new(key, AES.MODE_GCM)

ciphertext, tag = cipher.encrypt_and_digest(b"mensaje secreto")
```
