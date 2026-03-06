import pytest
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── Ajustar el path para importar desde src/ ──────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from des_cipher import des_encrypt_ecb, des_decrypt_ecb
from tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc
from aes_cipher import encrypt_ecb, encrypt_cbc, encrypt_ctr, split_ppm, save_ppm
from utils import (
    generate_des_key,
    generate_3des_key,
    generate_aes_key,
    generate_iv,
    pkcs7_pad,
    pkcs7_unpad,
)


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 1.1 – DES ECB
# ══════════════════════════════════════════════════════════════════════════════

class TestDESECB:
    """1.1 Cifrado DES con Modo ECB (20 puntos)"""

    def test_key_generation_length(self):
        """La clave DES debe ser exactamente 8 bytes."""
        key = generate_des_key()
        assert len(key) == 8, f"Se esperaban 8 bytes, se obtuvieron {len(key)}"

    def test_key_is_random(self):
        """Dos claves generadas consecutivamente deben ser distintas."""
        assert generate_des_key() != generate_des_key()

    def test_encrypt_returns_bytes(self):
        key = generate_des_key()
        ct = des_encrypt_ecb(b"Hola mundo!", key)
        assert isinstance(ct, bytes)

    def test_ciphertext_is_multiple_of_block_size(self):
        """El ciphertext DES debe ser múltiplo de 8 bytes (bloque DES)."""
        key = generate_des_key()
        ct = des_encrypt_ecb(b"Mensaje corto", key)
        assert len(ct) % 8 == 0

    def test_encrypt_decrypt_roundtrip_short(self):
        """Cifrar y descifrar un mensaje corto devuelve el original."""
        key = generate_des_key()
        pt = b"Mensaje secreto para DES"
        assert des_decrypt_ecb(des_encrypt_ecb(pt, key), key) == pt

    def test_encrypt_decrypt_roundtrip_exact_block(self):
        """Mensaje exactamente de 8 bytes (un bloque DES)."""
        key = generate_des_key()
        pt = b"12345678"
        assert des_decrypt_ecb(des_encrypt_ecb(pt, key), key) == pt

    def test_encrypt_decrypt_roundtrip_multiblock(self):
        """Mensaje multi-bloque (>8 bytes)."""
        key = generate_des_key()
        pt = b"A" * 64
        assert des_decrypt_ecb(des_encrypt_ecb(pt, key), key) == pt

    def test_different_keys_produce_different_ciphertexts(self):
        pt = b"Texto igual"
        ct1 = des_encrypt_ecb(pt, b"clave001")
        ct2 = des_encrypt_ecb(pt, b"clave002")
        assert ct1 != ct2

    def test_invalid_key_length_raises(self):
        """Clave que no sea 8 bytes debe lanzar ValueError."""
        with pytest.raises((ValueError, Exception)):
            des_encrypt_ecb(b"datos", b"corta")

    # ── Análisis 2.3: ECB – bloques idénticos → ciphertexts idénticos ─────────
    def test_ecb_identical_blocks_produce_identical_ciphertext(self):
        """
        Con ECB, bloques de plaintext iguales producen bloques de ciphertext iguales.
        Esto demuestra la debilidad fundamental de ECB.
        """
        key = b"8bytekey"
        block = b"ATAQUE!!"  # exactamente 8 bytes
        plaintext = block * 3          # tres bloques idénticos
        ct = des_encrypt_ecb(plaintext, key)

        # Cada bloque cifrado de 8 bytes debe ser igual
        b0 = ct[0:8]
        b1 = ct[8:16]
        b2 = ct[16:24]
        assert b0 == b1 == b2, (
            "ECB debe producir bloques idénticos para plaintext idéntico. "
            f"b0={b0.hex()}, b1={b1.hex()}, b2={b2.hex()}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 1.2 – 3DES CBC
# ══════════════════════════════════════════════════════════════════════════════

class TestTripleDESCBC:
    """1.2 Cifrado 3DES con Modo CBC (25 puntos)"""

    def test_key_option_2_is_16_bytes(self):
        assert len(generate_3des_key(2)) == 16

    def test_key_option_1_is_24_bytes(self):
        assert len(generate_3des_key(1)) == 24

    def test_invalid_key_option_raises(self):
        with pytest.raises(ValueError):
            generate_3des_key(99)

    def test_iv_generation_8_bytes(self):
        iv = generate_iv(8)
        assert len(iv) == 8

    def test_iv_is_random(self):
        """Cada IV generado debe ser distinto."""
        assert generate_iv(8) != generate_iv(8)

    def test_encrypt_returns_multiple_of_8(self):
        key = generate_3des_key(2)
        iv = generate_iv(8)
        ct = encrypt_3des_cbc(b"Mensaje de prueba", key, iv)
        assert len(ct) % 8 == 0

    def test_roundtrip_short_message(self):
        key = generate_3des_key(2)
        iv = generate_iv(8)
        pt = b"Mensaje secreto"
        assert decrypt_3des_cbc(encrypt_3des_cbc(pt, key, iv), key, iv) == pt

    def test_roundtrip_exact_block(self):
        """Mensaje de exactamente 8 bytes (un bloque 3DES)."""
        key = generate_3des_key(2)
        iv = generate_iv(8)
        pt = b"12345678"
        assert decrypt_3des_cbc(encrypt_3des_cbc(pt, key, iv), key, iv) == pt

    def test_roundtrip_24_byte_key(self):
        """Opción 1: clave de 24 bytes (tres claves independientes)."""
        key = generate_3des_key(1)
        iv = generate_iv(8)
        pt = b"Triple DES con 3 claves"
        assert decrypt_3des_cbc(encrypt_3des_cbc(pt, key, iv), key, iv) == pt

    def test_invalid_iv_length_raises(self):
        key = generate_3des_key(2)
        with pytest.raises(ValueError):
            encrypt_3des_cbc(b"datos", key, b"corto")

    def test_invalid_key_length_raises(self):
        iv = generate_iv(8)
        with pytest.raises(ValueError):
            encrypt_3des_cbc(b"datos", b"clavecorta", iv)

    def test_invalid_ciphertext_raises_on_decrypt(self):
        key = generate_3des_key(2)
        iv = generate_iv(8)
        with pytest.raises((ValueError, Exception)):
            decrypt_3des_cbc(b"", key, iv)

    # ── Análisis 2.4: CBC – mismo IV vs IV diferente ──────────────────────────
    def test_cbc_same_iv_produces_same_ciphertext(self):
        """Mismo mensaje + mismo IV → mismo ciphertext (riesgo de reutilización)."""
        key = generate_3des_key(2)
        iv = b"\x00" * 8
        pt = b"Mensaje repetido exacto!!"
        ct1 = encrypt_3des_cbc(pt, key, iv)
        ct2 = encrypt_3des_cbc(pt, key, iv)
        assert ct1 == ct2

    def test_cbc_different_ivs_produce_different_ciphertexts(self):
        """Mismo mensaje + IVs distintos → ciphertexts distintos."""
        key = generate_3des_key(2)
        pt = b"Mensaje repetido exacto!!"
        ct1 = encrypt_3des_cbc(pt, key, generate_iv(8))
        ct2 = encrypt_3des_cbc(pt, key, generate_iv(8))
        assert ct1 != ct2

    def test_cbc_different_keys_different_ciphertexts(self):
        """Claves distintas → ciphertexts distintos."""
        iv = generate_iv(8)
        pt = b"Texto de prueba 3DES"
        ct1 = encrypt_3des_cbc(pt, generate_3des_key(2), iv)
        ct2 = encrypt_3des_cbc(pt, generate_3des_key(2), iv)
        assert ct1 != ct2


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 1.3 – AES (ECB, CBC, CTR) + análisis visual
# ══════════════════════════════════════════════════════════════════════════════

class TestAESModes:
    """1.3 Cifrado AES con Modos ECB, CBC y CTR (30 puntos)"""

    def setup_method(self):
        self.key = generate_aes_key(256)
        self.plaintext = b"X" * 160  # 10 bloques AES de 16 bytes

    # ── Generación de claves ───────────────────────────────────────────────────
    def test_aes_key_128_bits(self):
        assert len(generate_aes_key(128)) == 16

    def test_aes_key_192_bits(self):
        assert len(generate_aes_key(192)) == 24

    def test_aes_key_256_bits(self):
        assert len(generate_aes_key(256)) == 32

    def test_aes_invalid_key_size_raises(self):
        with pytest.raises(ValueError):
            generate_aes_key(100)

    # ── ECB ───────────────────────────────────────────────────────────────────
    def test_ecb_output_length_matches_input(self):
        """encrypt_ecb trunca al tamaño original del body."""
        ct = encrypt_ecb(self.plaintext, self.key)
        assert len(ct) == len(self.plaintext)

    def test_ecb_changes_data(self):
        ct = encrypt_ecb(self.plaintext, self.key)
        assert ct != self.plaintext

    def test_ecb_deterministic_same_key(self):
        """ECB es determinista: mismos inputs → mismo output."""
        ct1 = encrypt_ecb(self.plaintext, self.key)
        ct2 = encrypt_ecb(self.plaintext, self.key)
        assert ct1 == ct2

    # ── Análisis 2.3: ECB bloques idénticos (AES) ─────────────────────────────
    def test_ecb_identical_16byte_blocks_produce_identical_ciphertext(self):
        """
        Con AES-ECB, bloques de 16 bytes iguales producen el mismo ciphertext.
        """
        block = b"A" * 16
        pt = block * 4
        ct = encrypt_ecb(pt, self.key)
        b0, b1, b2, b3 = ct[0:16], ct[16:32], ct[32:48], ct[48:64]
        assert b0 == b1 == b2 == b3

    # ── CBC ───────────────────────────────────────────────────────────────────
    def test_cbc_output_length_matches_input(self):
        ct = encrypt_cbc(self.plaintext, self.key)
        assert len(ct) == len(self.plaintext)

    def test_cbc_changes_data(self):
        ct = encrypt_cbc(self.plaintext, self.key)
        assert ct != self.plaintext

    def test_cbc_is_non_deterministic(self):
        """CBC usa IV aleatorio → dos cifrados del mismo plaintext son distintos."""
        ct1 = encrypt_cbc(self.plaintext, self.key)
        ct2 = encrypt_cbc(self.plaintext, self.key)
        assert ct1 != ct2

    def test_cbc_different_from_ecb(self):
        """CBC y ECB del mismo plaintext deben diferir."""
        assert encrypt_ecb(self.plaintext, self.key) != encrypt_cbc(self.plaintext, self.key)

    # ── CTR ───────────────────────────────────────────────────────────────────
    def test_ctr_output_length_equals_input(self):
        """CTR es cifrado de flujo: sin padding, longitud exacta."""
        ct = encrypt_ctr(self.plaintext, self.key)
        assert len(ct) == len(self.plaintext)

    def test_ctr_no_padding_needed_odd_size(self):
        """CTR funciona con cualquier longitud, incluso impar."""
        pt_odd = b"Z" * 37
        ct = encrypt_ctr(pt_odd, self.key)
        assert len(ct) == 37

    def test_ctr_changes_data(self):
        ct = encrypt_ctr(self.plaintext, self.key)
        assert ct != self.plaintext


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 2.5 – Padding PKCS#7 (manual)
# ══════════════════════════════════════════════════════════════════════════════

class TestPKCS7Padding:
    """2.5 Padding PKCS#7 implementado manualmente en utils.py"""

    def test_pad_5_bytes(self):
        """5 bytes → 3 bytes de padding con valor 0x03."""
        result = pkcs7_pad(b"HELLO", 8)
        assert len(result) == 8
        assert result == b"HELLO\x03\x03\x03"

    def test_pad_exact_block(self):
        """8 bytes (bloque exacto) → se agrega un bloque completo de padding."""
        result = pkcs7_pad(b"12345678", 8)
        assert len(result) == 16
        assert result[8:] == b"\x08" * 8

    def test_pad_10_bytes(self):
        """10 bytes → 6 bytes de padding con valor 0x06."""
        result = pkcs7_pad(b"0123456789", 8)
        assert len(result) == 16
        assert result[10:] == b"\x06" * 6

    def test_pad_result_is_multiple_of_block_size(self):
        for length in range(1, 25):
            result = pkcs7_pad(b"A" * length, 8)
            assert len(result) % 8 == 0

    def test_unpad_recovers_5_bytes(self):
        padded = pkcs7_pad(b"HELLO", 8)
        assert pkcs7_unpad(padded) == b"HELLO"

    def test_unpad_recovers_exact_block(self):
        padded = pkcs7_pad(b"12345678", 8)
        assert pkcs7_unpad(padded) == b"12345678"

    def test_unpad_recovers_10_bytes(self):
        padded = pkcs7_pad(b"0123456789", 8)
        assert pkcs7_unpad(padded) == b"0123456789"

    def test_unpad_empty_raises(self):
        with pytest.raises((ValueError, Exception)):
            pkcs7_unpad(b"")

    def test_unpad_invalid_padding_raises(self):
        with pytest.raises((ValueError, Exception)):
            pkcs7_unpad(b"HELLO\x00\x00\x00")  # padding inválido (0x00)

    def test_pad_unpad_roundtrip_all_sizes(self):
        """Para cualquier longitud 1..31, pad→unpad recupera el original."""
        for length in range(1, 32):
            data = bytes(range(length % 256)) * (length // 256 + 1)
            data = data[:length]
            assert pkcs7_unpad(pkcs7_pad(data, 8)) == data


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 3.1 – CTR: sin padding + rendimiento básico
# ══════════════════════════════════════════════════════════════════════════════

class TestCTRMode:
    """3.1 Modo CTR – sin padding y comparación básica de rendimiento."""

    def test_ctr_preserves_exact_length_various_sizes(self):
        key = generate_aes_key(256)
        for size in [1, 7, 15, 16, 17, 100, 255, 256, 1000]:
            pt = os.urandom(size)
            assert len(encrypt_ctr(pt, key)) == size

    def test_ctr_timing_comparable_or_faster_than_cbc(self):
        """
        CTR no debe ser significativamente más lento que CBC.
        (benchmark orientativo, no un límite estricto).
        """
        key = generate_aes_key(256)
        data = os.urandom(10 * 1024 * 1024)  # 10 MB

        start = time.perf_counter()
        encrypt_cbc(data, key)
        cbc_time = time.perf_counter() - start

        start = time.perf_counter()
        encrypt_ctr(data, key)
        ctr_time = time.perf_counter() - start

        # CTR no debe tardar más del doble que CBC
        assert ctr_time < cbc_time * 2, (
            f"CTR ({ctr_time:.3f}s) tardó más del doble que CBC ({cbc_time:.3f}s)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 2.3 – Análisis de vulnerabilidad ECB vs CBC con texto repetido
# ══════════════════════════════════════════════════════════════════════════════

class TestECBvsCBCAnalysis:
    """2.3 Demostración de la vulnerabilidad ECB con texto repetido."""

    def test_ecb_repeated_text_leaks_pattern(self):
        """
        'ATAQUE!ATAQUE!A' × 3 → tres bloques de ciphertext idénticos en ECB.
        Esto demuestra que ECB filtra patrones del plaintext.
        """
        key = b"clave_de_16bytes"  # 16 bytes para AES
        block = b"ATAQUE!ATAQUE!A!"  # exactamente 16 bytes
        pt = block * 3

        ct = encrypt_ecb(pt, key)
        b0, b1, b2 = ct[0:16], ct[16:32], ct[32:48]

        assert b0 == b1 == b2, (
            "ECB debería producir bloques idénticos. "
            f"\nb0={b0.hex()}\nb1={b1.hex()}\nb2={b2.hex()}"
        )

    def test_cbc_repeated_text_hides_pattern(self):
        """
        El mismo plaintext repetido con CBC produce bloques distintos.
        """
        key = generate_aes_key(256)
        block = b"ATAQUE!ATAQUE!A!"  # 16 bytes
        pt = block * 3

        ct = encrypt_cbc(pt, key)
        b0, b1, b2 = ct[0:16], ct[16:32], ct[32:48]

        # En CBC los bloques deben ser distintos
        assert not (b0 == b1 == b2), (
            "CBC NO debe producir bloques idénticos para plaintext igual."
        )