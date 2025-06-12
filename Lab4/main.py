from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad
from base64 import b64encode
import sys

BLOCK_SIZES = {
    'DES': 8,
    '3DES': 8,
    'AES': 16
}


def adjust_key(key, required_length):
    if len(key) > required_length: return key[:required_length]
    elif len(key) < required_length: return key.ljust(required_length, b'\0')
    return key


def get_cipher(algorithm, key, iv):
    if algorithm == 'DES':
        key = adjust_key(key, 8)
        print(f"Clave utilizada (DES): {key.hex()}")
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == '3DES':
        key = adjust_key(key, 24)  # 24 is max, compatible with 16 too
        print(f"Clave utilizada (3DES): {key.hex()}")
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'AES':
        key = adjust_key(key, 32)
        print(f"Clave utilizada (AES-256): {key.hex()}")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no soportado.")
    return cipher


def main():
    print("=== Cifrado con DES, AES-256 y 3DES ===")
    algorithm = input("Seleccione el algoritmo (DES / 3DES / AES): ").strip().upper()

    key = input("Ingrese la clave (en hexadecimal): ")
    iv = input("Ingrese el vector de inicialización IV (en hexadecimal): ")
    plaintext = input("Ingrese el texto plano a cifrar: ")

    try:
        key_bytes = bytes.fromhex(key)
        iv_bytes = bytes.fromhex(iv)

        block_size = BLOCK_SIZES.get(algorithm)
        if not block_size:
            raise ValueError("Algoritmo no reconocido.")

        cipher = get_cipher(algorithm, key_bytes, iv_bytes)
        padded_text = pad(plaintext.encode(), block_size)
        ciphertext = cipher.encrypt(padded_text)

        print(f"Texto cifrado (Base64): {b64encode(ciphertext).decode()}")

    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
