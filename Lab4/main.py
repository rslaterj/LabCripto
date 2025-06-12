from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad
import base64
import string
import random

def ajustar_parametro_random(parametro, longitud):
    b = parametro.encode('ascii')
    if len(b) > longitud: return b[:longitud]
    elif len(b) < longitud:
        padd = longitud - len(b)
        chars = string.ascii_letters + string.digits
        addpadd = ''.join(random.choice(chars) for _ in range(padd))
        return b + addpadd.encode('ascii')
    else: return b

def cifrar_des(key, iv, mensaje):
    des_key = ajustar_parametro_random(key, 8)
    des_iv = ajustar_parametro_random(iv, 8)
    print(f"Key: {des_key.decode()}")
    print(f"IV:  {des_iv.decode()}")
    cipher = DES.new(des_key, DES.MODE_CBC, des_iv)
    mensaje_bytes = mensaje.encode('utf-8')
    mensaje_padded = pad(mensaje_bytes, DES.block_size)
    return cipher.encrypt(mensaje_padded)

def cifrar_3des(key, iv, mensaje):
    des3_key = ajustar_parametro_random(key, 24)
    des3_iv = ajustar_parametro_random(iv, 8)
    print(f"Key: {des3_key.decode()}")
    print(f"IV:  {des3_iv.decode()}")
    cipher = DES3.new(des3_key, DES3.MODE_CBC, des3_iv)
    mensaje_bytes = mensaje.encode('utf-8')
    mensaje_padded = pad(mensaje_bytes, DES3.block_size)
    return cipher.encrypt(mensaje_padded)

def cifrar_aes256(key, iv, mensaje):
    aes_key = ajustar_parametro_random(key, 32)
    aes_iv = ajustar_parametro_random(iv, 16)
    print(f"Key: {aes_key.decode()}")
    print(f"IV:  {aes_iv.decode()}")
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    mensaje_bytes = mensaje.encode('utf-8')
    mensaje_padded = pad(mensaje_bytes, AES.block_size)
    return cipher.encrypt(mensaje_padded)


if __name__ == "__main__":
    key = input("Ingresa clave (texto plano): ")
    iv = input("Ingresa IV (texto plano): ")
    mensaje = input("Ingresa el mensaje a cifrar: ")

    print("\n--- DES ---")
    print(f"Ciphertext (base64): {base64.b64encode(cifrar_des(key, iv, mensaje)).decode()}")
    print("\n--- 3DES ---")
    print(f"Ciphertext (base64): {base64.b64encode(cifrar_3des(key, iv, mensaje)).decode()}")
    print("\n--- AES-256 ---")
    print(f"Ciphertext (base64): {base64.b64encode(cifrar_aes256(key, iv, mensaje)).decode()}")
