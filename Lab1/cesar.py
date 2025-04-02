import sys

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            # Determine the base for uppercase or lowercase letters.
            base = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap-around using modulo 26.
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            # Leave spaces (or any non-alphabetic character) unchanged.
            result += char
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <text> <shift>")
        sys.exit(1)

    text = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("Shift must be an integer")
        sys.exit(1)

    ciphered_text = caesar_cipher(text, shift)
    print(ciphered_text)