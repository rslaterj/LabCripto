import sys
import subprocess

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send_ping.py '<ciphered_text>'")
        sys.exit(1)

    ciphered_text = sys.argv[1]

    for char in ciphered_text:
        # Convert the character to its hexadecimal representation.
        # For example, 'A' becomes '41' and space becomes '20'.
        hex_data = char.encode('utf-8').hex()
        # Construct the ping command.
        # -c 1 sends one ping packet.
        command = ["ping", "-c", "1", "-p", hex_data, "8.8.8.8"]
        print(f"Sending ping with data '{char}' (hex: {hex_data})")
        # Execute the ping command.
        subprocess.run(command)