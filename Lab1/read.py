#!/usr/bin/env python3

from scapy.all import rdpcap, Raw
from scapy.layers.inet import ICMP
import re

# Spanish letter frequencies (approximate)
SPANISH_LETTER_FREQ = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86,
    'e': 13.68, 'f': 0.69, 'g': 1.01, 'h': 0.70,
    'i': 6.25, 'j': 0.44, 'k': 0.00, 'l': 4.97,
    'm': 3.15, 'n': 6.71, 'ñ': 0.31, 'o': 8.68,
    'p': 2.50, 'q': 0.88, 'r': 6.87, 's': 7.98,
    't': 4.63, 'u': 3.93, 'v': 0.90, 'w': 0.01,
    'x': 0.22, 'y': 0.90, 'z': 0.52
}


def read_message_from_pcap(pcap_file):
    """
    Reads the pcapng file and extracts the payload character from each ICMP echo request.
    The payload is assumed to be the hex representation (e.g. "41" for 'A') of the character,
    repeated over the data field. This version prints the raw data from each packet.
    """
    packets = rdpcap(pcap_file)
    chars = []


    for idx, packet in enumerate(packets):
        if packet.haslayer(ICMP) and packet[ICMP].type in (0, 999):  # Echo request or reply
            if packet.haslayer(Raw):
                data = packet[Raw].load

                if data:
                    try:
                        hex_data = data.hex()
                        decoded_data = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')
                        # Append only the last character from the decoded data
                        chars.append(decoded_data[-1])
                    except Exception as e:
                        print(f"Error decoding packet data: {e}")
                        continue

    cleaned_message = ''.join(chars)
    return cleaned_message


def caesar(text, shift):
    """
    Applies a Caesar shift to text by the given shift value.
    Non-alphabetic characters (such as spaces) are left unchanged.
    """
    result = []
    for char in text:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return ''.join(result)


def score_spanish_frequency(text):
    """
    Scores the text based on how closely its letter frequency matches typical Spanish letter frequencies.
    A higher (less negative) score means a closer match.
    """
    filtered = [ch for ch in text.lower() if ('a' <= ch <= 'z') or ch == 'ñ']
    if not filtered:
        return float('-inf')  # No letters found

    total_letters = len(filtered)
    freq_dict = {}
    for ch in filtered:
        freq_dict[ch] = freq_dict.get(ch, 0) + 1
    for ch in freq_dict:
        freq_dict[ch] = (freq_dict[ch] / total_letters) * 100

    # Calculate the difference from Spanish frequencies
    difference_sum = 0.0
    for letter, expected in SPANISH_LETTER_FREQ.items():
        actual = freq_dict.get(letter, 0.0)
        difference_sum += abs(actual - expected)

    return -difference_sum


def print_green(text):
    """Print the text in green color"""
    print(f"\033[92m{text}\033[0m")


def main():
    pcap_file = 'cesar.pcapng'
    ciphered_message = read_message_from_pcap(pcap_file)

    print("\nCiphered message extracted:")
    print(ciphered_message if ciphered_message else "<empty>")

    if not ciphered_message:
        print("Exiting because no ciphered text was detected. Check the pcap file and payload format.")
        return

    results = []
    best_score = float('-inf')
    best_message = None
    best_shift = None

    # Iterate over all shifts and store the candidate and score for each
    for shift_val in range(26):
        candidate = caesar(ciphered_message, -shift_val)
        current_score = score_spanish_frequency(candidate)
        results.append((shift_val, candidate, current_score))
        if current_score > best_score:
            best_score = current_score
            best_message = candidate
            best_shift = shift_val

    print("\nTrying all possible shifts:")
    for shift_val, candidate, current_score in results:
        if shift_val == best_shift:
            print_green(f"Shift {-shift_val:2d}: {candidate} | Score: {current_score:.2f}")
        else:
            print(f"Shift {-shift_val:2d}: {candidate} | Score: {current_score:.2f}")

    print("\nMost likely original message:")
    print(best_message)
    print(f"Detected displacement (used in encoding): {best_shift}")


if __name__ == '__main__':
    main()
