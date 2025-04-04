#!/usr/bin/env python3
import sys
import time
import struct
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

if len(sys.argv) < 2:
    print("Usage: python send_ping.py '<ciphered_text>'")
    sys.exit(1)

ciphered_text = sys.argv[1]
dest_ip = "8.8.8.8"

normal_payload_tail = b'Y' * 40
icmp_id = 0x1234

seq = 1
for char in ciphered_text:
    t = time.time()
    tv_sec = int(t)
    tv_usec = int((t - tv_sec) * 1000000)
    timestamp = struct.pack("!II", tv_sec, tv_usec)  # 8 bytes in network (big-endian) order

    custom_data = char.encode('utf-8') * 8
    # Complete payload: timestamp (8 bytes) + custom data (8 bytes) + constant tail (40 bytes)
    payload = timestamp + custom_data + normal_payload_tail
    pkt = IP(dst=dest_ip, id=seq) / ICMP(id=icmp_id, seq=seq) / payload

    # Delete checksum so Scapy recalculates it
    del pkt[ICMP].chksum

    print(f"Sending ping with char '{char}' (custom payload: {custom_data.hex()}) with seq {seq} and id {icmp_id}")
    send(pkt, verbose=False)
    seq += 1
