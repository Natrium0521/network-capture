import json
import os
from scapy.all import sniff, Packet


# Initialize CONFIG
if not os.path.isfile("./config.json"):
    CONFIG_INIT = {"iface": ""}
    with open("./config.json", "w", encoding="utf-8") as f:
        json.dump(CONFIG_INIT, f)
    print("Set config.json and restart...")
    exit(0)
with open("./config.json", "r", encoding="utf-8") as f:
    CONFIG = json.load(f)
IFACE = CONFIG.get("iface", "")


def print_bytes(data):
    def pb(b):
        hex_str = " ".join(f"{c:02x}" for c in b)
        if len(hex_str) > 23:
            hex_str = hex_str[:23] + " " + hex_str[23:]
        ascii_str = "".join(f'{chr(c) if 32 <= c <= 126 else "."}' for c in b)
        if len(ascii_str) > 8:
            ascii_str = ascii_str[:8] + " " + ascii_str[8:]
        print(f"{hex_str:<48} | {ascii_str}")

    arr = []
    for i in data:
        arr.append(i)
        if len(arr) == 16:
            pb(arr)
            arr = []
    if len(arr):
        pb(arr)


def callback(packet):
    raw_data = bytes(packet)
    print_bytes(raw_data)


sniff(filter="icmp", prn=callback, count=1, iface=IFACE)
