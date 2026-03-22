"""
Run this to find your active network interface.
Paste in PowerShell (as Administrator):
    python find_interface.py
"""
from scapy.all import conf, get_if_list
import socket

print("\n=== ALL INTERFACES ===")
for iface_name, iface in conf.ifaces.items():
    print(f"  Name : {iface.name}")
    print(f"  IP   : {iface.ip}")
    print(f"  MAC  : {iface.mac}")
    print(f"  NPF  : {iface_name}")
    print()

print("=== YOUR ACTIVE INTERFACE (best guess) ===")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()
    print(f"  Your IP: {my_ip}")
    for iface_name, iface in conf.ifaces.items():
        if iface.ip == my_ip:
            print(f"\n  USE THIS INTERFACE:")
            print(f"  NPF string : {iface_name}")
            print(f"  Friendly   : {iface.name}")
except Exception as e:
    print(f"  Error: {e}")