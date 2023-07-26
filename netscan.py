from scapy.all import *
import argparse
from scapy.layers.l2 import ARP, Ether

# Parse command line arguments
parser = argparse.ArgumentParser(description='Scan a network subnet using ARP.')
parser.add_argument('subnet', help='subnet to scan (example: 192.168.1.0/24)')
args = parser.parse_args()

# Create ARP request packet
arp = ARP(pdst=args.subnet)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# Send packet and capture response
result = srp(packet, timeout=3, verbose=0)[0]

# Process response
clients = []
for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# Print results
print("Scanned subnet:", args.subnet)
print("Hosts found:")
print("IP" + " "*18 + "MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))