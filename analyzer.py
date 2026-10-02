from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
import csv
from datetime import datetime

INTERFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"
PACKET_COUNT = 20

CSV_FILE = "traffic.csv"


print("========================================")
print("      NETWORK TRAFFIC ANALYZER")
print("========================================")
print()
print("Interface :", INTERFACE)
print("Capturing :", PACKET_COUNT, "packets")
print()
print("Generate some network traffic...")
print()


packets = sniff(
    iface=INTERFACE,
    count=PACKET_COUNT
)


print()
print("Capture complete!")
print("Packets captured:", len(packets))
print()
print("Saving traffic to", CSV_FILE, "...")
print()


with open(
    CSV_FILE,
    "w",
    newline=""
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Size"
    ])

    for packet in packets:

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        source_ip = ""
        destination_ip = ""
        protocol = "Other"

        source_port = ""
        destination_port = ""

        # IPv4
        if packet.haslayer(IP):

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        # IPv6
        elif packet.haslayer(IPv6):

            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        # TCP
        if packet.haslayer(TCP):

            protocol = "TCP"

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        # UDP
        elif packet.haslayer(UDP):

            protocol = "UDP"

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # ICMP
        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        packet_size = len(packet)

        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size
        ])


print("Done!")
print("File created:", CSV_FILE)