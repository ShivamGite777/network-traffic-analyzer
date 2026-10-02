import csv
from collections import Counter

filename = "traffic.csv"

with open(filename, "r") as file:

    reader = csv.DictReader(file)

    packets = list(reader)

print("Network Traffic Statistics")
print("==========================")

# Total packets
print("Total Packets :", len(packets))

# Protocol count
protocols = Counter(packet["Protocol"] for packet in packets)

print("\nProtocol Statistics")
print("-------------------")

for protocol, count in protocols.items():
    print(protocol, ":", count)

# Total traffic
total_bytes = sum(int(packet["Packet Size"]) for packet in packets)

print("\nTotal Traffic :", total_bytes, "bytes")

# Largest packet
if packets:

    largest = max(
        packets,
        key=lambda packet: int(packet["Packet Size"])
    )

    print("Largest Packet:", largest["Packet Size"], "bytes")

print("\nAnalysis complete!")