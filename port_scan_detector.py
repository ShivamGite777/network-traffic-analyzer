import csv
from collections import defaultdict

filename = "traffic.csv"

# Store unique destination ports for every source IP
source_ports = defaultdict(set)

with open(filename, "r") as file:

    reader = csv.DictReader(file)

    for packet in reader:

        source_ip = packet["Source IP"]
        destination_port = packet["Destination Port"]

        if source_ip and destination_port.isdigit():

            source_ports[source_ip].add(int(destination_port))


print("Port Scan Detection")
print("===================")

scan_found = False

# Threshold
PORT_THRESHOLD = 10

for source_ip, ports in source_ports.items():

    if len(ports) >= PORT_THRESHOLD:

        print("\n⚠️ Possible Port Scan Detected")
        print("Source IP       :", source_ip)
        print("Unique Ports    :", len(ports))
        print("Ports Scanned   :", sorted(ports))

        scan_found = True


if not scan_found:

    print("\nNo possible port scan detected.")

print("\nAnalysis complete!")