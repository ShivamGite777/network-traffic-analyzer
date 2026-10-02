import csv
from collections import Counter, defaultdict

filename = "traffic.csv"

packets = []

with open(filename, "r") as file:

    reader = csv.DictReader(file)

    for packet in reader:
        packets.append(packet)


print("========================================")
print("       NETWORK SECURITY REPORT")
print("========================================")

# -----------------------------
# 1. BASIC STATISTICS
# -----------------------------

print("\n[1] TRAFFIC STATISTICS")
print("----------------------------------------")

print("Total Packets :", len(packets))

protocols = Counter(packet["Protocol"] for packet in packets)

for protocol, count in protocols.items():
    print(protocol, ":", count)

total_bytes = sum(
    int(packet["Packet Size"])
    for packet in packets
    if packet["Packet Size"].isdigit()
)

print("Total Traffic :", total_bytes, "bytes")


# -----------------------------
# 2. SUSPICIOUS PORT DETECTION
# -----------------------------

print("\n[2] SUSPICIOUS PORTS")
print("----------------------------------------")

suspicious_ports = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Common Metasploit port"
}

port_alerts = 0

for packet in packets:

    destination_port = packet["Destination Port"]

    if destination_port.isdigit():

        port = int(destination_port)

        if port in suspicious_ports:

            print(
                "⚠️ Port:",
                port,
                "| Service:",
                suspicious_ports[port],
                "| Source:",
                packet["Source IP"]
            )

            port_alerts += 1


if port_alerts == 0:
    print("No suspicious ports detected.")


# -----------------------------
# 3. PORT SCAN DETECTION
# -----------------------------

print("\n[3] PORT SCAN DETECTION")
print("----------------------------------------")

source_ports = defaultdict(set)

for packet in packets:

    source_ip = packet["Source IP"]
    destination_port = packet["Destination Port"]

    if source_ip and destination_port.isdigit():

        source_ports[source_ip].add(int(destination_port))


scan_alerts = 0

for source_ip, ports in source_ports.items():

    if len(ports) >= 10:

        print(
            "⚠️ Possible port scan:",
            source_ip,
            "| Unique ports:",
            len(ports)
        )

        scan_alerts += 1


if scan_alerts == 0:
    print("No possible port scan detected.")


# -----------------------------
# 4. ANOMALY DETECTION
# -----------------------------

print("\n[4] TRAFFIC ANOMALIES")
print("----------------------------------------")

packet_sizes = [
    int(packet["Packet Size"])
    for packet in packets
    if packet["Packet Size"].isdigit()
]

anomaly_alerts = 0

if packet_sizes:

    average_size = sum(packet_sizes) / len(packet_sizes)

    threshold = average_size * 5

    for packet in packets:

        if packet["Packet Size"].isdigit():

            size = int(packet["Packet Size"])

            if size > threshold:

                print(
                    "⚠️ Large packet:",
                    size,
                    "bytes | Source:",
                    packet["Source IP"]
                )

                anomaly_alerts += 1


if anomaly_alerts == 0:
    print("No unusual packet sizes detected.")


# -----------------------------
# 5. FINAL SUMMARY
# -----------------------------

total_alerts = port_alerts + scan_alerts + anomaly_alerts

print("\n========================================")
print("             FINAL SUMMARY")
print("========================================")

print("Port Alerts     :", port_alerts)
print("Port Scan Alerts:", scan_alerts)
print("Anomaly Alerts  :", anomaly_alerts)
print("Total Alerts    :", total_alerts)

print("\nSecurity analysis complete.")