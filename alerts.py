import csv

filename = "traffic.csv"
alert_file = "alerts.csv"

suspicious_ports = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Common Metasploit port"
}

alerts = []

with open(filename, "r") as file:

    reader = csv.DictReader(file)

    for packet in reader:

        source_port = packet["Source Port"]
        destination_port = packet["Destination Port"]

        # Check destination port
        if destination_port.isdigit():

            port = int(destination_port)

            if port in suspicious_ports:

                alerts.append([
                    packet["Timestamp"],
                    packet["Source IP"],
                    packet["Destination IP"],
                    packet["Protocol"],
                    port,
                    suspicious_ports[port],
                    "Suspicious destination port"
                ])

        # Check source port
        if source_port.isdigit():

            port = int(source_port)

            if port in suspicious_ports:

                alerts.append([
                    packet["Timestamp"],
                    packet["Source IP"],
                    packet["Destination IP"],
                    packet["Protocol"],
                    port,
                    suspicious_ports[port],
                    "Suspicious source port"
                ])


# Save alerts
with open(alert_file, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Port",
        "Service",
        "Alert"
    ])

    writer.writerows(alerts)


print("Network Traffic Security Alerts")
print("================================")

if len(alerts) == 0:

    print("No suspicious ports detected.")

else:

    for alert in alerts:

        print("\n⚠️ ALERT")
        print("Source IP      :", alert[1])
        print("Destination IP :", alert[2])
        print("Protocol       :", alert[3])
        print("Port           :", alert[4])
        print("Service        :", alert[5])
        print("Reason         :", alert[6])

    print("\nTotal Alerts:", len(alerts))

print("\nAlert file created:", alert_file)