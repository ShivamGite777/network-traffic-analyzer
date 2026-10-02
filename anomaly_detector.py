import csv

filename = "traffic.csv"

packet_sizes = []

with open(filename, "r") as file:

    reader = csv.DictReader(file)

    for packet in reader:

        size = packet["Packet Size"]

        if size.isdigit():
            packet_sizes.append(int(size))


print("Traffic Anomaly Detection")
print("=========================")

if not packet_sizes:

    print("No packet data found.")

else:

    # Calculate average packet size
    average_size = sum(packet_sizes) / len(packet_sizes)

    # Set anomaly threshold
    threshold = average_size * 5

    print("Average Packet Size :", round(average_size, 2), "bytes")
    print("Anomaly Threshold   :", round(threshold, 2), "bytes")

    anomalies = []

    # Check packets again
    with open(filename, "r") as file:

        reader = csv.DictReader(file)

        for packet in reader:

            size = packet["Packet Size"]

            if size.isdigit():

                size = int(size)

                if size > threshold:

                    anomalies.append(packet)

    print("\nAnomalies Found:", len(anomalies))

    if anomalies:

        for packet in anomalies:

            print("\n⚠️ Large Packet Detected")
            print("Source IP      :", packet["Source IP"])
            print("Destination IP :", packet["Destination IP"])
            print("Protocol       :", packet["Protocol"])
            print("Packet Size    :", packet["Packet Size"], "bytes")

    else:

        print("No unusual packet sizes detected.")

print("\nAnalysis complete!")