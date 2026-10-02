import time
import requests

from scapy.all import (
    sniff,
    conf,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP
)

# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_URL = "http://127.0.0.1:5000"
PACKET_API = f"{BACKEND_URL}/api/agent/packets"

INTERFACE = conf.iface

BATCH_SIZE = 10
CAPTURE_INTERVAL = 3


# ============================================================
# PACKET STORAGE
# ============================================================

packet_batch = []


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    try:

        source_ip = "Unknown"
        destination_ip = "Unknown"
        protocol = "OTHER"

        source_port = "-"
        destination_port = "-"

        # -----------------------------
        # IPv4
        # -----------------------------

        if IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            if TCP in packet:

                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

            elif UDP in packet:

                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            elif ICMP in packet:

                protocol = "ICMP"

            else:

                protocol = "IP"

        # -----------------------------
        # IPv6
        # -----------------------------

        elif IPv6 in packet:

            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

            if TCP in packet:

                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

            elif UDP in packet:

                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            else:

                protocol = "IPv6"

        else:

            return

        packet_data = {

            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "protocol": protocol,

            "source_port": source_port,

            "destination_port": destination_port,

            "packet_size": len(packet)

        }

        packet_batch.append(packet_data)

        print(
            f"{source_ip} -> "
            f"{destination_ip} | "
            f"{protocol} | "
            f"{source_port} -> "
            f"{destination_port} | "
            f"{len(packet)} bytes"
        )

    except Exception as error:

        print(
            "Packet processing error:",
            error
        )


# ============================================================
# SEND PACKETS TO BACKEND
# ============================================================

def send_packets():

    global packet_batch

    if not packet_batch:

        return

    packets_to_send = packet_batch.copy()

    packet_batch.clear()

    try:

        response = requests.post(

            PACKET_API,

            json={
                "packets": packets_to_send
            },

            timeout=5

        )

        if response.status_code == 200:

            data = response.json()

            print(
                f"[SERVER] Sent "
                f"{len(packets_to_send)} packets"
            )

            print(
                f"[SERVER] Total packets: "
                f"{data.get('total_packets')}"
            )

        else:

            print(
                "[SERVER] Error:",
                response.status_code
            )

    except requests.exceptions.RequestException as error:

        print(
            "[SERVER] Connection error:",
            error
        )

        # Put packets back if server unavailable
        packet_batch[0:0] = packets_to_send


# ============================================================
# MAIN
# ============================================================

print()
print("=" * 55)
print("          NETWORK SECURITY AGENT")
print("=" * 55)
print()

print("Detected Interface:")
print(INTERFACE)

print()
print("Backend:")
print(BACKEND_URL)

print()
print("Agent Status: STARTING")
print()
print("Continuous packet monitoring enabled.")
print("Open websites / applications to generate traffic.")
print()
print("Press CTRL+C to stop the agent.")
print()

last_send = time.time()


try:

    while True:

        # Capture packets continuously
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
            timeout=CAPTURE_INTERVAL
        )

        # Send collected packets every few seconds
        if (
            len(packet_batch) >= BATCH_SIZE
            or
            time.time() - last_send >= CAPTURE_INTERVAL
        ):

            send_packets()

            last_send = time.time()


except KeyboardInterrupt:

    print()
    print("=" * 55)
    print("          AGENT STOPPED")
    print("=" * 55)

    # Send remaining packets
    send_packets()

    print()
    print("Agent monitoring stopped.")