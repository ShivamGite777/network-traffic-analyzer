from flask import Flask, jsonify, request

from flask_cors import CORS

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, PcapReader

import csv

import os

import threading

from datetime import datetime

from collections import Counter





app = Flask(__name__)

CORS(app)





BASE_DIR = os.path.dirname(

    os.path.dirname(

        os.path.abspath(__file__)

    )

)





CSV_FILE = os.path.join(

    BASE_DIR,

    "traffic.csv"

)

# Agent authentication token (set this in Render Environment Variables)
AGENT_TOKEN = os.getenv("AGENT_TOKEN")





INTERFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"





capture_thread = None

capture_running = False

capture_lock = threading.Lock()





 # =======================================

 # Read traffic.csv

 # =======================================



def read_packets():



    if not os.path.exists(CSV_FILE):

        return []



    with open(

        CSV_FILE,

        "r",

        newline=""

    ) as file:



        reader = csv.DictReader(file)



        return list(reader)





 # =======================================

 # Process Live Packet

 # =======================================



def process_packet(packet):



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





    return [

        timestamp,

        source_ip,

        destination_ip,

        protocol,

        source_port,

        destination_port,

        packet_size

    ]





 # =======================================

 # Live Capture

 # =======================================



def capture_packets():



    global capture_running





    try:



        print()



        print("========================================")

        print("LIVE CAPTURE STARTED")

        print("Interface:", INTERFACE)

        print("========================================")



        print()





        while True:



            with capture_lock:



                if not capture_running:

                    break





            packets = sniff(



                iface=INTERFACE,



                count=10,



                timeout=5



            )





            if not packets:

                continue





            file_exists = os.path.exists(

                CSV_FILE

            )





            with open(



                CSV_FILE,



                "a",



                newline=""



            ) as file:



                writer = csv.writer(file)





                # Create header

                if not file_exists:



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



                    row = process_packet(

                        packet

                    )



                    writer.writerow(row)





            print(

                f"Captured {len(packets)} packets"

            )





    except Exception as error:



        print(

            "Capture error:",

            error

        )





    finally:



        with capture_lock:



            capture_running = False





        print()



        print("LIVE CAPTURE STOPPED")



        print()





 # =======================================

 # Start Capture API

 # =======================================



@app.route(

    "/api/capture/start",

    methods=["POST"]

)

def start_capture():



    global capture_thread

    global capture_running





    with capture_lock:



        if capture_running:



            return jsonify({



                "status":

                    "already_running",



                "message":

                    "Capture is already running"



            })





        capture_running = True





    capture_thread = threading.Thread(



        target=capture_packets,



        daemon=True



    )





    capture_thread.start()





    return jsonify({



        "status":

            "started",



        "message":

            "Live capture started"



    })





 # =======================================

 # Stop Capture API

 # =======================================



@app.route(

    "/api/capture/stop",

    methods=["POST"]

)

def stop_capture():



    global capture_running





    with capture_lock:



        capture_running = False





    return jsonify({



        "status":

            "stopped",



        "message":

            "Live capture stopped"



    })





 # =======================================

 # Capture Status API

 # =======================================



@app.route(

    "/api/capture/status"

)

def capture_status():



    with capture_lock:



        status = capture_running





    return jsonify({



        "running":

            status,



        "interface":

            INTERFACE



    })





 # =======================================

 # Home API

 # =======================================



@app.route("/")

def home():



    return jsonify({



        "message":

            "Network Traffic Analyzer API is running"



    })
# =======================================
# Health Check API
# =======================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "Backend is healthy"
    })





 # =======================================

 # Live Traffic API

 # =======================================



@app.route(

    "/api/traffic"

)

def traffic():



    packets = read_packets()[-500:]





    return jsonify(packets)





 # =======================================

 # Live Statistics API

 # =======================================



@app.route(

    "/api/stats"

)

def stats():



    packets = read_packets()





    protocols = Counter(



        packet["Protocol"]



        for packet in packets



    )





    total_bytes = sum(



        int(packet["Packet Size"])



        for packet in packets



        if packet["Packet Size"].isdigit()



    )





    return jsonify({



        "total_packets":

            len(packets),



        "protocols":

            dict(protocols),



        "total_bytes":

            total_bytes



    })





 # =======================================

 # Live Security Alerts

 # =======================================



@app.route(

    "/api/alerts"

)

def alerts():



    packets = read_packets()





    suspicious_ports = {



        21: "FTP",



        23: "Telnet",



        445: "SMB",



        3389: "RDP",



        4444:

            "Common Metasploit port"



    }





    alerts = []





    for packet in packets:



        destination_port = packet[

            "Destination Port"

        ]





        if destination_port.isdigit():



            port = int(

                destination_port

            )





            if port in suspicious_ports:



                alerts.append({



                    "source_ip":

                        packet["Source IP"],



                    "destination_ip":

                        packet["Destination IP"],



                    "protocol":

                        packet["Protocol"],



                    "port":

                        port,



                    "service":

                        suspicious_ports[port]



                })





    return jsonify({



        "total_alerts":

            len(alerts),



        "alerts":

            alerts



    })





 # =======================================

 # PCAP FILE ANALYSIS

 # =======================================



@app.route(

    "/api/pcap/upload",

    methods=["POST"]

)

def upload_pcap():





    # ---------------------------------------

    # Check uploaded file

    # ---------------------------------------



    if "file" not in request.files:



        return jsonify({



            "status":

                "error",



            "message":

                "No PCAP file uploaded"



        }), 400





    uploaded_file = request.files["file"]





    # ---------------------------------------

    # Check filename

    # ---------------------------------------



    if uploaded_file.filename == "":



        return jsonify({



            "status":

                "error",



            "message":

                "No file selected"



        }), 400





    filename = uploaded_file.filename.lower()





    # ---------------------------------------

    # Allow PCAP and PCAPNG

    # ---------------------------------------



    if not (



        filename.endswith(".pcap")



        or



        filename.endswith(".pcapng")



    ):



        return jsonify({



            "status":

                "error",



            "message":

                "Only .pcap and .pcapng files are supported"



        }), 400





    # ---------------------------------------

    # Temporary upload file

    # ---------------------------------------



    temp_file = os.path.join(



        BASE_DIR,



        "uploaded_capture.pcap"



    )





    try:





        # -----------------------------------

        # Save uploaded file

        # -----------------------------------



        uploaded_file.save(

            temp_file

        )





        total_packets = 0



        total_bytes = 0





        protocols = Counter()





        # -----------------------------------

        # Suspicious ports

        # -----------------------------------



        suspicious_ports = {



            21: "FTP",



            23: "Telnet",



            445: "SMB",



            3389: "RDP",



            4444:

                "Common Metasploit port"



        }





        alerts_found = []

        # -----------------------------------

        # Actual PCAP packet data

        # -----------------------------------



        packet_data = []





        # -----------------------------------

        # Read PCAP / PCAPNG

        # -----------------------------------



        with PcapReader(

            temp_file

        ) as packets:



            for packet in packets:



                total_packets += 1



                packet_size = len(packet)



                total_bytes += packet_size





                # ---------------------------

                # Default values

                # ---------------------------



                timestamp = ""



                source_ip = ""



                destination_ip = ""



                protocol = "Other"



                source_port = ""



                destination_port = ""





                # ---------------------------

                # Timestamp

                # ---------------------------



                if packet.time:



                    timestamp = datetime.fromtimestamp(

                        float(packet.time)

                    ).strftime(

                        "%Y-%m-%d %H:%M:%S"

                    )





                # ---------------------------

                # IPv4

                # ---------------------------



                if packet.haslayer(IP):



                    source_ip = packet[IP].src



                    destination_ip = packet[IP].dst





                # ---------------------------

                # IPv6

                # ---------------------------



                elif packet.haslayer(IPv6):



                    source_ip = packet[IPv6].src



                    destination_ip = packet[IPv6].dst





                # ---------------------------

                # TCP

                # ---------------------------



                if packet.haslayer(TCP):



                    protocol = "TCP"



                    source_port = packet[TCP].sport



                    destination_port = packet[TCP].dport





                    if destination_port in suspicious_ports:



                        alerts_found.append({



                            "source_ip":

                                source_ip,



                            "destination_ip":

                                destination_ip,



                            "protocol":

                                "TCP",



                            "port":

                                destination_port,



                            "service":

                                suspicious_ports[

                                    destination_port

                                ]



                        })





                # ---------------------------

                # UDP

                # ---------------------------



                elif packet.haslayer(UDP):



                    protocol = "UDP"



                    source_port = packet[UDP].sport



                    destination_port = packet[UDP].dport





                    if destination_port in suspicious_ports:



                        alerts_found.append({



                            "source_ip":

                                source_ip,



                            "destination_ip":

                                destination_ip,



                            "protocol":

                                "UDP",



                            "port":

                                destination_port,



                            "service":

                                suspicious_ports[

                                    destination_port

                                ]



                        })





                # ---------------------------

                # ICMP

                # ---------------------------



                elif packet.haslayer(ICMP):



                    protocol = "ICMP"





                # ---------------------------

                # Protocol counter

                # ---------------------------



                protocols[

                    protocol

                ] += 1





                # ---------------------------

                # Store packet

                # ---------------------------



                packet_data.append({



                    "Timestamp":

                        timestamp,



                    "Source IP":

                        source_ip,



                    "Destination IP":

                        destination_ip,



                    "Protocol":

                        protocol,



                    "Source Port":

                        source_port,



                    "Destination Port":

                        destination_port,



                    "Packet Size":

                        packet_size



                })





        # ---------------------------------------

        # Return PCAP analysis

        # ---------------------------------------



        return jsonify({



            "status":

                "success",



            "filename":

                uploaded_file.filename,



            "total_packets":

                total_packets,



            "total_bytes":

                total_bytes,



            "protocols":

                dict(protocols),



            "total_alerts":

                len(alerts_found),



            "alerts":

                alerts_found,



            "packets":

                packet_data



        })





    except Exception as error:



        return jsonify({



            "status":

                "error",



            "message":

                str(error)



        }), 500





    finally:



        # -----------------------------------

        # Delete temporary uploaded file

        # -----------------------------------



        if os.path.exists(

            temp_file

        ):



            os.remove(

                temp_file

            )

 # ============================================================

 # AGENT API

 # ============================================================



agent_packets = []

agent_active = False





@app.route("/api/agent/status", methods=["GET"])

def agent_status():



    return jsonify({

        "status": "success",

        "agent_active": agent_active,

        "packet_count": len(agent_packets)

    })





@app.route("/api/agent/packets", methods=["POST"])

def receive_agent_packets():



    global agent_packets

    global agent_active



    request_token = request.headers.get("X-Agent-Token")



    if not AGENT_TOKEN or request_token != AGENT_TOKEN:
        return jsonify({
            "status": "error",
            "message": "Unauthorized agent"
        }), 401



    data = request.get_json(silent=True)



    if not data:

        return jsonify({

            "status": "error",

            "message": "No packet data received"

        }), 400



    packets = data.get("packets", [])



    if not isinstance(packets, list):

        return jsonify({

            "status": "error",

            "message": "Invalid packet format"

        }), 400



    # Keep only the latest 500 packets

    agent_packets.extend(packets)

    agent_packets = agent_packets[-500:]



    agent_active = True



    return jsonify({

        "status": "success",

        "received_packets": len(packets),

        "total_packets": len(agent_packets)

    })

@app.route("/api/agent/traffic", methods=["GET"])

def get_agent_traffic():



    return jsonify({

        "status": "success",

        "agent_active": agent_active,

        "total_packets": len(agent_packets),

        "packets": agent_packets

    })



 # =======================================

 # Run Flask

 # =======================================



if __name__ == "__main__":



    app.run(



        host="0.0.0.0",



        port=5000,



        debug=True,



        use_reloader=False



    )