WHATSAPP_IP_RANGES = [
    "31.13.64.0/18",
    "157.240.0.0/16",
    "66.220.144.0/20"
]

WHATSAPP_PORTS = list(range(49152, 65535))  # WhatsApp typically uses these UDP ports
LOG_FILE = "logs/packet_logs.pcap"         # Path to save packet capture logs
