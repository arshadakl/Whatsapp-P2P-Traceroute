from scapy.all import sniff, IP, UDP, wrpcap
from core.ip_filter import is_whatsapp_ip

class PacketSniffer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.packets = []

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check if packet matches WhatsApp IPs or ports
            if is_whatsapp_ip(src_ip) or is_whatsapp_ip(dst_ip):
                print(f"[+] Captured WhatsApp Packet: {src_ip} -> {dst_ip}")
                self.packets.append(packet)

    def start_sniffing(self, iface="eth0", count=100):
        print("[*] Starting packet sniffing...")
        sniff(
            iface=iface,
            filter="udp",
            prn=self.process_packet,
            count=count,
            store=0
        )
        self.save_packets()

    def save_packets(self):
        print(f"[*] Saving captured packets to {self.log_file}")
        wrpcap(self.log_file, self.packets)
