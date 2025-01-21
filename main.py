from core.packet_sniffer import PacketSniffer
from utils.geo_ip import get_geo_info
import argparse

def main():
    parser = argparse.ArgumentParser(description="WhatsApp IP Tracker Tool")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to sniff on")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to capture")
    args = parser.parse_args()

    sniffer = PacketSniffer(log_file="logs/packet_logs.pcap")
    sniffer.start_sniffing(iface=args.iface, count=args.count)

    # Post-processing: Analyze captured IPs and get geolocation data
    unique_ips = set([pkt[1].src for pkt in sniffer.packets])
    for ip in unique_ips:
        geo_info = get_geo_info(ip)
        if geo_info:
            print(f"[+] IP: {geo_info['ip']} - {geo_info['city']}, {geo_info['country']} "
                  f"({geo_info['latitude']}, {geo_info['longitude']})")

if __name__ == "__main__":
    main()
