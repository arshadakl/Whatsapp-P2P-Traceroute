from scapy.all import conf, get_if_list
from core.packet_sniffer import PacketSniffer
from utils.geo_ip import get_geo_info


def list_interfaces():
    """Lists all available network interfaces."""
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    return interfaces


def choose_interface(interfaces):
    """Prompts the user to select a network interface."""
    while True:
        try:
            choice = int(input("\nEnter the number of the interface you want to use: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print(f"Invalid choice. Please select a number between 0 and {len(interfaces) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


def main():
    print("[*] Network Interface Selection")
    interfaces = list_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"\n[+] You selected: {selected_interface}\n")

    # Start packet sniffing
    sniffer = PacketSniffer(log_file="logs/packet_logs.pcap")
    sniffer.start_sniffing(iface=selected_interface, count=100)

    # Post-processing: Analyze captured IPs and get geolocation data
    unique_ips = set([pkt[1].src for pkt in sniffer.packets])
    for ip in unique_ips:
        geo_info = get_geo_info(ip)
        if geo_info:
            print(f"[+] IP: {geo_info['ip']} - {geo_info['city']}, {geo_info['country']} "
                  f"({geo_info['latitude']}, {geo_info['longitude']})")


if __name__ == "__main__":
    main()
