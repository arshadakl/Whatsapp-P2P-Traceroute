import ipaddress
from config import WHATSAPP_IP_RANGES

def is_whatsapp_ip(ip):
    for ip_range in WHATSAPP_IP_RANGES:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
            return True
    return False
