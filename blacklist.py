BLACKLISTED_IPS = [
    "192.168.1.10",
    "10.0.0.5"
    # Add more known malicious IPs
]

def check_blacklist(ip):
    return ip in BLACKLISTED_IPS
