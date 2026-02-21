from scapy.all import *

def packet_callback(packet):
    # Redact sensitive information
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Mask IP Addresses
        masked_src = f"{ip_src.split('.')[0]}.{ip_src.split('.')[1]}.x.x"
        masked_dst = f"{ip_dst.split('.')[0]}.{ip_dst.split('.')[1]}.x.x"
        print(f"Captured Packet: [Source: {masked_src} -> Destination: {masked_dst}]")
        # Decode layer details
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                # Redact sensitive data
                if 'Authorization' in load:
                    load = load.replace(load.split('Authorization:')[1].split('\r\n')[0], '[REDACTED]')
                if 'email' in load:
                    load = load.replace(load.split('email=')[1].split('&')[0], '[REDACTED]')
                if 'password=' in load or 'token=' in load:
                    load = load.replace(load.split('password=')[1].split('&')[0], '[REDACTED]')
                print(f"Load: {load}")

# Capture 25 packets with a filter on port 80 (HTTP)
print("Starting packet capture...")
packets = sniff(filter='tcp port 80', prn=packet_callback, count=25)
print("Packet capture complete.")