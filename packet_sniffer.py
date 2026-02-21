import dpkt
import pcap
import socket
import re

def mask_ip(ip):
    return f"192.168.1.{ip[3]}"

def redact_data(data):
    # Redact Authorization headers
    data = re.sub(r'Authorization:\s+.*', 'Authorization: [REDACTED]', data, flags=re.IGNORECASE)
    # Redact cookies
    data = re.sub(r'Cookie:\s+.*', 'Cookie: [REDACTED]', data, flags=re.IGNORECASE)
    # Redact session tokens
    data = re.sub(r'session_token=\w+', 'session_token=[REDACTED_TOKEN]', data)
    # Redact emails
    data = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_EMAIL]', data)
    # Redact password/token in query strings
    data = re.sub(r'[\?&](password|token)=\w+', r'\1=[REDACTED]', data)
    return data

def packet_callback(ts, pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        src_ip = mask_ip(socket.inet_ntoa(ip.src))
        dst_ip = mask_ip(socket.inet_ntoa(ip.dst))
        
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            payload = tcp.data
            
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            payload = udp.data
            
        else:
            return  # Not TCP/UDP

        decoded_payload = redact_data(payload.decode('utf-8', errors='ignore'))
        print(f"Time: {ts}, Src: {src_ip}, Dst: {dst_ip}, Payload: {decoded_payload}")

def main():
    pcap_handler = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=100)
    pcap_handler.setfilter('tcp port 80 or udp port 53')
    
    packet_count = 0
    for ts, pkt in pcap_handler:
        packet_callback(ts, pkt)
        packet_count += 1
        if packet_count >= 25:
            break

if __name__ == '__main__':
    main()