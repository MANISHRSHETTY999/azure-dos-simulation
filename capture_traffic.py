import pyshark
import requests
import json

AZURE_ENDPOINT = "https://nids-atfzbjcebcfrdqa4.centralindia-01.azurewebsites.net/predict"

def send_to_azure(packet_data):
    try:
        response = requests.post(AZURE_ENDPOINT, json=packet_data)
        if response.status_code == 200:
            print("Packet sent successfully:", response.json())
        else:
            print(f"Failed to send packet: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending packet to Azure: {e}")

def capture_traffic(interface):
    print(f"Starting packet capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture.sniff_continuously(packet_count=10):
        try:
            packet_data = {
    'frame_len': getattr(packet.frame_info, 'len', "0"),  # Default to "0" if missing
    'frame_time_delta': getattr(packet.frame_info, 'time_delta', "0.0"),  # Default to "0.0"
    'frame_time_relative': getattr(packet.frame_info, 'time_relative', "0.0"),  # Default to "0.0"
    'ip_src': getattr(packet.ip, 'src', "0.0.0.0") if hasattr(packet, 'ip') else "0.0.0.0",
    'ip_dst': getattr(packet.ip, 'dst', "0.0.0.0") if hasattr(packet, 'ip') else "0.0.0.0",
    'ip_len': getattr(packet.ip, 'len', "0") if hasattr(packet, 'ip') else "0",
    'ip_ttl': getattr(packet.ip, 'ttl', "0") if hasattr(packet, 'ip') else "0",
    'tcp_srcport': getattr(packet.tcp, 'srcport', "0") if hasattr(packet, 'tcp') else "50367",
    'tcp_dstport': getattr(packet.tcp, 'dstport', "0") if hasattr(packet, 'tcp') else "3389",
    'tcp_len': getattr(packet.tcp, 'len', "0") if hasattr(packet, 'tcp') else "588",
    'tcp_flags_syn': getattr(packet.tcp, 'flags_syn', "False") if hasattr(packet, 'tcp') else "False",
    'tcp_flags_ack': getattr(packet.tcp, 'flags_ack', "False") if hasattr(packet, 'tcp') else "False",
    'tcp_flags_fin': getattr(packet.tcp, 'flags_fin', "False") if hasattr(packet, 'tcp') else "False",
    'tcp_flags_rst': getattr(packet.tcp, 'flags_rst', "False") if hasattr(packet, 'tcp') else "False",
    'tcp_flags_push': getattr(packet.tcp, 'flags_push', "False") if hasattr(packet, 'tcp') else "False",
    'tcp_flags_urg': getattr(packet.tcp, 'flags_urg', "False") if hasattr(packet, 'tcp') else "False",
}

            print("Captured packet:", json.dumps(packet_data, indent=4))
            send_to_azure(packet_data)
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    INTERFACE = "Ethernet"  # Replace with your actual interface name
    capture_traffic(INTERFACE)
