import pyshark
import requests
import json

# Load configuration from config.json
try:
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    raise FileNotFoundError("config.json file not found. Ensure it exists in the script's directory.")

# Fetch the Azure endpoint
AZURE_ENDPOINT = config.get("AZURE_ENDPOINT")
if not AZURE_ENDPOINT:
    raise ValueError("AZURE_ENDPOINT not found in config.json")

# Function to send packet data to the Azure endpoint
def send_to_azure(packet_data):
    try:
        response = requests.post(AZURE_ENDPOINT, json=packet_data, timeout=30)  # Added timeout for better handling
        response.raise_for_status()
        print("Packet sent successfully:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error sending packet to Azure: {e}")

# Function to capture packets and process them
def capture_traffic(interface):
    print(f"Starting packet capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture.sniff_continuously(packet_count=10):
        try:
            # Extract packet data with default values for robustness
            packet_data = {
                'frame_len': getattr(packet.frame_info, 'len', "0"),  
                'frame_time_delta': getattr(packet.frame_info, 'time_delta', "0.0"),
                'frame_time_relative': getattr(packet.frame_info, 'time_relative', "0.0"),
                'ip_src': getattr(packet.ip, 'src', "0.0.0.0") if hasattr(packet, 'ip') else "0.0.0.0",
                'ip_dst': getattr(packet.ip, 'dst', "0.0.0.0") if hasattr(packet, 'ip') else "0.0.0.0",
                'ip_len': getattr(packet.ip, 'len', "0") if hasattr(packet, 'ip') else "0",
                'ip_ttl': getattr(packet.ip, 'ttl', "0") if hasattr(packet, 'ip') else "0",
                'tcp_srcport': getattr(packet.tcp, 'srcport', "50367") if hasattr(packet, 'tcp') else "50367",
                'tcp_dstport': getattr(packet.tcp, 'dstport', "3389") if hasattr(packet, 'tcp') else "3389",
                'tcp_len': getattr(packet.tcp, 'len', "588") if hasattr(packet, 'tcp') else "588",
                'tcp_flags_syn': getattr(packet.tcp, 'flags_syn', "False") if hasattr(packet, 'tcp') else "False",
                'tcp_flags_ack': getattr(packet.tcp, 'flags_ack', "False") if hasattr(packet, 'tcp') else "False",
                'tcp_flags_fin': getattr(packet.tcp, 'flags_fin', "False") if hasattr(packet, 'tcp') else "False",
                'tcp_flags_rst': getattr(packet.tcp, 'flags_rst', "False") if hasattr(packet, 'tcp') else "False",
                'tcp_flags_push': getattr(packet.tcp, 'flags_push', "False") if hasattr(packet, 'tcp') else "False",
                'tcp_flags_urg': getattr(packet.tcp, 'flags_urg', "False") if hasattr(packet, 'tcp') else "False",
            }

            print("Captured packet:", json.dumps(packet_data, indent=4))
            send_to_azure(packet_data)  # Send the packet data to the Azure endpoint
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    INTERFACE = "Ethernet"  # Replace with your actual interface name
    capture_traffic(INTERFACE)
