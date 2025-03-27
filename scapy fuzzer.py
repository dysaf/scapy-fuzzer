from scapy.all import *
import random
import sys

# Disable Scapy's verbose mode
conf.verb = 0

# Target IP & Port (modify as needed)
TARGET_IP = "192.168.1.100"
TARGET_PORT = 80
PROTOCOL = "TCP"  # Options: TCP, UDP, ICMP, or "CUSTOM"

# Fuzzing parameters
NUM_PACKETS = 100  # Number of fuzzed packets to send
PAYLOAD_LENGTH = 100  # Random payload length
LOG_FILE = "fuzzing_log.txt"  # Log responses

def generate_random_payload(length):
    """Generate random payload for fuzzing."""
    return bytes([random.randint(0, 255) for _ in range(length)])

def fuzz_tcp(target_ip, target_port):
    """Send malformed TCP packets."""
    for _ in range(NUM_PACKETS):
        # Randomize TCP fields
        sport = random.randint(1024, 65535)
        dport = target_port
        flags = random.choice(["S", "A", "R", "F", "P", "U"])  # SYN, ACK, RST, etc.
        payload = generate_random_payload(PAYLOAD_LENGTH)
        
        # Craft packet
        packet = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags=flags)/payload
        
        # Send and log response
        response = sr1(packet, timeout=1)
        log_response(packet, response)

def fuzz_udp(target_ip, target_port):
    """Send malformed UDP packets."""
    for _ in range(NUM_PACKETS):
        sport = random.randint(1024, 65535)
        payload = generate_random_payload(PAYLOAD_LENGTH)
        
        packet = IP(dst=target_ip)/UDP(sport=sport, dport=target_port)/payload
        response = sr1(packet, timeout=1)
        log_response(packet, response)

def fuzz_icmp(target_ip):
    """Send malformed ICMP packets."""
    for _ in range(NUM_PACKETS):
        payload = generate_random_payload(PAYLOAD_LENGTH)
        
        packet = IP(dst=target_ip)/ICMP()/payload
        response = sr1(packet, timeout=1)
        log_response(packet, response)

def fuzz_custom_protocol(target_ip, target_port):
    """Example: Fuzz a custom protocol (modify as needed)."""
    for _ in range(NUM_PACKETS):
        payload = generate_random_payload(PAYLOAD_LENGTH)
        
        # Example: Raw IP packet with random protocol number
        packet = IP(dst=target_ip, proto=random.randint(0, 255))/payload
        response = sr1(packet, timeout=1)
        log_response(packet, response)

def log_response(packet, response):
    """Log sent packets and responses to a file."""
    with open(LOG_FILE, "a") as f:
        f.write(f"Sent Packet:\n{packet.summary()}\n")
        if response:
            f.write(f"Received Response:\n{response.summary()}\n")
        else:
            f.write("No response received.\n")
        f.write("-" * 50 + "\n")

if __name__ == "__main__":
    print(f"[+] Starting protocol fuzzing against {TARGET_IP}...")
    
    if PROTOCOL == "TCP":
        fuzz_tcp(TARGET_IP, TARGET_PORT)
    elif PROTOCOL == "UDP":
        fuzz_udp(TARGET_IP, TARGET_PORT)
    elif PROTOCOL == "ICMP":
        fuzz_icmp(TARGET_IP)
    elif PROTOCOL == "CUSTOM":
        fuzz_custom_protocol(TARGET_IP, TARGET_PORT)
    else:
        print("[-] Invalid protocol. Choose TCP, UDP, ICMP, or CUSTOM.")
        sys.exit(1)
    
    print(f"[+] Fuzzing completed. Check {LOG_FILE} for results.")
