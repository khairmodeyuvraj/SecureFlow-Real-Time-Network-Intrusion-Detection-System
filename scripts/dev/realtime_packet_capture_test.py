from scapy.all import sniff, IP, TCP, UDP


# ============================================================
# WIFI INTERFACE
# ============================================================

INTERFACE = r"\Device\NPF_{695DC79C-2EAC-4C44-978A-8CC2EFD1EC2F}"


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    protocol = packet[IP].proto

    if TCP in packet:

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol_name = "TCP"

    elif UDP in packet:

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol_name = "UDP"

    else:

        src_port = "-"
        dst_port = "-"
        protocol_name = str(protocol)

    print(
        f"{protocol_name:5} "
        f"{src}:{src_port}  ->  "
        f"{dst}:{dst_port}  "
        f"Length={len(packet)}"
    )


# ============================================================
# START CAPTURE
# ============================================================

print("=" * 70)
print("AI-IDS PACKET CAPTURE TEST")
print("=" * 70)

print("Interface:")
print(INTERFACE)

print("\nCapturing 20 packets...")
print("Generate some normal network activity if needed.")
print()


sniff(
    iface=INTERFACE,
    prn=packet_callback,
    count=20,
    store=False
)


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 70)
print("Packet capture test completed successfully.")
print("=" * 70)