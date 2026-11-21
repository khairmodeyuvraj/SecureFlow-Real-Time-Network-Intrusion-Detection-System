from scapy.all import sniff, IP, TCP, UDP
from flow_manager import FlowManager, PacketInfo
import time


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = r"\Device\NPF_{695DC79C-2EAC-4C44-978A-8CC2EFD1EC2F}"

INACTIVITY_TIMEOUT = 10
ACTIVE_TIMEOUT = 60


# ============================================================
# FLOW MANAGER
# ============================================================

flow_manager = FlowManager(
    inactivity_timeout=INACTIVITY_TIMEOUT,
    active_timeout=ACTIVE_TIMEOUT
)


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    # --------------------------------------------------------
    # Only process IPv4 packets
    # --------------------------------------------------------

    if IP not in packet:
        return

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        tcp = packet[TCP]

        protocol = "TCP"

        src_port = tcp.sport
        dst_port = tcp.dport

        transport_header_length = (
            tcp.dataofs * 4
            if tcp.dataofs is not None
            else 20
        )

        payload_length = len(tcp.payload)

        tcp_flags = str(tcp.flags)

        tcp_window = tcp.window

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif UDP in packet:

        udp = packet[UDP]

        protocol = "UDP"

        src_port = udp.sport
        dst_port = udp.dport

        transport_header_length = 8

        payload_length = len(udp.payload)

        tcp_flags = ""

        tcp_window = 0

    else:
        return

    # --------------------------------------------------------
    # IP HEADER
    # --------------------------------------------------------

    ip_header_length = (
        ip.ihl * 4
        if ip.ihl is not None
        else 20
    )

    # --------------------------------------------------------
    # PACKET LENGTH
    # --------------------------------------------------------

    packet_length = len(ip)

    # --------------------------------------------------------
    # CREATE PacketInfo
    # --------------------------------------------------------

    packet_info = PacketInfo(

        timestamp=time.time(),

        src_ip=src_ip,
        src_port=src_port,

        dst_ip=dst_ip,
        dst_port=dst_port,

        protocol=protocol,

        packet_length=packet_length,

        ip_header_length=ip_header_length,

        transport_header_length=transport_header_length,

        payload_length=payload_length,

        tcp_flags=tcp_flags,

        tcp_window=tcp_window
    )

    # --------------------------------------------------------
    # ADD TO FLOW MANAGER
    # --------------------------------------------------------

    flow_manager.add_packet(packet_info)

    # --------------------------------------------------------
    # DISPLAY
    # --------------------------------------------------------

    print(
        f"{protocol:5} "
        f"{src_ip}:{src_port} → "
        f"{dst_ip}:{dst_port} "
        f"| Length={packet_length:5} "
        f"| Active Flows={flow_manager.active_flow_count()}"
    )

    # --------------------------------------------------------
    # CHECK EXPIRED FLOWS
    # --------------------------------------------------------

    expired_flows = flow_manager.get_expired_flows()

    for flow in expired_flows:

        print()
        print("-" * 70)
        print("FLOW EXPIRED")
        print("-" * 70)

        print(f"Protocol          : {flow.key[0]}")

        print(
            f"Forward           : "
            f"{flow.forward_src_ip}:{flow.forward_src_port} → "
            f"{flow.forward_dst_ip}:{flow.forward_dst_port}"
        )

        print(
            f"Forward packets   : "
            f"{flow.forward_packets}"
        )

        print(
            f"Backward packets  : "
            f"{flow.backward_packets}"
        )

        print(
            f"Forward bytes     : "
            f"{flow.forward_bytes}"
        )

        print(
            f"Backward bytes    : "
            f"{flow.backward_bytes}"
        )

        print(
            f"Total packets     : "
            f"{len(flow.packets)}"
        )

        print("-" * 70)
        print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("AI-IDS LIVE FLOW CAPTURE")
    print("=" * 70)

    print()
    print("Interface:")
    print(INTERFACE)

    print()
    print("Inactivity timeout :", INACTIVITY_TIMEOUT, "seconds")
    print("Active timeout     :", ACTIVE_TIMEOUT, "seconds")

    print()
    print("Starting live packet capture...")
    print("Generate some network activity.")
    print("Press CTRL+C to stop.")
    print()

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print("Stopping capture...")
        print("=" * 70)

        remaining_flows = flow_manager.flush_all()

        print()
        print(
            f"Remaining active flows: "
            f"{len(remaining_flows)}"
        )

        for flow in remaining_flows:

            print()
            print(
                f"{flow.key[0]} "
                f"{flow.forward_src_ip}:{flow.forward_src_port} → "
                f"{flow.forward_dst_ip}:{flow.forward_dst_port}"
            )

            print(
                f"Packets: {len(flow.packets)} | "
                f"Fwd: {flow.forward_packets} | "
                f"Bwd: {flow.backward_packets}"
            )

        print()
        print("Capture stopped.")