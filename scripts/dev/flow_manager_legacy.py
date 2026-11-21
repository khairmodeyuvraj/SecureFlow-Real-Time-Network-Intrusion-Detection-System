from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
import time


# ============================================================
# FLOW KEY
# ============================================================

FlowKey = Tuple[
    str,   # protocol
    str,   # IP 1
    int,   # port 1
    str,   # IP 2
    int    # port 2
]


# ============================================================
# PACKET INFORMATION
# ============================================================

@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    packet_length: int

    ip_header_length: int = 0
    transport_header_length: int = 0
    payload_length: int = 0

    tcp_flags: str = ""
    tcp_window: int = 0


# ============================================================
# FLOW
# ============================================================

@dataclass
class Flow:
    key: FlowKey

    first_timestamp: float
    last_timestamp: float

    forward_src_ip: str
    forward_src_port: int
    forward_dst_ip: str
    forward_dst_port: int

    packets: list = field(default_factory=list)

    forward_packets: int = 0
    backward_packets: int = 0

    forward_bytes: int = 0
    backward_bytes: int = 0


# ============================================================
# FLOW MANAGER
# ============================================================

class FlowManager:

    def __init__(
        self,
        inactivity_timeout: float = 60.0,
        active_timeout: float = 120.0
    ):
        """
        inactivity_timeout:
            Close a flow if no packet is received for this many seconds.

        active_timeout:
            Maximum lifetime of a flow.
        """

        self.inactivity_timeout = inactivity_timeout
        self.active_timeout = active_timeout

        self.flows: Dict[FlowKey, Flow] = {}

    # --------------------------------------------------------
    # CREATE CANONICAL FLOW KEY
    # --------------------------------------------------------

    def _create_flow_key(
        self,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int
    ) -> FlowKey:

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        if endpoint1 <= endpoint2:
            return (
                protocol,
                src_ip,
                src_port,
                dst_ip,
                dst_port
            )

        return (
            protocol,
            dst_ip,
            dst_port,
            src_ip,
            src_port
        )

    # --------------------------------------------------------
    # ADD PACKET
    # --------------------------------------------------------

    def add_packet(self, packet: PacketInfo) -> Optional[Flow]:

        key = self._create_flow_key(
            packet.protocol,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port
        )

        # ----------------------------------------------------
        # CREATE NEW FLOW
        # ----------------------------------------------------

        if key not in self.flows:

            flow = Flow(
                key=key,

                first_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,

                forward_src_ip=packet.src_ip,
                forward_src_port=packet.src_port,
                forward_dst_ip=packet.dst_ip,
                forward_dst_port=packet.dst_port
            )

            self.flows[key] = flow

        else:
            flow = self.flows[key]

        # ----------------------------------------------------
        # DETERMINE DIRECTION
        # ----------------------------------------------------

        is_forward = (
            packet.src_ip == flow.forward_src_ip
            and packet.src_port == flow.forward_src_port
            and packet.dst_ip == flow.forward_dst_ip
            and packet.dst_port == flow.forward_dst_port
        )

        # ----------------------------------------------------
        # UPDATE FLOW
        # ----------------------------------------------------

        flow.packets.append(packet)

        flow.last_timestamp = packet.timestamp

        if is_forward:

            flow.forward_packets += 1
            flow.forward_bytes += packet.packet_length

        else:

            flow.backward_packets += 1
            flow.backward_bytes += packet.packet_length

        return flow

    # --------------------------------------------------------
    # CHECK EXPIRED FLOWS
    # --------------------------------------------------------

    def get_expired_flows(
        self,
        current_time: Optional[float] = None
    ) -> list:

        if current_time is None:
            current_time = time.time()

        expired = []

        for key, flow in list(self.flows.items()):

            inactivity = (
                current_time - flow.last_timestamp
            )

            lifetime = (
                current_time - flow.first_timestamp
            )

            if (
                inactivity >= self.inactivity_timeout
                or lifetime >= self.active_timeout
            ):

                expired.append(flow)

                del self.flows[key]

        return expired

    # --------------------------------------------------------
    # FORCE FLUSH
    # --------------------------------------------------------

    def flush_all(self) -> list:

        flows = list(self.flows.values())

        self.flows.clear()

        return flows

    # --------------------------------------------------------
    # NUMBER OF ACTIVE FLOWS
    # --------------------------------------------------------

    def active_flow_count(self) -> int:

        return len(self.flows)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    manager = FlowManager(
        inactivity_timeout=10,
        active_timeout=60
    )

    now = time.time()

    # Forward packet
    packet1 = PacketInfo(
        timestamp=now,
        src_ip="172.20.10.6",
        src_port=50000,
        dst_ip="20.52.64.204",
        dst_port=443,
        protocol="TCP",
        packet_length=1200
    )

    # Reverse packet
    packet2 = PacketInfo(
        timestamp=now + 0.1,
        src_ip="20.52.64.204",
        src_port=443,
        dst_ip="172.20.10.6",
        dst_port=50000,
        protocol="TCP",
        packet_length=800
    )

    manager.add_packet(packet1)
    manager.add_packet(packet2)

    print("=" * 70)
    print("FLOW MANAGER TEST")
    print("=" * 70)

    print(f"Active flows: {manager.active_flow_count()}")

    flow = list(manager.flows.values())[0]

    print()
    print("Flow information:")
    print(f"Protocol           : {flow.key[0]}")
    print(f"Forward packets    : {flow.forward_packets}")
    print(f"Backward packets   : {flow.backward_packets}")
    print(f"Forward bytes     : {flow.forward_bytes}")
    print(f"Backward bytes    : {flow.backward_bytes}")
    print(f"Total packets     : {len(flow.packets)}")

    print("=" * 70)
    print("Flow Manager test completed successfully.")
    print("=" * 70)