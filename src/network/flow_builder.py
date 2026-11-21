from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional
import time

# FlowKey: (protocol, IP1, port1, IP2, port2)
FlowKey = Tuple[str, str, int, str, int]


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_length: int
    ip_header_length: int = 20
    transport_header_length: int = 20
    payload_length: int = 0
    tcp_flags: str = ""
    tcp_window: int = 0


@dataclass
class Flow:
    key: FlowKey
    first_timestamp: float
    last_timestamp: float
    forward_src_ip: str
    forward_src_port: int
    forward_dst_ip: str
    forward_dst_port: int
    packets: List[PacketInfo] = field(default_factory=list)
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0


class FlowManager:
    """
    Manages active bidirectional network flows from streamed or captured packets.
    """

    def __init__(
        self,
        inactivity_timeout: float = 15.0,
        active_timeout: float = 120.0,
    ):
        self.inactivity_timeout = inactivity_timeout
        self.active_timeout = active_timeout
        self.flows: Dict[FlowKey, Flow] = {}

    def _create_flow_key(
        self,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> Tuple[FlowKey, bool]:
        """
        Create a canonical flow key where the forward direction is determined
        by the first packet seen.
        """
        forward_key = (protocol, src_ip, src_port, dst_ip, dst_port)
        reverse_key = (protocol, dst_ip, dst_port, src_ip, src_port)

        if forward_key in self.flows:
            return forward_key, True
        if reverse_key in self.flows:
            return reverse_key, False

        return forward_key, True

    def add_packet(self, packet: PacketInfo) -> Optional[Flow]:
        """
        Add a packet to its flow. If a flow exceeds timeouts, return the completed flow.
        """
        completed_flow: Optional[Flow] = None

        key, is_forward = self._create_flow_key(
            packet.protocol,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
        )

        flow = self.flows.get(key)

        if flow is not None:
            # Check timeout before adding
            idle_time = packet.timestamp - flow.last_timestamp
            total_duration = packet.timestamp - flow.first_timestamp

            if idle_time > self.inactivity_timeout or total_duration > self.active_timeout:
                completed_flow = self.flows.pop(key)
                # Start new flow
                flow = Flow(
                    key=key,
                    first_timestamp=packet.timestamp,
                    last_timestamp=packet.timestamp,
                    forward_src_ip=packet.src_ip,
                    forward_src_port=packet.src_port,
                    forward_dst_ip=packet.dst_ip,
                    forward_dst_port=packet.dst_port,
                )
                self.flows[key] = flow
        else:
            flow = Flow(
                key=key,
                first_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,
                forward_src_ip=packet.src_ip,
                forward_src_port=packet.src_port,
                forward_dst_ip=packet.dst_ip,
                forward_dst_port=packet.dst_port,
            )
            self.flows[key] = flow

        # Append packet to flow
        flow.packets.append(packet)
        flow.last_timestamp = max(flow.last_timestamp, packet.timestamp)

        if is_forward:
            flow.forward_packets += 1
            flow.forward_bytes += packet.packet_length
        else:
            flow.backward_packets += 1
            flow.backward_bytes += packet.packet_length

        return completed_flow

    def get_expired_flows(self, current_time: Optional[float] = None) -> List[Flow]:
        """Retrieve and remove flows that have expired."""
        now = current_time or time.time()
        expired: List[Flow] = []
        keys_to_remove: List[FlowKey] = []

        for key, flow in self.flows.items():
            idle_time = now - flow.last_timestamp
            total_duration = now - flow.first_timestamp

            if idle_time > self.inactivity_timeout or total_duration > self.active_timeout:
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        return expired

    def flush_all(self) -> List[Flow]:
        """Flush and return all currently active flows."""
        all_flows = list(self.flows.values())
        self.flows.clear()
        return all_flows
