import pytest
import time
from src.network.flow_builder import FlowManager, PacketInfo
from src.network.packet_capture import check_capture_capabilities, TrafficReplayStreamer


def test_flow_manager_aggregation():
    manager = FlowManager(inactivity_timeout=5.0, active_timeout=20.0)
    now = time.time()

    # Forward packet
    p1 = PacketInfo(
        timestamp=now,
        src_ip="10.0.0.1",
        src_port=12345,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
        packet_length=60,
    )
    completed = manager.add_packet(p1)
    assert completed is None

    # Reverse packet (same flow)
    p2 = PacketInfo(
        timestamp=now + 0.1,
        src_ip="10.0.0.2",
        src_port=80,
        dst_ip="10.0.0.1",
        dst_port=12345,
        protocol="TCP",
        packet_length=120,
    )
    completed = manager.add_packet(p2)
    assert completed is None

    # Verify flow properties
    flows = manager.flush_all()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.forward_packets == 1
    assert flow.backward_packets == 1
    assert flow.forward_bytes == 60
    assert flow.backward_bytes == 120
    assert len(flow.packets) == 2


def test_flow_manager_expiration():
    manager = FlowManager(inactivity_timeout=1.0, active_timeout=5.0)
    now = 1000.0

    p1 = PacketInfo(
        timestamp=now,
        src_ip="1.1.1.1",
        src_port=5000,
        dst_ip="2.2.2.2",
        dst_port=443,
        protocol="TCP",
        packet_length=100,
    )
    manager.add_packet(p1)

    # Check expiration after 2 seconds (exceeds inactivity_timeout of 1.0)
    expired = manager.get_expired_flows(current_time=now + 2.0)
    assert len(expired) == 1
    assert len(manager.flows) == 0


def test_capture_capabilities():
    caps = check_capture_capabilities()
    assert isinstance(caps, dict)
    assert "scapy_installed" in caps
    assert "pcap_driver_present" in caps
    assert "can_sniff" in caps
    assert "interfaces" in caps
    assert "message" in caps
