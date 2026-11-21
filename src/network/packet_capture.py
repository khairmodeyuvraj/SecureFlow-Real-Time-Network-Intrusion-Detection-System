from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import os
import threading
import time
import re
import numpy as np
import pandas as pd
import psutil

try:
    import scapy.config
    scapy.config.conf.interactive = False
except Exception:
    pass

from src.utils.logger import get_logger
from src.network.flow_builder import FlowManager, Flow, PacketInfo

logger = get_logger("PacketCapture")


_cached_interfaces: Optional[List[Dict[str, Any]]] = None


def get_available_interfaces(timeout: float = 1.0, refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Dynamically detect all physical and virtual network adapters on the host.
    Uses psutil for instantaneous interface enumeration and status without invoking
    Scapy device discovery or triggering Windows UAC / packet capture permission prompts.
    """
    global _cached_interfaces
    if _cached_interfaces is not None and not refresh:
        return _cached_interfaces

    interfaces: List[Dict[str, Any]] = []

    # 1. Enumerate adapters and IP/MAC stats via psutil (user-space, zero elevation needed)
    net_addrs: Dict[str, Any] = {}
    net_stats: Dict[str, Any] = {}
    try:
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
    except Exception as e:
        logger.debug(f"psutil query error: {e}")

    seen_names = set()

    for name, addrs in net_addrs.items():
        # Filter internal lightweight filter driver sub-instances
        if any(filter_tag in name for filter_tag in [
            "-WFP Native", "-Npcap Packet Driver", "-QoS Packet",
            "-WFP 802.3", "-VirtualBox NDIS", "-Native WiFi Filter",
            "isatap", "Teredo"
        ]):
            continue

        stats = net_stats.get(name)
        is_up = stats.isup if stats else False

        ipv4_addr = next(
            (a.address for a in addrs if getattr(a, "family", None) and getattr(a.family, "name", "") == "AF_INET" and not a.address.startswith("169.254.")),
            ""
        )
        mac_addr = next(
            (a.address for a in addrs if getattr(a, "family", None) and (getattr(a.family, "name", "") in ("AF_LINK", "AF_PACKET") or getattr(a.family, "value", 0) == -1)),
            ""
        )

        desc = f"Network Adapter (Speed: {stats.speed}Mbps)" if (stats and stats.speed) else name

        interfaces.append({
            "id": name,
            "name": name,
            "description": desc,
            "guid": "",
            "ip": ipv4_addr,
            "mac": mac_addr,
            "is_up": is_up,
            "status": "Active" if (is_up and ipv4_addr) else ("Connected" if is_up else "Inactive"),
            "scapy_name": name,
            "has_ip": bool(ipv4_addr),
        })
        seen_names.add(name)

    # Prioritize: active with IP (e.g. Wi-Fi, Ethernet) first, then other active, then loopback, then inactive
    def _sort_key(item: Dict[str, Any]) -> Tuple[int, int, int, str]:
        is_loop = 1 if "loopback" in item["name"].lower() else 0
        has_ip = 0 if item.get("has_ip") else 1
        is_up = 0 if item.get("is_up") else 1
        return (has_ip, is_loop, is_up, item["name"])

    interfaces.sort(key=_sort_key)

    _cached_interfaces = interfaces
    return interfaces


def resolve_scapy_interface(iface_name: str) -> Optional[str]:
    """
    Lazily resolve an adapter friendly name (e.g. 'Wi-Fi') to Scapy's
    Windows device string (e.g. '\\Device\\NPF_{...}'), executed ONLY when the user
    explicitly starts live hardware capture.
    """
    if not iface_name:
        return None
    if "loopback" in iface_name.lower():
        return r"\Device\NPF_Loopback"

    try:
        from scapy.arch.windows import get_windows_if_list
        wifs = get_windows_if_list()
        if isinstance(wifs, list):
            for w in wifs:
                n = w.get("name", "")
                d = w.get("description", "")
                g = w.get("guid", "")
                if g and (n.strip().lower() == iface_name.strip().lower() or d.strip().lower() == iface_name.strip().lower()):
                    return f"\\Device\\NPF_{g}"
    except Exception as e:
        logger.debug(f"Scapy lazy iface resolution: {e}")

    return iface_name


def check_capture_capabilities(timeout: float = 1.0, refresh: bool = False) -> Dict[str, Any]:
    """
    Check if the host platform supports live packet capture
    and whether administrative/Npcap privileges are available without probing raw devices.
    """
    is_windows = (os.name == "nt")
    is_admin = False
    if is_windows:
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
    else:
        is_admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    capabilities = {
        "scapy_installed": False,
        "pcap_driver_present": False,
        "npcap_installed": False,
        "is_admin": is_admin,
        "interfaces": [],
        "can_sniff": False,
        "message": "",
    }

    try:
        import scapy
        capabilities["scapy_installed"] = True
    except ImportError:
        capabilities["message"] = "Scapy is not installed."
        return capabilities

    # Check Npcap on Windows
    system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    npcap_wpcap = os.path.join(system32, "Npcap", "wpcap.dll")
    sys_wpcap = os.path.join(system32, "wpcap.dll")
    if os.path.exists(npcap_wpcap) or os.path.exists(sys_wpcap):
        capabilities["npcap_installed"] = True
        capabilities["pcap_driver_present"] = True

    ifs = get_available_interfaces(timeout=timeout, refresh=refresh)

    if ifs:
        capabilities["interfaces"] = [
            {
                "id": item["id"],
                "name": item["name"],
                "description": item["description"],
                "ip": item.get("ip", ""),
                "status": item.get("status", "Unknown"),
                "scapy_name": item.get("scapy_name", ""),
            }
            for item in ifs
        ]
        capabilities["can_sniff"] = True
        if is_windows:
            if capabilities["npcap_installed"]:
                if is_admin:
                    capabilities["message"] = "Npcap driver active with Administrator privileges. Ready for live packet sniffing."
                else:
                    capabilities["message"] = "Npcap driver detected. Ready for capture (Administrator privileges recommended for raw adapter sniffing)."
            else:
                capabilities["message"] = "Npcap driver not detected. Install Npcap from https://npcap.com to enable live hardware capture."
        else:
            capabilities["message"] = "Network adapters detected. Ready for live capture."
    else:
        capabilities["can_sniff"] = False
        capabilities["message"] = "No usable network adapters detected."

    return capabilities


class LiveTrafficManager:
    """
    Unified manager for real-time network traffic analysis supporting:
    1. Live Hardware Packet Capture (via Scapy & FlowManager)
    2. Demonstration Stream (using verified benchmark traffic datasets)
    Thread-safe, non-blocking, and designed for continuous dashboard telemetry.
    """

    _instances: Dict[str, "LiveTrafficManager"] = {}
    _instance_lock = threading.Lock()

    def __init__(self, user_id: str = "default"):
        self.user_id = user_id
        self.is_running = False
        self.is_paused = False
        self.mode = "demo"  # "demo" or "live"
        self.current_interface: Optional[str] = None
        self.error_message: Optional[str] = None

        self._lock = threading.Lock()
        self._worker_thread: Optional[threading.Thread] = None
        self._harvester_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.buffer: List[Dict[str, Any]] = []
        self.max_buffer_size = 500
        self.total_streamed = 0
        self.total_attacks = 0
        self.total_benign = 0

        # Flow management for live capture
        self.flow_manager = FlowManager(inactivity_timeout=5.0, active_timeout=30.0)

        # Source data for demo mode
        self.source_df: Optional[pd.DataFrame] = None
        self.current_index = 0

    @classmethod
    def get_instance(cls, user_id: str = "default") -> "LiveTrafficManager":
        with cls._instance_lock:
            uid = user_id or "default"
            if uid not in cls._instances:
                cls._instances[uid] = cls(user_id=uid)
            return cls._instances[uid]

    def set_source_data(self, df: pd.DataFrame):
        """Set source dataframe for demonstration mode, validating columns."""
        with self._lock:
            if df is not None and not df.empty and len(df.columns) >= 30:
                self.source_df = df.copy()
                self.current_index = 0

    def start(self, mode: str = "demo", interface: Optional[str] = None, interval_seconds: float = 1.2):
        """Start the live or demonstration traffic telemetry pipeline."""
        with self._lock:
            if self.is_running and not self.is_paused:
                return

            if self.is_paused:
                self.is_paused = False
                logger.info("Traffic telemetry resumed.")
                return

            self.error_message = None

            # 1. Validate Mode
            if mode not in ("demo", "live"):
                self.error_message = f"Unsupported telemetry mode '{mode}'. Choose 'demo' or 'live'."
                self.is_running = False
                return

            # 2. Validate Interface if mode is 'live'
            if mode == "live":
                if not interface or interface.strip().lower() in ("none", "", "default"):
                    self.error_message = "Please select a valid network interface before starting live capture."
                    self.is_running = False
                    return

                available = get_available_interfaces()
                valid_names = {i["name"].lower() for i in available}
                if interface.strip().lower() not in valid_names:
                    self.error_message = f"Selected network interface '{interface}' does not exist or is unavailable. Please select an active adapter."
                    self.is_running = False
                    return

                # Check Npcap on Windows
                if os.name == "nt":
                    caps = check_capture_capabilities()
                    if not caps.get("npcap_installed"):
                        self.error_message = (
                            "Npcap driver was not detected on this system. "
                            "Please download and install Npcap from https://npcap.com to enable live hardware packet capture, "
                            "or select 'Demonstration Stream (Benchmark Flows)'."
                        )
                        self.is_running = False
                        return

            self.is_running = True
            self.is_paused = False
            self.mode = mode
            self.current_interface = interface
            self._stop_event.clear()

        if mode == "live":
            self._worker_thread = threading.Thread(
                target=self._run_live_capture,
                args=(interface,),
                daemon=True,
                name="IDS-LiveCapture"
            )
            self._harvester_thread = threading.Thread(
                target=self._run_flow_harvester,
                daemon=True,
                name="IDS-FlowHarvester"
            )
            self._worker_thread.start()
            self._harvester_thread.start()
            logger.info(f"Live network capture started on interface '{interface}'.")
        else:
            self._worker_thread = threading.Thread(
                target=self._run_demo_stream,
                args=(interval_seconds,),
                daemon=True,
                name="IDS-DemoReplay"
            )
            self._worker_thread.start()
            logger.info("Demonstration traffic replay stream started.")

    def pause(self):
        """Pause processing new incoming traffic."""
        with self._lock:
            self.is_paused = True
        logger.info("Traffic telemetry paused.")

    def resume(self):
        """Resume paused traffic stream."""
        with self._lock:
            self.is_paused = False
        logger.info("Traffic telemetry resumed.")

    def stop(self):
        """Safely stop packet capture, release network handles, and shut down workers."""
        with self._lock:
            self.is_running = False
            self.is_paused = False
            self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)
            self._worker_thread = None
        if self._harvester_thread and self._harvester_thread.is_alive():
            self._harvester_thread.join(timeout=1.5)
            self._harvester_thread = None

        self.flow_manager.flush_all()
        logger.info("Traffic telemetry stopped.")

    def clear(self):
        """Reset session buffer and metrics counters."""
        with self._lock:
            self.buffer.clear()
            self.total_streamed = 0
            self.total_attacks = 0
            self.total_benign = 0
            self.error_message = None
            self.flow_manager.flush_all()

    def _add_classified_record(self, record: Dict[str, Any]):
        """Thread-safe insertion of a classified flow record."""
        with self._lock:
            self.buffer.append(record)
            if len(self.buffer) > self.max_buffer_size:
                self.buffer.pop(0)

            self.total_streamed += 1
            if record.get("Prediction") == "ATTACK":
                self.total_attacks += 1
            else:
                self.total_benign += 1

    def _run_demo_stream(self, interval: float):
        """Continuous generator of ML classifications from benchmark datasets."""
        from src.inference.predictor import get_predictor
        from config import SAMPLES_DIR

        predictor = get_predictor()

        while not self._stop_event.is_set():
            if self.is_paused:
                time.sleep(0.5)
                continue

            with self._lock:
                if self.source_df is None or self.source_df.empty or len(self.source_df.columns) < 30:
                    sample_file = SAMPLES_DIR / "sample_mixed_traffic.csv"
                    if sample_file.is_file():
                        self.source_df = pd.read_csv(sample_file)
                    else:
                        from config import PROCESSED_DATA_DIR
                        test_file = PROCESSED_DATA_DIR / "test.csv"
                        if test_file.is_file():
                            self.source_df = pd.read_csv(test_file, nrows=300)

            if self.source_df is not None and not self.source_df.empty:
                with self._lock:
                    row_idx = self.current_index % len(self.source_df)
                    row_df = self.source_df.iloc[[row_idx]].copy()
                    self.current_index += 1

                try:
                    pred_df, _ = predictor.predict_dataframe(row_df)
                    row_data = pred_df.iloc[0].to_dict()

                    now_str = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Extract key feature dictionary for the View Details modal
                    feat_keys = [
                        "Flow_Duration", "Total_Fwd_Packets", "Total_Backward_Packets",
                        "Total_Length_of_Fwd_Packets", "Total_Length_of_Bwd_Packets",
                        "Fwd_Packet_Length_Mean", "Bwd_Packet_Length_Mean",
                        "Flow_Bytess", "Flow_Packetss", "Flow_IAT_Mean", "Packet_Length_Mean",
                        "SYN_Flag_Count", "ACK_Flag_Count", "PSH_Flag_Count",
                        "Active_Mean", "Idle_Mean"
                    ]
                    features_dict = {}
                    for k in feat_keys:
                        if k in row_df.columns:
                            val = row_df[k].iloc[0]
                            features_dict[k] = round(float(val), 2) if isinstance(val, (int, float)) else str(val)

                    record = {
                        "id": self.total_streamed + 1,
                        "Flow_ID": self.total_streamed + 1,
                        "Source_IP": str(row_data.get("Source_IP", f"192.168.1.{10 + (row_idx % 45)}")),
                        "Destination_IP": str(row_data.get("Destination_IP", "10.0.0.1")),
                        "Source_Port": int(row_data.get("Source_Port", 49152 + (row_idx * 37 % 16000))),
                        "Destination_Port": int(row_data.get("Destination_Port", 80)),
                        "Protocol": str(row_data.get("Protocol", "TCP")),
                        "Prediction": str(row_data.get("Prediction", "BENIGN")),
                        "Attack_Type": str(row_data.get("Attack_Type", "Normal Traffic")),
                        "Confidence": float(row_data.get("Confidence", 99.8)),
                        "Duration": float(row_data.get("Duration", 0.0)),
                        "Source_Bytes": int(row_data.get("Source_Bytes", 0)),
                        "Download_Bytes": int(row_data.get("Download_Bytes", 0)),
                        "Fwd_Packets": int(row_data.get("Fwd_Packets", 1)),
                        "Bwd_Packets": int(row_data.get("Bwd_Packets", 1)),
                        "Timestamp": now_str,
                        "Mode": "Demonstration Stream",
                        "features": features_dict,
                    }

                    self._add_classified_record(record)

                    if record.get("Prediction") == "ATTACK" and self.user_id not in ("standalone", ""):
                        try:
                            from dashboard.user_db import add_user_alert
                            add_user_alert(
                                user_id=self.user_id,
                                alert={
                                    "time": now_str,
                                    "severity": "High",
                                    "type": record.get("Attack_Type", "Intrusion"),
                                    "source": "Demonstration Telemetry",
                                    "src_ip": record.get("Source_IP", "-"),
                                    "dst_ip": record.get("Destination_IP", "-"),
                                    "protocol": record.get("Protocol", "TCP"),
                                    "confidence": f"{record.get('Confidence', 100.0):.1f}%",
                                    "details": f"Intrusion detected: {record.get('Attack_Type')} ({record.get('Confidence', 100.0):.1f}%)",
                                    "status": "Active",
                                }
                            )
                        except Exception as alert_err:
                            logger.debug(f"Could not persist user alert: {alert_err}")

                except Exception as e:
                    logger.warning(f"Error during demonstration flow inference: {e}")

            time.sleep(interval)

    def _run_live_capture(self, iface_name: Optional[str]):
        """Capture live network packets from selected adapter using Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP
        except ImportError:
            with self._lock:
                self.error_message = "Scapy library not installed."
                self.is_running = False
            return

        # Resolve scapy device identifier lazily
        scapy_iface = resolve_scapy_interface(iface_name) if iface_name else None
        self.current_interface = iface_name

        def packet_handler(pkt):
            if self._stop_event.is_set():
                return
            if self.is_paused:
                return

            if IP not in pkt:
                return

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(ip_layer)

            if TCP in pkt:
                tcp = pkt[TCP]
                proto = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                trans_len = tcp.dataofs * 4 if tcp.dataofs is not None else 20
                payload_len = len(tcp.payload)
                flags = str(tcp.flags)
                win = tcp.window
            elif UDP in pkt:
                udp = pkt[UDP]
                proto = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                trans_len = 8
                payload_len = len(udp.payload)
                flags = ""
                win = 0
            else:
                return

            ip_hdr_len = ip_layer.ihl * 4 if ip_layer.ihl is not None else 20

            p_info = PacketInfo(
                timestamp=time.time(),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                packet_length=pkt_len,
                ip_header_length=ip_hdr_len,
                transport_header_length=trans_len,
                payload_length=payload_len,
                tcp_flags=flags,
                tcp_window=win,
            )

            completed = self.flow_manager.add_packet(p_info)
            if completed:
                self._classify_and_record_flow(completed)

        try:
            logger.info(f"Sniffing on interface: {scapy_iface or 'all'}")
            sniff(
                iface=scapy_iface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except (OSError, PermissionError) as os_err:
            logger.warning(f"Live sniffing failed with permission/device error: {os_err}")
            with self._lock:
                self.error_message = (
                    "Live packet capture requires Administrator privileges on Windows. "
                    "Please restart your terminal or PowerShell using 'Run as administrator' and launch SecureFlow again (python run.py). "
                    "Alternatively, select 'Demonstration Stream (Benchmark Flows)' to monitor verified real-time traffic."
                )
                self.is_running = False
        except Exception as err:
            logger.error(f"Live packet sniff error: {err}")
            with self._lock:
                self.error_message = f"Capture error: {err}"
                self.is_running = False

    def _run_flow_harvester(self):
        """Periodically flushes completed or expired flows from FlowManager."""
        while not self._stop_event.is_set():
            if not self.is_paused and self.mode == "live":
                try:
                    expired_flows = self.flow_manager.get_expired_flows()
                    for flow in expired_flows:
                        self._classify_and_record_flow(flow)
                except Exception as e:
                    logger.debug(f"Error harvesting flows: {e}")
            time.sleep(1.0)

    def _classify_and_record_flow(self, flow: Flow):
        """Run ML inference on a captured flow and push to buffer."""
        from src.inference.predictor import get_predictor
        predictor = get_predictor()

        try:
            flow_dict = predictor.predict_flow(flow)
            now_str = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")

            record = {
                "id": self.total_streamed + 1,
                "Flow_ID": self.total_streamed + 1,
                "Source_IP": flow_dict["src_ip"],
                "Destination_IP": flow_dict["dst_ip"],
                "Source_Port": flow_dict["src_port"],
                "Destination_Port": flow_dict["dst_port"],
                "Protocol": flow_dict["protocol"],
                "Prediction": flow_dict["prediction"],
                "Attack_Type": flow_dict["attack_type"],
                "Confidence": flow_dict["confidence"],
                "Duration": flow_dict.get("duration", 0.0),
                "Source_Bytes": flow_dict.get("source_bytes", 0),
                "Download_Bytes": flow_dict.get("download_bytes", 0),
                "Fwd_Packets": flow_dict.get("fwd_packets", 1),
                "Bwd_Packets": flow_dict.get("bwd_packets", 1),
                "Timestamp": now_str,
                "Mode": "Live Capture",
                "features": flow_dict.get("features", {}),
            }

            self._add_classified_record(record)

            if flow_dict["prediction"] == "ATTACK" and self.user_id not in ("standalone", ""):
                try:
                    from dashboard.user_db import add_user_alert
                    add_user_alert(
                        user_id=self.user_id,
                        alert={
                            "time": now_str,
                            "severity": "High",
                            "type": flow_dict["attack_type"],
                            "source": f"Live Capture ({self.current_interface or 'Network'})",
                            "src_ip": flow_dict["src_ip"],
                            "dst_ip": flow_dict["dst_ip"],
                            "protocol": flow_dict["protocol"],
                            "confidence": f"{flow_dict['confidence']:.1f}%",
                            "details": f"Intrusion detected: {flow_dict['attack_type']} ({flow_dict['confidence']:.1f}%)",
                            "status": "Active",
                        }
                    )
                except Exception as alert_err:
                    logger.debug(f"Could not persist user alert: {alert_err}")
        except Exception as e:
            logger.warning(f"Error classifying live flow: {e}")

    def get_latest_records(self, count: int = 50) -> Dict[str, Any]:
        """Fetch the most recent stream items and overall statistics."""
        with self._lock:
            items = list(self.buffer[-count:])
            total = self.total_streamed
            attacks = self.total_attacks
            benign = self.total_benign
            threat_rate = round((attacks / total) * 100.0, 1) if total > 0 else 0.0

            return {
                "records": items,
                "is_running": self.is_running,
                "is_paused": self.is_paused,
                "mode": "Live Capture" if self.mode == "live" else "Demonstration Replay (Benchmark Flows)",
                "current_interface": self.current_interface or "Default Adapter",
                "total_streamed": total,
                "total_attacks": attacks,
                "total_benign": benign,
                "threat_percentage": threat_rate,
                "engine_status": "Online (Random Forest Classifier)",
                "error": self.error_message,
            }


# Backwards compatibility alias
TrafficReplayStreamer = LiveTrafficManager
