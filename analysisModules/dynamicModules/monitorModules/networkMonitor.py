import time
import threading
import asyncio
import pyshark

class NetworkMonitor:
    """
    Malware-focused network monitoring via Pyshark.
    """

    # common exploit/service ports
    suspiciousPorts = [21, 22, 23, 25, 53, 80, 443, 445, 3389]

    def __init__(self, checkInterval: float = 0.1):
        self.checkInterval = checkInterval
        self.results = []
        self.name = "NetworkMonitor"

    def identifyInterfaces(self) -> list:
        """Return available network interfaces excluding loopback if possible."""
        try:
            available = pyshark.LiveCapture().interfaces
            if not available:
                print("No Pyshark interfaces detected.")
                return []

            filtered = [i for i in available if "Loopback" not in i]
            return filtered or [available[0]]

        except Exception as e:
            print(f"Error detecting interfaces: {e}")
            return []

    def convertPacket(self, packet) -> dict:
        """Extract relevant packet info."""
        data = {
            "timestamp": packet.sniff_time.strftime("%d:%m:%y %H:%M:%S"),
            "src": "",
            "dst": "",
            "proto": "",
            "port": "",
            "layers": [],
        }
        try:
            if hasattr(packet, "ip"):
                data["src"] = packet.ip.src
                data["dst"] = packet.ip.dst
            if hasattr(packet, "tcp"):
                data["proto"] = "TCP"
                data["port"] = int(packet.tcp.dstport)
            elif hasattr(packet, "udp"):
                data["proto"] = "UDP"
                data["port"] = int(packet.udp.dstport)
            else:
                data["proto"] = packet.highest_layer
        except Exception:
            pass

        try:
            data["layers"] = [layer.layer_name for layer in packet.layers]
        except Exception:
            pass

        return data

    def runMonitor(self, stopEvent: threading.Event):
        asyncio.set_event_loop(asyncio.new_event_loop())
        print(f"{self.name} Started")

        interfaces = self.identifyInterfaces()
        if not interfaces:
            print(f"No valid interfaces found. {self.name} exiting.")
            return self.results

        print(f"Monitoring interfaces: {interfaces}")

        try:
            capture = pyshark.LiveCapture(interface=interfaces)

            for packet in capture.sniff_continuously():
                if stopEvent.is_set():
                    break
                try:
                    pktInfo = self.convertPacket(packet)

                    if pktInfo["dst"] not in ["127.0.0.1", "localhost"]:
                        # Optional port filter
                        if pktInfo["port"] in self.suspiciousPorts or not pktInfo["port"]:
                            self.results.append(pktInfo)

                except Exception as error:
                    print(f"Packet parse error: {error}")

                time.sleep(self.checkInterval)

        except Exception as error:
            print(f"Error in monitor {self.name}: {error}")

        print(f"{self.name} Finished Capturing : {len(self.results)} packets recorded.")
        return self.results
