import psutil
import pyshark

class NetworkMonitor:

    def __init__(self):
        pass

    def identifyInterfaces(self) -> list:
        networkInterface = list(psutil.net_if_addrs().keys())
        return networkInterface

    def convertPacket(self, packet: any) -> dict:
        packetData = {
            "timestamp": packet.sniff_time.strftime("%d:%m:%y %H:%M:%S")
        }

        return packetData

    def runMonitor(self):
        sharkCapture = pyshark.LiveCapture(interface=self.identifyInterfaces())