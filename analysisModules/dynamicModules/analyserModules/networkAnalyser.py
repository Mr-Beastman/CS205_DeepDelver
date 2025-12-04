import re
from collections import Counter

class NetworkAnalyser:
    badPorts = {4444, 1337, 8081, 9001, 9002, 23, 21, 69}
    suspiciousProtocols = {"IRC", "FTP", "TFTP", "TELNET", "SSH", "SMB", "ICMP"}
    privateIpRegex = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", re.IGNORECASE)

    def isPublicIp(self, ip: str) -> bool:
        if not ip or ip == "0.0.0.0":
            return False
        return not bool(self.privateIpRegex.match(ip))

    def analyse(self, netData: list) -> list:
        results = []
        beaconFreq = Counter()
        protoCounter = Counter()
        externalComm = Counter()
        suspiciousPortsDetected = set()

        for pkt in netData:
            src = pkt.get("src", "")
            dst = pkt.get("dst", "")
            proto = pkt.get("proto", "").upper()
            port = pkt.get("port")
            flagged = False

            protoCounter[proto] += 1

            #  IP coms tracking
            if self.isPublicIp(dst):
                externalComm[dst] += 1
                beaconFreq[dst] += 1

            # dsuspicious protocol
            if proto in self.suspiciousProtocols:
                results.append({
                    "eventType": "SuspiciousProtocol",
                    "description": f"Suspicious protocol detected: {proto}",
                    "riskLevel": "medium",
                    "details": {"src": src, "dst": dst, "protocol": proto}
                })
                flagged = True

            # port detection
            if isinstance(port, int) and port in self.badPorts:
                suspiciousPortsDetected.add(port)
                flagged = True

            if not flagged:
                results.append({
                    "eventType": proto or "Network",
                    "description": "No suspicious network activity detected",
                    "riskLevel": "safe",
                    "details": {"src": src, "dst": dst, "proto": proto}
                })

        # beaconing
        for host, count in beaconFreq.items():
            if count > 15:
                results.append({
                    "eventType": "Beaconing",
                    "description": f"Repeated comms to {host}",
                    "riskLevel": "high",
                    "details": {"host": host, "count": count}
                })

        # ICMP
        if protoCounter.get("ICMP", 0) > 20:
            results.append({
                "eventType": "HeavyICMP",
                "description": "Elevated ICMP activity",
                "riskLevel": "medium",
                "details": {"count": protoCounter["ICMP"]}
            })

        # bad ports
        for port in suspiciousPortsDetected:
            results.append({
                "eventType": "SuspiciousPort",
                "description": f"Traffic on suspicious port: {port}",
                "riskLevel": "medium",
                "details": {"port": port}
            })

        # external connections
        if externalComm:
            results.append({
                "eventType": "ExternalComm",
                "description": f"Outbound communication to {len(externalComm)} external IPs.",
                "riskLevel": "medium",
                "details": dict(externalComm)
            })

        return results
