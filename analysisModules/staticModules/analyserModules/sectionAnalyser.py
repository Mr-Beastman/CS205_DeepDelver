from typing import Dict, Any, List

class SectionAnalyser:
    """Analyse PE sections for anomalies and suspicious indicators."""

    RWX_MASK = 0x30000000  # Execute + Write + Read bits
    STANDARD_SECTIONS = [".text", ".rdata", ".data", ".rsrc", ".pdata"]

    def __init__(self, sectionDict: Dict[str, Dict[str, Any]]):
        self.sections = sectionDict or {}
        self.findings: List[Dict[str, Any]] = []

    def rawVsVirtual(self, name: str, s: Dict[str, int]) -> List[Dict[str, Any]]:
        anomalies = []
        v = s.get("VirtualSize", 0)
        r = s.get("SizeOfRawData", 0)

        if r == 0 and v > 0:
            anomalies.append({
                "section": name,
                "check": "raw_vs_virtual",
                "severity": "high",
                "result": f"RawSize=0 but VirtualSize={v} — likely packed or injected.",
                "value": f"VirtualSize={v}, RawSize={r}"
            })
        if r > 0 and v > r * 3:
            anomalies.append({
                "section": name,
                "check": "raw_vs_virtual",
                "severity": "medium",
                "result": f"Unusually large VirtualSize (V={v}, R={r}).",
                "value": f"VirtualSize={v}, RawSize={r}"
            })
        return anomalies

    def checkRwx(self, name: str, s: Dict[str, int]) -> List[Dict[str, Any]]:
        if s.get("Characteristics", 0) & self.RWX_MASK == self.RWX_MASK:
            return [{
                "section": name,
                "check": "rwx_permissions",
                "severity": "high",
                "result": "Section has RWX permissions — very suspicious.",
                "value": s.get("Characteristics", 0)
            }]
        return []

    def checkCustom(self, name: str) -> List[Dict[str, Any]]:
        if name.lower() not in [sec.lower() for sec in self.STANDARD_SECTIONS]:
            return [{
                "section": name,
                "check": "custom_name",
                "severity": "medium",
                "result": "Non-standard section name detected.",
                "value": name
            }]
        return []

    def analyseSections(self) -> dict:
        results = {
            "anomalies": [],
            "suspiciousSections": []
        }
        for name, s in self.sections.items():
            findings = self.rawVsVirtual(name, s)
            results["anomalies"].extend(findings)
            custom = self.checkCustom(name)
            results["suspiciousSections"].extend(custom)
            results["anomalies"].extend(self.checkRwx(name, s))
        return results
