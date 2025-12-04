import datetime
from typing import Dict, Any

class MetadataAnalyser:
    """Analyse PE metadata for anomalies and suspicious indicators."""

    notableSections = [
        ".packed", ".pdata", ".xyz", ".adata", ".ndata",
        ".aspack", ".upx", "upx", "vmp", ".themida"
    ]

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata or {}

    @staticmethod
    def parseDate(times: str):
        """
        Sets date format to 'dd-mm-yyyy HH:MM:SS'.

        Parameters:
            times (str): Timestamps

        Returns:
            datetime or None: Parsed datetime obj
        """
        try:
            _, dateString = times.split(":", 1)
            return datetime.datetime.strptime(dateString.strip(), "%d-%m-%Y %H:%M:%S")
        except Exception:
            return None

    @staticmethod
    def inFuture(dt: datetime.datetime) -> bool:
        """
        Check if a date/time is in the future.

        Parameters:
            dt (datetime.datetime): datetime object to check

        Returns:
            bool: True if in the future, False if not
        """
        return dt > datetime.datetime.now()

    def analyseTimestamps(self) -> dict:
        """
        CHeck timestamps for anomalies, future timestamps and compile-after-creation inconsistencies.

        Returns:
            Dict[str, Dict[str, str]]: Mapping of timestamp checks and their analysis results
        """
        times = self.metadata.get("fileTimeStamps", [])
        parsedDict = {}
        results = {}

        for time in times:
            dt = self.parseDate(time)
            if dt:
                key = time.split(":", 1)[0].strip().lower()
                parsedDict[key] = dt
                results[key] = {
                    "severity": "high" if self.inFuture(dt) else "info",
                    "result": "Timestamp in the future" if self.inFuture(dt) else "Normal timestamp",
                    "value": dt.strftime("%Y-%m-%d %H:%M:%S")
                }

        if "compiled" in parsedDict and "created" in parsedDict:
            severity = "high" if parsedDict["compiled"] > parsedDict["created"] else "info"
            results["compile_vs_create"] = {
                "severity": severity,
                "result": ("Compiled after creation (possible spoofing)" if severity == "high" else "Normal order"),
                "value": f"Compiled={parsedDict['compiled']}, Created={parsedDict['created']}"
            }

        return results

    def analyseSectionNames(self) -> dict:
        """
        Analyse section names for suspicious patterns/packing.

        Returns:
            Dict: section names and analysis results
        """
        sections = self.metadata.get("fileSections", {})
        results = {}
        for name in sections:
            severity = "high" if name.lower() in self.notableSections else "info"
            results[name] = {
                "severity": severity,
                "result": "Unusual section name" if severity == "high" else "Standard section",
                "value": name
            }
        return results

    def analyseSectionCount(self) -> dict:
        """
        Analyse the number of sections to detect anomalies (e.g., packed files).

        Returns:
            Dict: Section count
        """
        count = self.metadata.get("fileSectionCount", 0)
        if count <= 3:
            severity = "high"
            result = "Very low section count (likely packed)"
        elif count > 10:
            severity = "medium"
            result = "High number of sections (possible obfuscation)"
        else:
            severity = "info"
            result = "Normal section count"

        return {
            "total_sections": {
                "severity": severity,
                "result": result,
                "value": count
            }
        }

    def analyseFileSize(self) -> dict:
        """
        Analyse the file size for suspiciously small or large executables.

        Returns:
            Dict: File size results
        """
        sizeString = str(self.metadata.get("fileSize", "0 MB"))
        try:
            sizeValue, unit = sizeString.split()
            size = float(sizeValue)
            if unit.upper() == "GB":
                size *= 1024  # normalize GB to MB
        except Exception:
            size = 0

        if size < 0.05:
            severity = "high"
            result = "Extremely small executable (likely packer stub)"
        elif size > 50:
            severity = "medium"
            result = "Very large executable (possible dropper or bundled payload)"
        else:
            severity = "info"
            result = "Normal size"

        return {
            "fileSize": {
                "severity": severity,
                "result": result,
                "value": sizeString
            }
        }

    def analyseArchitecture(self) -> dict:
        """
        Analyse CPU architecture of the file for uncommon types.

        Returns:
            Dict : Architecture results
        """
        arch = str(self.metadata.get("fileArchitecture", "")).lower()
        severity = "high" if arch not in ["x86", "x64"] else "info"
        result = f"Uncommon architecture: {arch}" if severity == "high" else "Standard architecture"

        return {
            "fileArchitecture": {
                "severity": severity,
                "result": result,
                "value": arch
            }
        }

    def analyseEntryPoint(self) -> dict:
        """
        Analyse the entry point of the PE file to detect anomalies.

        Returns:
            Dict: Entry points
        """
        entryHex = self.metadata.get("fileEntryPoint", "0x0")
        try:
            entry = int(entryHex, 16)
        except Exception:
            entry = 0

        sections = self.metadata.get("fileSections", {})
        severity = "high"
        result = "Entry point not found in any section (corrupted/unusual)"

        for name, sec in sections.items():
            start = sec.get("VirtualAddress", 0)
            end = start + sec.get("VirtualSize", 0)
            if start <= entry <= end:
                if name.lower() == ".text":
                    severity = "info"
                    result = "Entry point in .text (normal)"
                else:
                    severity = "high"
                    result = f"Entry point in unusual section: {name}"
                break

        return {
            "fileEntryPoint": {
                "severity": severity,
                "result": result,
                "value": entryHex
            }
        }

    def analyseSectionsProperties(self) -> dict:
        """
        Analyse sections for zero-size and executable-but-unusual characteristics.

        Returns:
            Dict: section with list of findings
        """
        sections = self.metadata.get("fileSections", {})
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        results = {}

        for name, sec in sections.items():
            sec_results = []
            if sec.get("VirtualSize", 0) == 0 or sec.get("sizeOfRawData", 0) == 0:
                sec_results.append({
                    "severity": "high",
                    "result": "Zero-size section (suspicious, possibly packed)",
                    "value": f"VirtualSize={sec.get('VirtualSize')}, SizeOfRawData={sec.get('sizeOfRawData')}"
                })

            characteristics = sec.get("characteristics", 0)
            if (characteristics & IMAGE_SCN_MEM_EXECUTE) and name.lower() != ".text":
                sec_results.append({
                    "severity": "high",
                    "result": "Executable section outside .text (possible shellcode/injection)",
                    "value": f"Characteristics={hex(characteristics)}"
                })

            if sec_results:
                results[name] = sec_results

        return results

    def analyseMetadata(self) -> Dict:
        """
        Run all analyses and return a dictionary structured like MetadataExtractor.

        Returns:
            Dict: All analysis results keyed via typing
        """
        return {
            "fileTimeStamps": self.analyseTimestamps(),
            "fileSectionsNames": self.analyseSectionNames(),
            "fileSectionCount": self.analyseSectionCount(),
            "fileSize": self.analyseFileSize(),
            "fileArchitecture": self.analyseArchitecture(),
            "fileEntryPoint": self.analyseEntryPoint(),
            "fileSectionsProperties": self.analyseSectionsProperties()
        }
