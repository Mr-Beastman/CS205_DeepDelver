from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


class StaticReport:
    """
    Generates the static analysis section of the malware report.
    """

    def __init__(self, filePath: str, staticResults: dict):
        self.filePath = filePath
        self.staticResults = staticResults or {}
        self.styles = getSampleStyleSheet()
        self.page = []
        self.maxRows = 50


    def addSectionTitle(self, title: str, explanation: str = None):
        """Add section header and optional explanation."""
        self.page.append(Spacer(1, 8))
        self.page.append(Paragraph(title, self.styles["Heading3"]))
        if explanation:
            self.page.append(Spacer(1, 4))
            self.page.append(Paragraph(explanation, self.styles["Normal"]))
        self.page.append(Spacer(1, 6))

    def defaultTableStyle(self):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ])

    def wrapStyle(self):
        return ParagraphStyle(name="wrap", wordWrap='CJK')

    # table builders
    def timestampsToTable(self, items):
        headers = ["Check", "Result", "Severity", "Value"]
        tableData = [headers]
        wrapStyle = self.wrapStyle()
        for item in items[:self.maxRows]:
            tableData.append([
                Paragraph(item.get("check", ""), wrapStyle),
                Paragraph(item.get("result", ""), wrapStyle),
                Paragraph(item.get("severity", ""), wrapStyle),
                Paragraph(item.get("value", ""), wrapStyle)
            ])
        if len(items) > self.maxRows:
            tableData.append([Paragraph(f"{len(items) - self.maxRows} more entries not shown", wrapStyle), "", "", ""])
        return Table(tableData, colWidths=[150, 100, 80, 200], repeatRows=1, style=self.defaultTableStyle())

    def hashesToTable(self, items):
        headers = ["Hash Type", "Hash Value", "Result", "Severity"]
        tableData = [headers]
        wrapStyle = self.wrapStyle()
        for item in items[:self.maxRows]:
            tableData.append([
                Paragraph(item.get("hashType", ""), wrapStyle),
                Paragraph(item.get("hashValue", ""), wrapStyle),
                Paragraph(item.get("result", ""), wrapStyle),
                Paragraph(item.get("severity", ""), wrapStyle)
            ])
        if len(items) > self.maxRows:
            tableData.append([Paragraph("...", wrapStyle), Paragraph(f"{len(items) - self.maxRows} additional entries not shown", wrapStyle), "", ""])
        return Table(tableData, colWidths=[60, 250, 100, 60], repeatRows=1, style=self.defaultTableStyle())

    def stringsToTable(self, items):
        headers = ["Value", "Classification"]
        tableData = [headers]
        wrapStyle = self.wrapStyle()
        for entry in items[:self.maxRows]:
            tableData.append([
                Paragraph(entry.get("value", ""), wrapStyle),
                Paragraph(entry.get("classification", ""), wrapStyle)
            ])
        if len(items) > self.maxRows:
            tableData.append([Paragraph("...", wrapStyle), Paragraph(f"{len(items) - self.maxRows} additional entries not shown", wrapStyle)])
        return Table(tableData, colWidths=[300, 150], repeatRows=1, style=self.defaultTableStyle())

    def importsToTable(self, items):
        headers = ["Category / DLL", "Function", "Severity", "Result"]
        tableData = [headers]
        wrapStyle = self.wrapStyle()
        for entry in items[:self.maxRows]:
            tableData.append([
                Paragraph(entry.get("category", ""), wrapStyle),
                Paragraph(f"{entry.get('dll','')}: {entry.get('function','')}", wrapStyle),
                Paragraph(entry.get("severity", ""), wrapStyle),
                Paragraph(entry.get("result", ""), wrapStyle)
            ])
        if len(items) > self.maxRows:
            tableData.append([Paragraph("...", wrapStyle), Paragraph(f"{len(items) - self.maxRows} additional entries not shown", wrapStyle), "", ""])
        return Table(tableData, colWidths=[120, 200, 80, 150], repeatRows=1, style=self.defaultTableStyle())

    def entropyToTable(self, items):
        headers = ["Metric", "Value", "Severity", "Indicator"]
        tableData = [headers]
        wrapStyle = self.wrapStyle()
        for entry in items[:self.maxRows]:
            tableData.append([
                Paragraph(entry.get("metric", ""), wrapStyle),
                str(entry.get("value", "")),
                entry.get("severity", ""),
                Paragraph(entry.get("indicator", ""), wrapStyle)
            ])
        if len(items) > self.maxRows:
            tableData.append([Paragraph("...", wrapStyle), f"{len(items) - self.maxRows} additional entries not shown", "", ""])
        return Table(tableData, colWidths=[120, 60, 80, 250], repeatRows=1, style=self.defaultTableStyle())

    # formatters
    def formatMetadata(self):
        explanation = "Examine file metadata such as timestamps, sections, and other properties to detect anomalies that may indicate tampering or malware."
        self.addSectionTitle("Metadata Analysis", explanation)
        metadata = self.staticResults.get("metadata", {})
        if not metadata:
            self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))
            return

        categories = {
            "fileTimeStamps": "Timestamps",
            "fileSectionsNames": "Section Names",
            "fileInfo": "File Info",
            "otherChecks": "Other Checks"
        }

        for key, displayName in categories.items():
            entries = metadata.get(key, {})
            if not entries:
                continue
            tableItems = []
            for entryKey, entryVal in entries.items():
                if isinstance(entryVal, dict):
                    tableItems.append({
                        "check": entryKey,
                        "result": entryVal.get("result", ""),
                        "severity": entryVal.get("severity", ""),
                        "value": entryVal.get("value", "")
                    })
                else:
                    tableItems.append({
                        "check": entryKey,
                        "result": str(entryVal),
                        "severity": "",
                        "value": ""
                    })
            if tableItems:
                self.addSectionTitle(displayName)
                self.page.append(self.timestampsToTable(tableItems))
                self.page.append(Spacer(1, 6))

    def formatHashes(self):
        explanation = "Display cryptographic hashes of the file to verify integrity and for threat intelligence purposes."
        self.addSectionTitle("Hash Analysis", explanation)
        hashesData = self.staticResults.get("hashes", {}).get("hashes", [])
        if hashesData:
            self.page.append(self.hashesToTable(hashesData))
        else:
            self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))

    def formatStrings(self):
        explanation = "Analyze embedded strings to detect suspicious content, such as URLs, commands, or malware indicators."
        self.addSectionTitle("Strings Analysis", explanation)
        strings = self.staticResults.get("strings", {})
        if not strings:
            self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))
            return
        for category, items in strings.items():
            self.addSectionTitle(category.replace("_", " ").title())
            if not items:
                self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))
                continue
            self.page.append(self.stringsToTable(items))

    def formatImports(self):
        explanation = "Analyze imported DLLs and functions to identify suspicious API usage that may indicate malicious behavior."
        self.addSectionTitle("Imports Analysis", explanation)
        imports = self.staticResults.get("imports", {}).get("findings", [])
        if not imports:
            self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))
            return
        self.page.append(self.importsToTable(imports))

    def formatEntropy(self):
        explanation = "Entropy analysis detects regions of high randomness that may indicate packed or obfuscated code."
        self.addSectionTitle("Entropy Analysis", explanation)
        entropy = self.staticResults.get("entropy", {})
        tableItems = []
        sh = entropy.get("shannon", {})
        if sh:
            tableItems.append(sh)
        sp = entropy.get("spikes", {})
        if sp:
            tableItems.append(sp)
        if tableItems:
            self.page.append(self.entropyToTable(tableItems))
        else:
            self.page.append(Paragraph("Nothing identified", self.styles["Normal"]))

    # flowables
    def getFlowables(self):
        """Return flowables for the static results section of the report."""
        self.page = []

        # Main title
        mainTitle = "Static Analysis Results"
        mainExplanation = (
            "Static analysis examines the file without executing it. "
            "It identifies characteristics such as metadata, embedded strings, "
            "cryptographic hashes, imports, and entropy metrics. "
            "These may indicate malicious behavior or anomalies."
        )
        self.addSectionTitle(mainTitle, mainExplanation)

        # Section-specific analyses
        self.formatHashes()
        self.formatMetadata()
        self.formatStrings()
        self.formatImports()
        self.formatEntropy()

        return self.page
