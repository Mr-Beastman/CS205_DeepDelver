from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class DynamicReport:
    """
    Generate dynamic analysis section of the malware report.
    """

    def __init__(self, filePath: str, dynamicResults: dict):
        self.filePath = filePath
        self.dynamicResults = dynamicResults or {}
        self.styles = getSampleStyleSheet()
        self.page = []
        self.maxRows = 50

    def addSectionTitle(self, title: str, description: str):
        self.page.append(Spacer(1, 12))
        self.page.append(Paragraph(title, self.styles["Heading2"]))
        self.page.append(Spacer(1, 6))
        self.page.append(Paragraph(description, self.styles["Normal"]))
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

    def createTable(self, headers, rows, colWidths=None):
        wrapStyle = ParagraphStyle(name="wrap")
        tableData = [headers]

        for row in rows[:self.maxRows]:
            tableData.append([Paragraph(str(cell), wrapStyle) for cell in row])

        remaining = len(rows) - self.maxRows
        if remaining > 0:
            tableData.append([Paragraph(f"... {remaining} more entries not shown", wrapStyle)] + [""] * (len(headers) - 1))

        return Table(tableData, colWidths=colWidths, style=self.defaultTableStyle())

    # tabke builders 
    def processesToTable(self, entries):
        headers = ["PID", "Process Name", "Executable Path", "Parent", "Risk Level"]
        rows = []
        for e in entries:
            rows.append([
                e.get("details", {}).get("pid", ""),
                e.get("details", {}).get("name", ""),
                e.get("details", {}).get("exePath", ""),
                e.get("details", {}).get("parent", ""),
                e.get("riskLevel", ""),
            ])
        return self.createTable(headers, rows, colWidths=[40, 120, 200, 100, 60])

    def registryToTable(self, entries):
        headers = ["Event Type", "Key/Name", "Value", "Risk Level"]
        rows = []
        for e in entries:
            rows.append([
                e.get("eventType", ""),
                e.get("details", {}).get("key", "") or e.get("details", {}).get("name", ""),
                e.get("details", {}).get("value", ""),
                e.get("riskLevel", ""),
            ])
        return self.createTable(headers, rows, colWidths=[80, 150, 250, 60])

    def persistenceToTable(self, entries):
        headers = ["Event Type", "Item/Task/Service", "Path/Value", "Risk Level"]
        rows = []
        for e in entries:
            rows.append([
                e.get("eventType", ""),
                e.get("details", {}).get("item", "") or e.get("details", {}).get("taskName", "") or e.get("details", {}).get("service", "") or e.get("details", {}).get("name", ""),
                e.get("details", {}).get("value", "") or e.get("details", {}).get("path", ""),
                e.get("riskLevel", ""),
            ])
        return self.createTable(headers, rows, colWidths=[80, 150, 250, 60])

    def networkToTable(self, entries):
        headers = ["Event Type", "Source", "Destination", "Protocol", "Port", "Risk Level"]
        rows = []
        for e in entries:
            rows.append([
                e.get("eventType", ""),
                e.get("details", {}).get("src", ""),
                e.get("details", {}).get("dst", ""),
                e.get("details", {}).get("protocol", "") or e.get("details", {}).get("proto", ""),
                str(e.get("details", {}).get("port", "")),
                e.get("riskLevel", ""),
            ])
        return self.createTable(headers, rows, colWidths=[80, 80, 80, 60, 40, 60])

    def filesystemToTable(self, entries):
        headers = ["Event Type", "Path", "Extension", "Risk Level"]
        rows = []
        for e in entries:
            rows.append([
                e.get("eventType", ""),
                e.get("details", {}).get("path", ""),
                e.get("details", {}).get("extension", ""),
                e.get("riskLevel", ""),
            ])
        return self.createTable(headers, rows, colWidths=[80, 200, 60, 60])

    # formatting each section
    def formatProcesses(self):
        self.addSectionTitle(
            "Process Analysis",
            "Analyzing running or created processes to detect suspicious executables, "
            "unusual parent-child relationships, LOLBIN abuse, and random process names."
        )
        entries = self.dynamicResults.get("process", [])
        if entries:
            self.page.append(self.processesToTable(entries))
        else:
            self.page.append(Paragraph("No processes of interest identified.", self.styles["Normal"]))

    def formatRegistry(self):
        self.addSectionTitle(
            "Registry Analysis",
            "Inspecting registry modifications to identify persistence mechanisms, "
            "suspicious keys, and unusual run/startup entries."
        )
        entries = self.dynamicResults.get("registry", [])
        if entries:
            self.page.append(self.registryToTable(entries))
        else:
            self.page.append(Paragraph("No suspicious registry activity detected.", self.styles["Normal"]))

    def formatPersistence(self):
        self.addSectionTitle(
            "Persistence Analysis",
            "Detecting services, scheduled tasks, and startup items that may indicate "
            "malware persistence."
        )
        entries = self.dynamicResults.get("persistence", [])
        if entries:
            self.page.append(self.persistenceToTable(entries))
        else:
            self.page.append(Paragraph("No persistence mechanisms detected.", self.styles["Normal"]))

    def formatNetwork(self):
        self.addSectionTitle(
            "Network Analysis",
            "Monitoring network activity for suspicious connections, unusual protocols, "
            "beaconing, or communication with external hosts."
        )
        entries = self.dynamicResults.get("network", [])
        if entries:
            self.page.append(self.networkToTable(entries))
        else:
            self.page.append(Paragraph("No suspicious network activity detected.", self.styles["Normal"]))

    def formatFilesystem(self):
        self.addSectionTitle(
            "Filesystem Analysis",
            "Inspecting file events for access to sensitive locations, creation of executables, "
            "or files with randomized names."
        )
        entries = self.dynamicResults.get("filesystem", [])
        if entries:
            self.page.append(self.filesystemToTable(entries))
        else:
            self.page.append(Paragraph("No suspicious filesystem activity detected.", self.styles["Normal"]))

    def getFlowables(self):
            self.page = []

            mainTitle = "Dynamic Analysis Results"
            mainExplanation = (
                "Dynamic analysis monitors the behavior of the file during execution. "
                "It identifies processes, registry modifications, persistence mechanisms, network activity "
                "and file system changes in an attempt to detect malicious behavior in real time."
            )
            self.addSectionTitle(mainTitle, mainExplanation)

            self.formatProcesses()
            self.formatRegistry()
            self.formatPersistence()
            self.formatNetwork()
            self.formatFilesystem()

            return self.page
