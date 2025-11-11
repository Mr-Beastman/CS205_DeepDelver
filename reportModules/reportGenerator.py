from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, filePath: str, staticResults: dict):
        self.filePath = filePath
        self.staticResults = staticResults
        self.styles = getSampleStyleSheet()
        self.page = []

    def formatHeader(self):
        self.page.append(Paragraph("DeepDelver Malware Analysis Report", self.styles['Title']))
        self.page.append(Spacer(1, 12))

    def formatSummary(self):
        self.page.append(Paragraph("Summary", self.styles["Heading2"]))
        self.page.append(Paragraph(f"<b>File Name:</b> {self.staticResults.get('Metadata', {}).get('fileName')}", self.styles['Normal']))
        self.page.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", self.styles['Normal']))
        self.page.append(Paragraph(f"<b>Rating:</b>"))
        self.page.append(Spacer(1, 20))        

    def formatMetadata(self):
        self.page.append(Paragraph("Metadata", self.styles["Heading2"]))

        metadata = self.staticResults.get("Metadata",{})
        tableData = []

        for key, value in metadata.items():
            if isinstance(value, list):
                value = "\n".join(value)
            tableData.append([key, str(value)])

        table = Table(tableData, colWidths=[120, 350])

        self.page.append(table)  

    def generateReport(self, outputPath: str = None):
            if outputPath is None:
                filename = os.path.basename(self.filePath)
                outputPath = f"{filename}_report.pdf"

            doc = SimpleDocTemplate(outputPath, pagesize=letter)

            self.formatHeader()
            self.formatSummary()
            self.formatMetadata()

            # Build PDF
            doc.build(self.page)
            print(f"[+] PDF report generated: {os.path.abspath(outputPath)}")
