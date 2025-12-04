from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class SummaryReport:
    def __init__(self, filePath, staticResults, riskReport):
        self.filePath = filePath
        self.staticResults = staticResults
        self.riskReport = riskReport
        self.styles = getSampleStyleSheet()

    def addSectionTitle(self, title):
        return [Spacer(1, 12), Paragraph(title, self.styles["Heading2"]), Spacer(1, 6)]

    def getFlowables(self):
        flowables = []

        print("> Creating Title")
        flowables.append(Paragraph("<b>DeepDelver Malware Analysis Report</b>", self.styles['Title']))
        flowables.append(Spacer(1, 20))

        print("> Creating Summary")
        flowables.extend(self.addSectionTitle("Summary"))
        fileInfo = self.staticResults.get("fileInfo", {})
        flowables.append(Paragraph(f"<b>File Name:</b> {fileInfo.get('fileName', 'Unknown')}", self.styles["Normal"]))
        flowables.append(Paragraph(f"<b>File Type:</b> {fileInfo.get('fileType', 'Unknown')}", self.styles["Normal"]))
        flowables.append(Paragraph(f"<b>File Size:</b> {fileInfo.get('fileSize', 'Unknown')}", self.styles["Normal"]))
        flowables.append(Spacer(1, 10))
        flowables.append(Paragraph(f"<b>Total Risk Score:</b> {self.riskReport.get('totalScore', 'N/A')}", self.styles["Normal"]))
        flowables.append(Paragraph(f"<b>Overall Rating:</b> {self.riskReport.get('rating', 'N/A')}", self.styles["Normal"]))
        flowables.append(Spacer(1, 10))

        return flowables