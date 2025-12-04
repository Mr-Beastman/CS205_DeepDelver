from reportlab.platypus import PageBreak, SimpleDocTemplate
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

from reportModules.summaryGenerator import SummaryReport
from reportModules.staticGenerator import StaticReport
from reportModules.dynamicGenerator import DynamicReport

MAX_ROWS = 50

# ----------------- Base Controller -----------------
class ReportGenerator:
    """
    Controller to collect flowables from summary, static, and dynamic reports.
    """
    def __init__(self, filePath: str, staticResults: dict, dynamicResults: dict, riskReport: dict):
        self.filePath = filePath
        self.staticResults = staticResults
        self.dynamicResults = dynamicResults
        self.riskReport = riskReport
        self.styles = getSampleStyleSheet()

        # Initialize individual report sections
        self.summarySection = SummaryReport(filePath, staticResults, riskReport)
        self.staticSection = StaticReport(filePath, staticResults)
        self.dynamicSection = DynamicReport(filePath, dynamicResults)

    def buildReportSections(self):
        """Return combined flowables from summary, static, and dynamic sections."""
        flowables = []

        # Summary first
        flowables.extend(self.summarySection.getFlowables())

        # # Static analysis
        flowables.extend(self.staticSection.getFlowables())

        # # Dynamic analysis
        flowables.extend(self.dynamicSection.getFlowables())

        return flowables

    def generatePDF(self, outputPath=None):
        """Build PDF using all available sections."""
        if outputPath is None:
            import os
            filename = os.path.basename(self.filePath)
            outputPath = os.path.join(os.path.expanduser("~"), "Desktop", f"{filename}_report.pdf")

        flowables = self.buildReportSections()
        doc = SimpleDocTemplate(outputPath, pagesize=letter)
        doc.build(flowables)
        print(f"[+] PDF report generated: {outputPath}")
