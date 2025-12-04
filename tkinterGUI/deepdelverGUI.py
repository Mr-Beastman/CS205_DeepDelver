import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
import os

from analysisModules.controllerModule.analysisController import runFullAnalysis
from reportModules.reportGenerator import ReportGenerator
from securityModules.enviormentModule import isVirtualMachine
from utilitieModules.utilities import isExe

class DeepDelverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DeepDelver Malware Analysis")
        self.root.geometry("720x420")

        tk.Label(root, text="DeepDelver Malware Analysis", font=("Arial", 16, "bold")).pack(pady=10)

        self.selectButton = tk.Button(root, text="Select EXE & Start Analysis", command=self.selectFile)
        self.selectButton.pack(pady=10)

        self.statusCurrent = tk.Label(root, text="> Ready >", fg="#2ecc71", font=("Consolas", 10))
        self.statusCurrent.pack(pady=20)

        self.loaderRunning = False

    def selectFile(self):
        if not isVirtualMachine():
            warn = messagebox.askyesno(
                "Warning: Not in Virtual Machine",
                "⚠ No virtual machine detected.\nRunning malware analysis on a REAL system can be dangerous.\nContinue?"
            )
            if not warn:
                self.updateStatus(">", "Analysis cancelled: Not in VM")
                return

        filepath = filedialog.askopenfilename(title="Select EXE", filetypes=[("Executable files", "*.exe")])
        if not filepath:
            self.updateStatus(">", "No file selected.")
            return

        if not isExe(filepath):
            messagebox.showerror("Invalid File", "The file selected is NOT a valid Windows EXE.")
            self.updateStatus(">", "Invalid EXE file selected.")
            return

        threading.Thread(target=self.startAnalysis, args=(filepath,), daemon=True).start()

    def startAnalysis(self, filepath):
        self.loaderRunning = True
        self.startLoader("Running Full Analysis")

        report_path = os.path.splitext(filepath)[0] + "_report.pdf"

        try:
            fullReport = runFullAnalysis(filepath)

            staticResults = fullReport["CombinedResults"]["StaticAnalysis"]

            print(fullReport["CombinedResults"]["DynamicAnalysis"])
            dynamicResults = fullReport["CombinedResults"]["DynamicAnalysis"]
            riskReport = fullReport["RiskReport"]

            self.updateStatus(">", f"Analysis Complete - Risk: {riskReport['rating']} ({riskReport['totalScore']})")

            # gen report
            report = ReportGenerator(filepath, staticResults, dynamicResults, riskReport)
            report.generatePDF(report_path)

        except Exception as e:
            self.updateStatus(">", f"Error during analysis: {e}")
            messagebox.showerror("Analysis Error", str(e))

        finally:
            self.loaderRunning = False
            messagebox.showinfo("Report Generated", f"PDF report saved to:\n{report_path}")
            self.openReport(report_path)

    def startLoader(self, message):
        def animate():
            dots = ""
            while self.loaderRunning:
                dots = dots + "." if len(dots) < 5 else ""
                self.updateStatus(">", f"{message}{dots}")
                time.sleep(0.3)
        threading.Thread(target=animate, daemon=True).start()

    def updateStatus(self, prefix, message):
        if prefix.startswith("==="):
            self.statusMain.config(text=message)
        elif prefix.startswith("="):
            self.statusSub.config(text=message)
        elif prefix.startswith(">"):
            self.statusCurrent.config(text=message)

    def parseOutput(self, text):
        for line in text.splitlines():
            if line.startswith("==="):
                self.updateStatus("===", line)
            elif line.startswith("="):
                self.updateStatus("=", line)
            elif line.startswith(">"):
                self.updateStatus(">", line)
            time.sleep(0.05)

    def openReport(self, report_path):
        if os.path.exists(report_path):
            try:
                os.startfile(report_path)
            except Exception:
                messagebox.showinfo("Report Ready", f"PDF report is ready at:\n{report_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DeepDelverApp(root)
    root.mainloop()
