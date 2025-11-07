import tkinter as tk
from tkinter import filedialog
import threading
import time
import os
import sys
import io

from analysisModules.staticModules.controllerModule.staticController import StaticController


class DeepDelverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DeepDelver Malware Analysis")

        # Layout
        tk.Label(root, text="DeepDelver Malware Analysis", font=("Arial", 16, "bold")).pack(pady=10)

        self.selectButton = tk.Button(root, text="Select EXE & Start Analysis", command=self.selectFile)
        self.selectButton.pack(pady=10)

        # status display
        self.statusMain = tk.Label(root, text="=== Main: Waiting ===", fg="#e67e22", font=("Consolas", 12, "bold"))
        self.statusMain.pack(pady=(10, 2))

        self.statusSub = tk.Label(root, text="= Sub: Idle =", fg="#3498db", font=("Consolas", 11))
        self.statusSub.pack(pady=2)

        self.statusCurrent = tk.Label(root, text="> Ready >", fg="#2ecc71", font=("Consolas", 10))
        self.statusCurrent.pack(pady=5)

        self.loaderRunning = False

    
    def selectFile(self):
        filepath = filedialog.askopenfilename(title="Select EXE", filetypes=[("Executable files", "*.exe")])
        if not filepath:
            self.updateStatus(">", "No file selected.")
            return

        thread = threading.Thread(target=self.startAnalysis, args=(filepath,))
        thread.start()

    # start analys
    ## hardcoded to static for testing
    def startAnalysis(self, filepath):
        self.loaderRunning = True
        self.startLoader("Loading File")

        oldStdout = sys.stdout
        sys.stdout = io.StringIO()

        try:
            analyzer = StaticController(filepath)
            analyzer.runStaticAnalysis()

        except Exception as e:
            self.updateStatus(">", f"Error during analysis: {e}")

        finally:
            # Capture and parse output
            output = sys.stdout.getvalue()
            sys.stdout = oldStdout
            self.loaderRunning = False

            self.parseOutput(output)
            self.updateStatus(">", f"Analysis complete: {os.path.basename(filepath)}")

    # clean up stdout txt and displaying correctly
    def parseOutput(self, text):
        """Parse lines and update each of the 3 status labels appropriately."""
        for line in text.splitlines():
            if line.startswith("==="):
                self.updateStatus("===", line)
            elif line.startswith("="):
                self.updateStatus("=", line)
            elif line.startswith(">"):
                self.updateStatus(">", line)
            time.sleep(0.05)

    # loading animation
    def startLoader(self, message):
        def animate():
            dots = ""
            while self.loaderRunning:
                dots = dots + "." if len(dots) < 5 else ""
                self.updateStatus(">", f"{message}{dots}")
                time.sleep(0.3)
        threading.Thread(target=animate, daemon=True).start()

    # update status lines
    def updateStatus(self, prefix, message):
        """Send updates to the correct status line based on message prefix."""
        if prefix.startswith("==="):
            self.statusMain.config(text=message)
        elif prefix.startswith("="):
            self.statusSub.config(text=message)
        elif prefix.startswith(">"):
            self.statusCurrent.config(text=message)


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("600x300")
    app = DeepDelverApp(root)
    root.mainloop()
