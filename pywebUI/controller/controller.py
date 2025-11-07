import os
import tempfile
from analysisModules.staticModules.controllerModules.staticController import StaticController

class GUIController:
    def __init__(self):
        self.staticObj = None
        self.window = None

    def setWindow(self, window):
        self.window = window    

    def startAnalysis(self, fileBytes, filename):
        """
        Receives a bytes object (from JS Uint8Array) and runs static analysis.
        """
        tempDir = "./temp"
        os.makedirs(tempDir, exist_ok=True)

        tempPath = None

        try:
            if isinstance(fileBytes, list):
                fileBytes = bytes(fileBytes)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", dir=tempDir) as tempFile:
                tempPath = tempFile.name
                tempFile.write(fileBytes)

            if self.window:
                self.window.evaluate_js("updateStatus('Static analysis started...')")


            self.staticObj = StaticController(tempPath)
            self.staticObj.runStaticAnalysis()
            
            return f"Static analysis finished: {filename}"

        except Exception as error:
            return f"Error during analysis: {error}"