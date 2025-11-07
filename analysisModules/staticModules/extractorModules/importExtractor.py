import pefile

class ImportExtractor:
    
    def __init__(self, filePath:str):
        self.filePath = filePath  
        self.suspiciousAPI = [
            "VirtualAllocEx", 
            "WriteProcessMemory", 
            "CreateRemoteThread",
            "SetWindowsHookEx", 
            "GetAsyncKeyState", 
            "URLDownloadToFile",
            "WinExec", 
            "ShellExecute", 
            "InternetConnectA", 
            "HttpSendRequest"
        ]

    def getImports(self) -> dict:
        #docString
        """
        
        """
        print("> Checking for Suspicious APIs")
        
        imports = {}

        try:
            pe = pefile.PE(self.filePath)

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="ignore")
                    function_names = []
                    for imp in entry.imports:
                        if imp.name:
                            function_names.append(imp.name.decode(errors="ignore"))
                        else:
                            function_names.append(f"Ordinal_{imp.ordinal}")
                    imports[dll_name] = function_names
            else:
                imports["None"] = ["No imports found"]

        except Exception as error:
            imports["Error"] = [str(error)]

        return imports