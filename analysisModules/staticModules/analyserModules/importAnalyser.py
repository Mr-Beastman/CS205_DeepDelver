
class ImportAnalyzer:
    """
    Analyzes extracted PE imports:
    - Categorizes APIs (registry, network, process, etc.)
    - Flags suspicious ones
    - Provides category summary and suspicious indicators
    """

    API_CATEGORIES = {
        "process_memory": [
            "VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory",
            "CreateRemoteThread", "CreateThread", "VirtualProtect", "OpenProcess",
            "GetProcAddress", "LoadLibrary", "LoadLibraryEx"
        ],

        # Execution-related / launching processes
        "execution": [
            "ShellExecute", "ShellExecuteEx", "CreateProcess", "CreateProcessW", "WinExec",
            "system", "ExitProcess"
        ],

        # Registry operations
        "registry": [
            "RegCreateKey", "RegCreateKeyEx", "RegOpenKey", "RegOpenKeyEx",
            "RegSetValue", "RegSetValueEx", "RegDeleteKey", "RegDeleteValue",
            "RegQueryValue", "RegQueryValueEx", "RegEnumKey", "RegEnumValue"
        ],

        # Privilege escalation
        "privilege": [
            "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValue",
            "GetTokenInformation"
        ],

        # Network / HTTP / sockets
        "network": [
            "URLDownloadToFile", "InternetConnect", "HttpSendRequest",
            "WSASocket", "connect", "send", "recv"
        ],

        # Clipboard / key logging / input
        "clipboard_input": [
            "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx", "OpenClipboard",
            "SetClipboardData", "CloseClipboard", "EmptyClipboard"
        ],

        # GUI / mention category (common UI)
        "mention": [
            # KERNEL32.dll
            "CreateFile", "ReadFile", "WriteFile", "CloseHandle", "SetFilePointer",
            "GetFileSize", "CopyFile", "MoveFile", "DeleteFile", "CreateDirectory",
            "RemoveDirectory", "GetModuleHandle", "GetModuleFileName", "LoadLibrary",
            # USER32.dll
            "CreateWindowEx", "DispatchMessage", "DrawText", "MessageBox",
            "GetDlgItem", "SetWindowText", "SendMessage", "BeginPaint", "EndPaint",
            "DefWindowProc", "InvalidateRect", "EnableWindow", "GetDC", "ReleaseDC",
            # GDI32.dll
            "SelectObject", "SetBkMode", "SetBkColor", "SetTextColor", "DeleteObject",
            "CreateFontIndirect", "CreateBrushIndirect", "GetDeviceCaps"
        ],

        # Anti-analysis / debugger checks
        "be_aware": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
            "NtQueryInformationProcess"
        ]
    }

    def __init__(self, imports: dict):
        self.imports = imports
        self.categorized = {}
        self.suspicious = {}

    def categorize_imports(self) -> dict[str, list[tuple[str, str]]]:
        categorized = {cat: [] for cat in self.API_CATEGORIES.keys()}
        categorized["uncategorized"] = []

        for dll, funcs in self.imports.items():
            for func in funcs:
                matched = False
                for cat, api_list in self.API_CATEGORIES.items():
                    if any(api.lower() in func.lower() for api in api_list):
                        categorized[cat].append((dll, func))
                        matched = True
                        break
                if not matched:
                    categorized["uncategorized"].append((dll, func))
        self.categorized = categorized
        return categorized

    def getNotableApis(self) -> dict[str, list[str]]:
        notableApis = [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "URLDownloadToFile", "InternetConnect", "HttpSendRequest",
            "IsDebuggerPresent", "AdjustTokenPrivileges", "SetWindowsHookEx",
            "GetAsyncKeyState"
        ]

        flagged = {}
        for dll, funcs in self.imports.items():
            hits = [f for f in funcs if any(s.lower() in f.lower() for s in notableApis)]
            if hits:
                flagged[dll] = hits
        self.suspicious = flagged
        return flagged

    def summarize(self) -> dict[str, any]:
        if not self.categorized:
            self.categorize_imports()
        if not self.suspicious:
            self.getNotableApis()

        summary = {cat: len(funcs) for cat, funcs in self.categorized.items() if funcs}
        return {
            "categorys": summary,
            "suspicious": self.suspicious,
            "total": sum(summary.values())
        }