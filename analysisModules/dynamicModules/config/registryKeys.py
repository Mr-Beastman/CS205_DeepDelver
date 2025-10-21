# Registry keys to monitor

from winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER

persistanceKeys = [
    (HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

serviceKeys = [
    (HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services"),
]

installKeys = [
    (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

powershellKeys = [
    (HKEY_LOCAL_MACHINE, r"Software\Microsoft\PowerShell"),
    (HKEY_CURRENT_USER,  r"Software\Microsoft\PowerShell"),
]

# A combined list for default monitor settings.
defaultKeys = (
    persistanceKeys +
    serviceKeys +
    installKeys +
    powershellKeys +
    [(HKEY_LOCAL_MACHINE, r"Software\DeepDelverTest")]  # dev and testing
)
