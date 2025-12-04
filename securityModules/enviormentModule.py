import subprocess
import re


### Functions related to checking enviroment for virtual machine.

def getWmicValue(propertyName:str) -> str:
    #docString
    """
    Get WMIC value for supplied property
    
    Parameters:
        propertyName (str): property requsted e.g Manufacturer/Model

    Returns:
        str: value of the requested property
    """
    try:
        output = subprocess.check_output(
            f"wmic computersystem get {propertyName} /value",
            shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        match = re.search(rf"{propertyName}=(.*)", output)
        return match.group(1).strip() if match else ""
    except Exception:
        return ""


def isVirtualMachine() -> bool:
    #docString
    """
    Detect if running inside a VM on Windows.
    
    Parameters:
        None

    Returns:
        Bool : True of False vmSignatures found in Wmic values
    """
    manufacturer = getWmicValue("Manufacturer").lower()
    model = getWmicValue("Model").lower()

    #popular Virtual Machines
    vmSignatures = [
        "vmware", "virtualbox", "qemu", "xen", "parallels", "virtual machine"
    ]

    vmInManufacturer = any(sig in manufacturer for sig in vmSignatures)
    vmInModel = any(sig in model for sig in vmSignatures)

    return vmInManufacturer or vmInModel

