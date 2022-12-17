""" Reads UEFI environment variables (Windows only)

    SeSystemEnvironmentPrivilege is required to read variables from NVRAM, hence the script
    calls AdjustTokenPrivileges(). Make sure the python interpreter is allowed to assign
    priviledges; launching a cmd instance "as Administrator" to run the script should do the trick.
    

    :Copyright:
        Ry Auscitte 2022. This script is distributed under MIT License.
    
    :Authors:
        Ry Auscitte
"""


from ctypes import windll, wintypes, POINTER, byref, Structure, sizeof, create_string_buffer
import sys
import re


#Copying prototypes and defintions from WinAPI headers, a process known for its therapeutic effects
class LUID(Structure):
    _fields_ = [ ("LowPart", wintypes.DWORD), 
                 ("HighPart", wintypes.LONG) ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [ ("PrivilegeCount", wintypes.DWORD),
                 ("Luid", LUID),
                 ("Attributes", wintypes.DWORD) ]

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [ wintypes.HANDLE,
                              wintypes.DWORD,
                              POINTER(wintypes.HANDLE) ]
OpenProcessToken.restype = wintypes.BOOL

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

LookupPrivilegeValue = windll.advapi32.LookupPrivilegeValueW
LookupPrivilegeValue.argtypes = [ wintypes.LPCWSTR,
                                  wintypes.LPCWSTR,
                                  POINTER(LUID) ]
LookupPrivilegeValue.restype = wintypes.BOOL

AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [ wintypes.HANDLE,
                                   wintypes.BOOL,
                                   POINTER(TOKEN_PRIVILEGES),
                                   wintypes.DWORD,
                                   POINTER(TOKEN_PRIVILEGES),
                                   POINTER(wintypes.DWORD) ]
AdjustTokenPrivileges.restype = wintypes.BOOL

GetFirmwareEnvironmentVariable = windll.kernel32.GetFirmwareEnvironmentVariableW
GetFirmwareEnvironmentVariable.argtypes = [ wintypes.LPCWSTR,
                                            wintypes.LPCWSTR,
                                            wintypes.LPVOID,
                                            wintypes.DWORD ]
GetFirmwareEnvironmentVariable.restype = wintypes.DWORD


#Reading UEFI variables from NVRAM requires SeSystemEnvironmentPrivilege
def enable_SeSystemEnvironmentPrivilege():
    hProc = windll.kernel32.GetCurrentProcess()
    hToken = wintypes.HANDLE()
    if not OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, byref(hToken)):
        print("OpenProcessToken() failed with the error code", windll.kernel32.GetLastError())
        return False

    luid = LUID()
    if not LookupPrivilegeValue(None, "SeSystemEnvironmentPrivilege", byref(luid)):
        print("LookupPrivilegeValue() failed with the error code", windll.kernel32.GetLastError())
        windll.kernel32.CloseHandle(hToken)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Attributes = SE_PRIVILEGE_ENABLED
    tp.Luid.HighPart = luid.HighPart
    tp.Luid.LowPart = luid.LowPart

    if not AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(TOKEN_PRIVILEGES), None, None):
        print("AdjustTokenPrivileges() failed with the error code", windll.kernel32.GetLastError())
        windll.kernel32.CloseHandle(hToken)
        return False

    windll.kernel32.CloseHandle(hToken)
    return True


EFI_IMAGE_SECURITY_DATABASE_GUID = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"
EFI_GLOBAL_VARIABLE = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
Variables2Namespaces = { "db": EFI_IMAGE_SECURITY_DATABASE_GUID,
                         "dbx" : EFI_IMAGE_SECURITY_DATABASE_GUID,
                         "dbt" : EFI_IMAGE_SECURITY_DATABASE_GUID,
                         "dbr" : EFI_IMAGE_SECURITY_DATABASE_GUID,
                         "AuditMode" : EFI_GLOBAL_VARIABLE,
                         "BootCurrent" : EFI_GLOBAL_VARIABLE,
                         "Boot[0-9,a-f,A-F]{4}" : EFI_GLOBAL_VARIABLE,
                         "BootNext" : EFI_GLOBAL_VARIABLE,
                         "BootOrder" : EFI_GLOBAL_VARIABLE,
                         "BootOptionSupport" : EFI_GLOBAL_VARIABLE,
                         "ConIn" : EFI_GLOBAL_VARIABLE,
                         "ConInDev" : EFI_GLOBAL_VARIABLE,
                         "ConOut" : EFI_GLOBAL_VARIABLE,
                         "ConOutDev" : EFI_GLOBAL_VARIABLE,
                         "CryptoIndications" : EFI_GLOBAL_VARIABLE,
                         "CryptoIndicationsSupported" : EFI_GLOBAL_VARIABLE,
                         "CryptoIndicationsActivated" : EFI_GLOBAL_VARIABLE,
                         "dbDefault" : EFI_GLOBAL_VARIABLE,
                         "dbrDefault" : EFI_GLOBAL_VARIABLE,
                         "dbtDefault" : EFI_GLOBAL_VARIABLE,
                         "dbxDefault" : EFI_GLOBAL_VARIABLE,
                         "DeployedMode" : EFI_GLOBAL_VARIABLE,
                         "devAuthBoot" : EFI_GLOBAL_VARIABLE,
                         "devdbDefault" : EFI_GLOBAL_VARIABLE,
                         "Driver[0-9,a-f,A-F]{4}" : EFI_GLOBAL_VARIABLE,
                         "DriverOrder" : EFI_GLOBAL_VARIABLE,
                         "ErrOut" : EFI_GLOBAL_VARIABLE,
                         "ErrOutDev" : EFI_GLOBAL_VARIABLE,
                         "HwErrRecSupport" : EFI_GLOBAL_VARIABLE,
                         "KEK" : EFI_GLOBAL_VARIABLE,
                         "KEKDefault" : EFI_GLOBAL_VARIABLE,
                         "Key[0-9,a-f,A-F]{4}" : EFI_GLOBAL_VARIABLE,
                         "Lang" : EFI_GLOBAL_VARIABLE,
                         "LangCodes" : EFI_GLOBAL_VARIABLE,
                         "OsIndications" : EFI_GLOBAL_VARIABLE,
                         "OsIndicationsSupported" : EFI_GLOBAL_VARIABLE,
                         "OsRecoveryOrder" : EFI_GLOBAL_VARIABLE,
                         "PK" : EFI_GLOBAL_VARIABLE,
                         "PKDefault" : EFI_GLOBAL_VARIABLE,
                         "PlatformLangCodes" : EFI_GLOBAL_VARIABLE,
                         "PlatformLang" : EFI_GLOBAL_VARIABLE,
                         "PlatformRecovery[0-9,a-f,A-F]{4}" : EFI_GLOBAL_VARIABLE,
                         "SignatureSupport" : EFI_GLOBAL_VARIABLE,
                         "SecureBoot" : EFI_GLOBAL_VARIABLE,
                         "SetupMode" : EFI_GLOBAL_VARIABLE,
                         "SysPrep[0-9,a-f,A-F]{4}" : EFI_GLOBAL_VARIABLE,
                         "SysPrepOrder" : EFI_GLOBAL_VARIABLE,
                         "Timeout" : EFI_GLOBAL_VARIABLE,
                         "VendorKeys" : EFI_GLOBAL_VARIABLE }


def get_namespace(name):
    if name in Variables2Namespaces:
        return Variables2Namespaces[name]

    for k, v in Variables2Namespaces.items():
        if re.search(k, name) == None:
            continue
        return v
    
    return None


def print_usage(args):
    print(args[0], "<variable name> [<path to the output file>]")


def main(args):
    #Many thanks to Carcigenicate and Basj (https://stackoverflow.com/questions/62537058/read-a-uefi-variable-into-a-buffer-with-ctypes-windll-and-winapi-using-getfirm)
    if not enable_SeSystemEnvironmentPrivilege():
        return
    
    ns = get_namespace(args[1])
    if ns is None:
        print("Have never heard of", args[1], "; chances are editing Variables2Namespaces will help.")
        return

    max_size = 2 * 1024 * 1024
    buf = create_string_buffer(max_size)
    ln = GetFirmwareEnvironmentVariable(args[1], ns, buf, max_size)
    if ln == 0:
        print("GetFirmwareEnvironmentVariable() failed with the error code", 
              windll.kernel32.GetLastError())
        return
    
    if len(args) < 3:
        print(buf.raw[0:ln])
    else:
        with open(args[2], "wb") as f:
            f.write(buf.raw[0:ln])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage(sys.argv)
    else:    
        main(sys.argv)
