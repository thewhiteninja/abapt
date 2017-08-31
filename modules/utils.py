import glob
import hashlib
import math
import os
import platform
import sys
import time
from ctypes import util

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from modules.constants import *


def check_signature(filename):
    file_data = WINTRUST_FILE_INFO()
    file_data.cbStruct = sizeof(WINTRUST_FILE_INFO)
    file_data.pcwszFilePath = filename
    file_data.hFile = None
    file_data.pgKnownSubject = None

    wvt_policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2

    win_trust_data = WINTRUST_DATA()
    win_trust_data.cbStruct = sizeof(WINTRUST_DATA)
    win_trust_data.pPolicyCallbackData = None
    win_trust_data.pSIPClientData = None
    win_trust_data.dwUIChoice = WinTrustUIChoice.WTD_UI_NONE.value
    win_trust_data.fdwRevocationChecks = WinTrustRevocationChecks.WTD_REVOKE_NONE.value
    win_trust_data.dwUnionChoice = WinTrustUnionChoice.WTD_CHOICE_FILE.value
    win_trust_data.dwStateAction = WinTrustStateAction.WTD_STATEACTION_VERIFY.value
    win_trust_data.hWVTStateData = None
    win_trust_data.pwszURLReference = None
    win_trust_data.dwUIContext = 0
    win_trust_data.tmp_union.pFile = pointer(file_data)

    ret = windll.wintrust.WinVerifyTrust(None, byref(wvt_policy_guid), byref(win_trust_data))

    win_trust_data.dwStateAction = WinTrustStateAction.WTD_STATEACTION_CLOSE.value
    windll.wintrust.WinVerifyTrust(None, byref(wvt_policy_guid), byref(win_trust_data))

    return ret


# TODO
def extract_pkcs7(fname):
    pass


def align(number, value=16):
    if number % value:
        return number + (value - (number % value))
    else:
        return number


def find_python_lib():
    python_lib = "python{0}{1}.dll".format(sys.version_info.major, sys.version_info.minor)
    return util.find_library(python_lib)


def find_lib(lib_name):
    return util.find_library(lib_name)


def format_error(code):
    return FormatError(code).replace(u"\u2018", "'").replace(u"\u2019", "'")


def get_proc_address(dll_name, function_name):
    h_kernel32 = windll.kernel32.GetModuleHandleA(dll_name.encode())
    if h_kernel32 == 0:
        raise_windows_error("Unable get kernel32.dll base address")
    h_loadlib = windll.kernel32.GetProcAddress(h_kernel32, function_name.encode())
    if h_loadlib == 0:
        raise_windows_error("Unable get LoadLibraryA function address")
    return h_loadlib


def raise_windows_error(msg, code=None):
    err_code = 0
    if code is None:
        err_code = windll.kernel32.GetLastError()
    else:
        err_code = code
    raise Exception(
        "%s (Error: %d:%s)" % (msg, err_code, FormatError(err_code)))


def set_debug_privileges():
    token_hande = HANDLE()
    luid = LUID()
    token_state = TOKEN_PRIVILEGES()
    if not windll.advapi32.OpenProcessToken(windll.kernel32.GetCurrentProcess(),
                                            Token.TOKEN_ADJUST_PRIVILEGES.value | Token.TOKEN_QUERY.value,
                                            byref(token_hande)):
        raise_windows_error("OpenProcessToken")
    else:
        if not windll.advapi32.LookupPrivilegeValueA(0, b"seDebugPrivilege", byref(luid)):
            raise_windows_error("LookupPrivilegeValue")
        else:
            token_state.PrivilegeCount = 1
            token_state.Privileges[0].Luid = luid
            token_state.Privileges[0].Attributes = AjustPrivilege.SE_PRIVILEGE_ENABLED.value
            if not windll.advapi32.AdjustTokenPrivileges(token_hande, 0, byref(token_state), 0, 0, 0):
                raise_windows_error("AdjustTokenPrivileges")
        windll.kernel32.CloseHandle(token_hande)


def get_page_size():
    system_info = SYSTEM_INFO()
    windll.kernel32.GetSystemInfo(byref(system_info))
    return system_info.dwPageSize


def is_executable(exe):
    if exe == "" or exe is None:
        return False
    if not os.path.isfile(exe):
        return False
    if not os.access(exe, os.X_OK):
        return False
    return True


def get_binary_type(path):
    binary_type = c_ulong(0)
    windll.kernel32.GetBinaryTypeA(c_char_p(path.encode()), byref(binary_type))
    return binary_type.value


def read_file(h_file, size):
    c_read = DWORD()
    buffer = create_string_buffer(2001)
    ret = windll.kernel32.ReadFile(h_file, buffer, size, byref(c_read), None)
    if ret == 0:
        raise_windows_error("Unable to read file")
    buffer[c_read.value] = 0x00
    return buffer


def get_binary_type_from_mem(m):
    e_lfanew = struct.unpack("<L", m[0x3c:0x40])[0]
    opt_header = e_lfanew + 0x18
    magic = struct.unpack("<H", m[opt_header:opt_header + 2])[0]
    if magic == 0x10b:
        return BinaryType.SCS_32BIT_BINARY.value
    elif magic == 0x20b:
        return BinaryType.SCS_64BIT_BINARY.value
    raise Exception("ROM binary type is not supported")


def get_raw_disassembler(arch, detailed=True):
    if arch == BinaryType.SCS_32BIT_BINARY.value:
        d = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == BinaryType.SCS_64BIT_BINARY.value:
        d = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        raise Exception("No disassembler for this architecture")
    d.detail = detailed
    return d


def is_os64():
    return "PROGRAMFILES(X86)" in os.environ


def python64():
    return platform.architecture()[0] == "64bit"


def welcome():
    print("Starting %s at %s (%s version)\n" % (
        os.path.basename(sys.argv[0]), time.asctime(time.localtime(time.time())), platform.architecture()[0]))


def humansize(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    if nbytes == 0:
        return '0 B'
    i = 0
    while nbytes >= 1024 and i < len(suffixes) - 1:
        nbytes /= 1024.
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])


def hash_mem(mem):
    h = dict()
    a = hashlib.md5()
    a.update(mem)
    h["md5"] = a.hexdigest()
    a = hashlib.sha1()
    a.update(mem)
    h["sha1"] = a.hexdigest()
    a = hashlib.sha256()
    a.update(mem)
    h["sha256"] = a.hexdigest()
    return h


def xor(data, key):
    return bytearray(a ^ key for a in data)


def clean_folder(directory):
    for f in glob.glob(directory + '/*'):
        os.remove(f)


def entropy(data):
    if not data:
        return 0
    ent = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            ent += - p_x * math.log(p_x, 2)
    return ent
