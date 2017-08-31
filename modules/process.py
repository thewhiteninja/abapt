from modules.thread import *
from modules.utils import python64, get_binary_type, is_executable, raise_windows_error, align, get_proc_address


class Process(object):
    def __init__(self, filename):
        self._filename = filename
        self._process_handle = None
        self._process_id = None
        self._bitness = None
        self._modified_memory = False
        self._threads = ThreadList(self)

    @property
    def filename(self):
        return self._filename

    @property
    def process_id(self):
        return self._process_id

    @property
    def process_handle(self):
        return self._process_handle

    @property
    def bitness(self):
        if self._bitness is None:
            self._bitness = get_binary_type(self.filename)
        return self._bitness

    @property
    def threads(self):
        return self._threads

    def run(self, arguments=None, flags=0):
        if not is_executable(self._filename):
            raise Exception("File does not seem to be executable")
        bintype = get_binary_type(self._filename.encode())
        if not python64() and bintype == BinaryType.SCS_64BIT_BINARY.value:
            raise_windows_error("Unable create 64bit process using Python 32bit")

        pi = ProcessInfo()
        si = StartupInfo()
        if not windll.kernel32.CreateProcessA(
                c_char_p(0),
                c_char_p((self._filename + ("" if arguments is None else (" " + arguments))).encode('utf-8')),
                0, 0, False, flags, 0, 0, byref(si), byref(pi)):
            raise_windows_error("Unable create process")
        self._process_id = pi.dwProcessId
        self._process_handle = pi.hProcess
        self._threads.add(Thread(pi.dwThreadId, pi.hThread))

    def flush_instruction_cache(self):
        if self._modified_memory:
            windll.kernel32.FlushInstructionCache(self.process_handle, 0, 0)
            self._modified_memory = False

    def kill(self):
        windll.kernel32.TerminateProcess(self._process_handle, -1)
        windll.kernel32.CloseHandle(self._process_handle)

    def wait(self, timeout=WaitObject.INFINITE):
        wait_code = windll.kernel32.WaitForSingleObject(self._process_handle, timeout.value)
        if wait_code == WaitObject.WAIT_TIMEOUT.value:
            return None
        elif wait_code == WaitObject.WAIT_OBJECT_0.value:
            sys.stdout.flush()
            exitcode = DWORD()
            windll.kernel32.GetExitCodeProcess(self._process_handle, byref(exitcode))
            return exitcode.value
        return None

    def allocate(self, size, aligned=0):
        if aligned != 0:
            size = align(size, aligned)
        address = windll.kernel32.VirtualAllocEx(self._process_handle, 0, size,
                                                 AllocationType.VIRTUAL_MEM.value,
                                                 MemoryPermission.PAGE_READWRITE.value)
        if address == 0:
            raise_windows_error("Unable allocate memory in remote process")
        return address

    def free(self, address):
        ret = windll.kernel32.VirtualFreeEx(self._process_handle, address, 0, FreeType.MEM_RELEASE.value)
        if ret == 0:
            raise_windows_error("Unable freed memory in remote process")

    def protect_memory(self, address, length, protection):
        old_protection = c_ulong(0)
        p = None
        if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
            windll.kernel32.VirtualProtectEx.argtypes = [
                c_int, c_ulong, c_int, c_long, POINTER(c_ulong)]
            p = windll.kernel32.VirtualProtectEx(self._process_handle, address, length, protection,
                                                 byref(old_protection))
        elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
            windll.kernel32.VirtualProtectEx.argtypes = [
                c_int, c_uint64, c_int, c_long, POINTER(c_ulong)]
            p = windll.kernel32.VirtualProtectEx(self._process_handle, c_uint64(address), length,
                                                 protection,
                                                 byref(old_protection))
        else:
            raise Exception("Unsupported processus bitness")

        if p == 0:
            raise_windows_error("Unable to VirtualProtectEx [%08x-%08x] with protection 0x%08x" % (
                address, address + length, protection))
        return old_protection.value

    def read_memory(self, address, length):
        data = bytes()
        read_buf = create_string_buffer(length)
        if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
            count = c_ulong(0)
        elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
            count = c_int64(0)
        while length:
            r = 0
            if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
                r = windll.kernel32.ReadProcessMemory(self._process_handle, address, read_buf, length,
                                                      byref(count))
            elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
                windll.kernel32.ReadProcessMemory.argtypes = [
                    c_int, c_uint64, c_char_p, c_long, POINTER(c_int64)]
                r = windll.kernel32.ReadProcessMemory(self._process_handle, c_uint64(address), read_buf, length,
                                                      byref(count))
            if r == 0:
                if len(data) == 0:
                    raise_windows_error("Unable to read %d bytes from address %08x" % (length, address))
                else:
                    return data
            data += read_buf.raw
            length -= count.value
            address += count.value
        return data

    def write_memory(self, address, value, force=False):
        if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
            count = c_ulong(0)
        elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
            count = c_int64(0)
        old_protect = 0
        if force:
            old_protect = self.protect_memory(
                address, len(value), MemoryPermission.PAGE_EXECUTE_READWRITE.value)
        tmp_length = len(value)
        while len(value) > 0:
            r = 0
            if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
                r = windll.kernel32.WriteProcessMemory(self._process_handle, address, value, len(value),
                                                       byref(count))
            elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
                windll.kernel32.WriteProcessMemory.argtypes = [
                    c_int, c_uint64, c_char_p, c_long, POINTER(c_int64)]
                r = windll.kernel32.WriteProcessMemory(self._process_handle, c_uint64(address), value, len(value),
                                                       byref(count))
            if r == 0:
                raise_windows_error("Unable to write %d bytes to address %08x" % (len(value), address))
            value = value[count.value:]
        if force:
            self.protect_memory(address, tmp_length, old_protect)
        self._modified_memory = True
        return True

    def dereference(self, address):
        if self.bitness == BinaryType.SCS_32BIT_BINARY.value:
            return struct.unpack("<L", self.read_memory(address, 4))[0]
        elif self.bitness == BinaryType.SCS_64BIT_BINARY.value:
            return struct.unpack("<Q", self.read_memory(address, 8))[0]
        else:
            raise Exception("Unsupported processus bitness")

    def read_string(self, address, wide, max_length=0x1000):
        if address > 0:
            data = self.read_memory(address, max_length)
            if wide:
                data = data.decode('U16', 'replace')
            return data[:data.find("\x00")]
        return None

    def create_thread(self, address, arguments_address):
        thread_id = c_ulong(0)
        h_thread = windll.kernel32.CreateRemoteThread(self._process_handle, None, 0, address, arguments_address,
                                                      0,
                                                      byref(thread_id))
        if h_thread == 0:
            raise_windows_error("Failed to create thread in remote process")
        return Thread(thread_id.value, h_thread)

    def load_library(self, dll_path):
        dll_len = len(dll_path)
        arg_address = self.allocate(dll_len + 1)
        self.write_memory(arg_address, dll_path)

        h_loadlib = get_proc_address("kernel32.dll", "LoadLibraryA")
        th = self.create_thread(h_loadlib, arg_address)
        exit_code = th.wait()

        self.free(arg_address)
        if exit_code != 0:
            raise_windows_error("Error during remote thread execution", exit_code)

    @property
    def peb(self):
        process_basic_information = PROCESS_BASIC_INFORMATION()
        returned_length = DWORD()
        ret = windll.ntdll.NtQueryInformationProcess(self._process_handle,
                                                     ProcessInformationQuery.PROCESS_BASIC_INFORMATION.value,
                                                     byref(process_basic_information),
                                                     sizeof(process_basic_information), byref(returned_length))
        if ret != NTStatus.STATUS_SUCCESS.value:
            raise_windows_error("Unable to query information for remote process")

        peb_addr = process_basic_information.PebBaseAddress
        peb = PEB()
        read = DWORD()
        ret = windll.kernel32.ReadProcessMemory(self._process_handle, peb_addr, byref(peb), sizeof(peb),
                                                byref(read))
        if ret == 0:
            raise_windows_error("Unable to read data in remote process")

        return peb
