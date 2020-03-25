from modules.breakpoints import *
from modules.process import *
from modules.thread import *
from modules.utils import *


class DebuggedProcessModule(object):
    def __init__(self, base, name):
        self.__base = base
        self.__name = name

    @property
    def base(self):
        return self.__base

    @property
    def name(self):
        return self.__name


class DebuggedProcessList(object):
    def __init__(self):
        self.__processes = []

    def add(self, p):
        if self.get_by_id(p.process_id) is None:
            self.__processes.append(p)

    def remove(self, process_id):
        p = self.get_by_id(process_id)
        if p is not None:
            self.__processes.remove(p)
        return p

    def get_by_id(self, process_id):
        for p in self.__processes:
            if p.process_id == process_id:
                return p
        return None

    def __getitem__(self, item):
        return self.__processes[item]

    @property
    def count(self):
        return len(self.__processes)


class DebuggedProcess(Process):
    def __init__(self, filename):
        Process.__init__(self, filename)

        self.__next_debug_register = DebugRegister.DR0.value
        self._breakpoints = dict()

        self._current_process = None
        self._current_thread = None

        self._processes = DebuggedProcessList()

        self.on_debug_start = None

        set_debug_privileges()

    @staticmethod
    def from_createprocess_event(ev):
        p = DebuggedProcess(None)
        p._process_handle = ev.hProcess
        p._process_id = windll.kernel32.GetProcessId(ev.hProcess)

        image_mem = read_file(ev.hFile, 2000)
        p._bitness = get_binary_type_from_mem(image_mem)
        if ev.lpImageName is not None:
            p._filename = p.read_string(p.dereference(ev.lpImageName), ev.fUnicode)
        return p

    @property
    def breakpoints(self):
        return self._breakpoints

    @property
    def processes(self):
        return self._processes

    def add_software_breakpoint(self, address, handler=None):
        if address not in self._breakpoints:
            original_byte = self.read_memory(address, 1)
            bp = SoftwareBreakpoint(address, handler, original_byte)
            self.breakpoints[address] = bp
            self.write_memory(bp.address, INT3)
            log_debug("Breakpoint at %08x added" % address)
            return bp
        else:
            raise Exception("Breakpoint already exists at address %08x" % address)

    def add_memory_breakpoint(self, address, handler=None, access=MemoryBreakPointAccess.ON_READ, size=1):
        if address not in self._breakpoints:
            bp = MemoryBreakpoint(address, handler, access, size)

            mbi = MEMORY_BASIC_INFORMATION()
            ret = windll.kernel32.VirtualQueryEx(self._process_handle, address, byref(mbi), sizeof(mbi))
            if ret < sizeof(mbi):
                raise_windows_error("Unable to query memory information")

            current_page = mbi.BaseAddress
            page_size = get_page_size()
            while current_page < address + size:
                old_protection = c_ulong(0)
                ret = windll.kernel32.VirtualProtectEx(self._process_handle, current_page, size,
                                                       mbi.Protect | MemoryPermission.PAGE_GUARD, byref(old_protection))
                if ret == 0:
                    raise_windows_error("Unable to set memory breakpoint")
                current_page += page_size

            self.breakpoints[address] = bp
            log_debug("Breakpoint at %08x added" % address)
            return bp
        else:
            raise Exception("Breakpoint already exists at address %08x" % address)

    def add_hardware_breakpoint(self, address, handler=None, access=HardwareBreakPointAccess.ON_CODE,
                                size=HardwareBreakPointSize.SIZE_4):
        if address not in self._breakpoints:
            if self.__next_debug_register < DebugRegister.DR_MAX.value:
                bp = HardwareBreakpoint(address, handler, access, size)
                bp.register = self.__next_debug_register
                self.__next_debug_register += 1
                self.breakpoints[address] = bp
                return bp
            else:
                raise Exception("Maximum hardware breakpoints reached (4)")
        else:
            raise Exception("Breakpoint already exists at address %08x" % address)

    def _callback(self, cb):
        if cb is not None:
            kwargs = {"ctx": self._current_thread.get_context(), "process": self}
            updated_ctx = cb(**kwargs)
            self._current_thread.set_context(updated_ctx)

    def run(self, arguments=None, flags=0):
        flags += CreationFlag.DEBUG_PROCESS.value
        if not is_executable(self.filename):
            raise Exception("File does not seem to be executable")
        if not python64() and self.bitness == BinaryType.SCS_64BIT_BINARY.value:
            raise_windows_error("Unable create 64bit process using Python 32bit")

        pi = ProcessInfo()
        si = StartupInfo()
        if not windll.kernel32.CreateProcessA(
                c_char_p(0),
                c_char_p((self.filename + ("" if arguments is None else (" " + arguments))).encode('utf-8')),
                0, 0, False, flags, 0, 0, byref(si), byref(pi)):
            raise_windows_error("Unable create debugged process")
        self._process_id = pi.dwProcessId
        self._process_handle = pi.hProcess
        self._threads.add(Thread(pi.dwThreadId, pi.hThread))

        debug = DEBUG_EVENT()
        first_breakpoint = 0
        first_module = True
        while True:
            self.flush_instruction_cache()
            if windll.kernel32.WaitForDebugEvent(byref(debug), 100):
                if debug.dwDebugEventCode == DebugEvent.EXCEPTION_DEBUG_EVENT.value:
                    exception_code = debug.u.Exception.ExceptionRecord.ExceptionCode
                    exception_address = debug.u.Exception.ExceptionRecord.ExceptionAddress
                    self._current_process = self._processes.get_by_id(debug.dwProcessId)
                    self._current_thread = self._threads.get_by_id(debug.dwThreadId)
                    if exception_code == DebugExceptionCode.EXCEPTION_BREAKPOINT.value:
                        if first_breakpoint == 0:
                            log_debug("First exception: %08x" % exception_address)
                            first_breakpoint = exception_address
                            self._callback(self.on_debug_start)
                        else:
                            if exception_address != first_breakpoint:
                                log_debug("Breakpoint at %08x triggered" % exception_address)
                                if exception_address in self.breakpoints:
                                    bp = self.breakpoints[exception_address]
                                    self._callback(bp.handler)
                                    self.write_memory(bp.address, bp.original_byte)
                                    self.flush_instruction_cache()
                                else:
                                    log_debug("Unexpected breakpoint at %08x" % exception_address)
                    elif exception_code == DebugExceptionCode.EXCEPTION_WX86_BREAKPOINT.value:
                        log_debug("WOW64 initialized")
                    else:
                        log_warn('Crash: exception code : 0x%x at %08x' % (
                            debug.u.Exception.ExceptionRecord.ExceptionCode,
                            debug.u.Exception.ExceptionRecord.ExceptionAddress))
                        return
                elif debug.dwDebugEventCode == DebugEvent.EXIT_PROCESS_DEBUG_EVENT.value:
                    log_debug("Process exited with code: 0x%x" % debug.u.ExitProcess.dwExitCode)
                    self._processes.remove(debug.dwProcessId)
                    if debug.dwProcessId == self._process_id:
                        break
                elif debug.dwDebugEventCode == DebugEvent.CREATE_THREAD_DEBUG_EVENT.value:
                    log_debug("New thread: Handle %d starting at %08x" % (
                        debug.u.CreateThread.hThread, debug.u.CreateThread.lpStartAddress))
                    self._threads.add(
                        Thread(windll.kernel32.GetThreadId(debug.u.CreateThread.hThread), debug.u.CreateThread.hThread))
                elif debug.dwDebugEventCode == DebugEvent.CREATE_PROCESS_DEBUG_EVENT.value:
                    log_debug("New process: PID %d starting at %08x" % (
                        debug.dwProcessId, debug.u.CreateProcessInfo.lpStartAddress))
                    self._processes.add(DebuggedProcess.from_createprocess_event(debug.u.CreateProcessInfo))
                    if debug.u.CreateProcessInfo.hFile:
                        windll.kernel32.CloseHandle(debug.u.CreateProcessInfo.hFile)
                elif debug.dwDebugEventCode == DebugEvent.EXIT_THREAD_DEBUG_EVENT.value:
                    log_debug("Thread exited with code: 0x%x" % debug.u.ExitThread.dwExitCode)
                    self._threads.remove(debug.dwThreadId)
                elif debug.dwDebugEventCode == DebugEvent.LOAD_DLL_DEBUG_EVENT.value:
                    mod_base = debug.u.LoadDll.lpBaseOfDll
                    mod_name = "unknown"
                    if first_module:
                        mod_name = "ntdll.dll"
                        first_module = False
                    else:
                        if debug.u.LoadDll.lpImageName is not None:
                            mod_name = self.read_string(self.dereference(debug.u.LoadDll.lpImageName), debug.u.LoadDll.fUnicode)
                    log_debug("Dll loaded: %s at %08x" % (mod_name, mod_base))
                    if debug.u.LoadDll.hFile:
                        windll.kernel32.CloseHandle(debug.u.LoadDll.hFile)
                elif debug.dwDebugEventCode == DebugEvent.UNLOAD_DLL_DEBUG_EVENT.value:
                    log_debug("Dll unloaded: %08x" % debug.u.UnloadDll.lpBaseOfDll)
                elif debug.dwDebugEventCode == DebugEvent.OUTPUT_DEBUG_STRING_EVENT.value:
                    log_info("Debug string: %s" % (self.read_string(
                        debug.u.DebugString.lpDebugStringData, debug.u.DebugString.fUnicode,
                        debug.u.DebugString.nDebugStringLength)))
                elif debug.dwDebugEventCode == DebugEvent.RIP_EVENT.value:
                    log_debug("RIP event not implemented")
                elif debug.dwDebugEventCode == DebugEvent.USER_CALLBACK_DEBUG_EVENT.value:
                    log_debug("USER_CALLBACK event not implemented")
                else:
                    log_debug("Debug event not implemented")
            windll.kernel32.ContinueDebugEvent(
                debug.dwProcessId, debug.dwThreadId, ContinueStatus.DBG_CONTINUE.value)
        windll.kernel32.TerminateProcess(self._process_handle, -1)
        windll.kernel32.CloseHandle(self._process_handle)
