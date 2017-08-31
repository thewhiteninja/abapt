from modules.logger import *
from modules.utils import *


class Thread(object):
    def __init__(self, thread_id, thread_handle, start_address=None):
        self._owner = None
        self._thread_id = thread_id
        self._thread_handle = thread_handle
        self._start_address = start_address

    @property
    def thread_id(self):
        return self._thread_id

    @property
    def thread_handle(self):
        return self._thread_handle

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, p):
        self._owner = p

    @property
    def start_address(self):
        if self._start_address is None:
            res = ULONG()
            windll.ntdll.NtQueryInformationThread(self.thread_handle,
                                                  ThreadInformationClass.ThreadQuerySetWin32StartAddress, byref(res),
                                                  sizeof(res))
            self._start_address = res.value
        return self._start_address

    def wait(self, timeout=WaitObject.INFINITE):
        wait_code = windll.kernel32.WaitForSingleObject(self._thread_handle, timeout.value)
        if wait_code == WaitObject.WAIT_TIMEOUT.value:
            return None
        elif wait_code == WaitObject.WAIT_OBJECT_0.value:
            sys.stdout.flush()
            exitcode = DWORD()
            windll.kernel32.GetExitCodeThread(self._thread_handle, byref(exitcode))
            return exitcode.value
        return None

    def terminate(self, code=0):
        ret = windll.kernel32.TerminateThread(self.thread_handle, code)
        if ret == 0:
            raise_windows_error("Unable to terminate thread (id=%x)" % self.thread_id)

    def resume(self):
        ret = windll.kernel32.ResumeThread(self.thread_handle)
        if ret == 0:
            raise_windows_error("Unable to resume thread (id=%x)" % self.thread_id)

    def suspend(self):
        ret = windll.kernel32.SuspendThread(self.thread_handle)
        if ret == 0:
            raise_windows_error("Unable to suspend thread (id=%x)" % self.thread_id)

    def set_context(self, ctx):
        log_debug("Set context 0x%x" % self._thread_handle)
        if self._owner.bitness == BinaryType.SCS_32BIT_BINARY.value and python64():
            ret = windll.kernel32.Wow64SetThreadContext(self._thread_handle, byref(ctx))
        else:
            ret = windll.kernel32.SetThreadContext(self._thread_handle, byref(ctx))
        if ret == 0:
            raise_windows_error("Unable to set context for thread handle %d" % self._thread_handle)

    def get_context(self):
        context = None
        log_debug("Get context 0x%x" % self._thread_handle)

        if self._owner.bitness == BinaryType.SCS_32BIT_BINARY.value:
            if python64():
                context = CONTEXT_WOW64()
                context.ContextFlags = ContextType.CONTEXT_ALL.value
                ret = windll.kernel32.Wow64GetThreadContext(self._thread_handle, byref(context))
            else:
                context = CONTEXT32()
                context.ContextFlags = ContextType.CONTEXT_ALL.value
                ret = windll.kernel32.GetThreadContext(self._thread_handle, byref(context))
        elif self._owner.bitness == BinaryType.SCS_64BIT_BINARY.value:
            context = CONTEXT64()
            context.ContextFlags = ContextType.CONTEXT_ALL.value
            ret = windll.kernel32.GetThreadContext(self._thread_handle, byref(context))
        else:
            raise Exception("Unsupported processus bitness")

        if ret == 0:
            raise_windows_error("Unable to get context for thread handle %d" % self._thread_handle)

        return context


class ThreadList(object):
    def __init__(self, owner):
        self._owner = owner
        self._threads = []

    def add(self, th):
        if self.get_by_id(th.thread_id) is None:
            th.owner = self._owner
            self._threads.append(th)

    def get_by_id(self, thread_id):
        for th in self._threads:
            if th.thread_id == thread_id:
                return th
        return None

    def remove(self, thread_id):
        t = self.get_by_id(thread_id)
        if t is not None:
            self._threads.remove(t)
        return t

    def __getitem__(self, item):
        return self._threads[item]

    @property
    def count(self):
        return len(self._threads)
