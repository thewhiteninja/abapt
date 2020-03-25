from modules.constants import *


def debugged_cb(f):
    def wrapper(**kwargs):
        ctx = kwargs["ctx"]
        orig_ip = None
        if isinstance(ctx, CONTEXT32):
            orig_ip = ctx.Eip
        elif isinstance(ctx, CONTEXT64):
            orig_ip = ctx.Rip

        f(**kwargs)

        if isinstance(ctx, CONTEXT32):
            if orig_ip == ctx.Eip:
                ctx.Eip -= 1
        elif isinstance(ctx, CONTEXT64):
            if orig_ip == ctx.Rip:
                ctx.Rip -= 1

        return ctx

    return wrapper


class BreakPointType(enum.Enum):
    SOFTWARE_BREAKPOINT = 0
    MEMORY_BREAKPOINT = 1
    HARDWARE_BREAKPOINT = 3


class MemoryBreakPointAccess(enum.Enum):
    ON_EXECUTE = 1
    ON_WRITE = 2
    ON_READ = 4
    ON_READWRITE = 6


class HardwareBreakPointAccess(enum.Enum):
    ON_CODE = 0
    ON_READWRITE = 1
    ON_WRITE = 2


class HardwareBreakPointSize(enum.Enum):
    SIZE_1 = 0
    SIZE_2 = 1
    SIZE_4 = 2
    SIZE_8 = 3


class Breakpoint:
    def __init__(self, bp_type, address, handler):
        self._type = bp_type
        self._address = address
        self._handler = handler

    @property
    def type(self):
        return self._type

    @property
    def address(self):
        return self._address

    @property
    def handler(self):
        return self._handler

    def __str__(self):
        return "%s breakpoint at %08x %s" % (
            ["Software", "Memory", "Hardware"][self._type], self._address, "[handler -> " + self._handler.__name__ if
            self._handler is not None else "")


class SoftwareBreakpoint(Breakpoint):
    def __init__(self, address, handler, original_byte):
        Breakpoint.__init__(self, BreakPointType.SOFTWARE_BREAKPOINT, address, handler)
        self._original_byte = original_byte

    @property
    def original_byte(self):
        return self._original_byte

    @original_byte.setter
    def original_byte(self, b):
        self._original_byte = b


class MemoryBreakpoint(Breakpoint):
    def __init__(self, address, handler, access, size):
        Breakpoint.__init__(self, BreakPointType.MEMORY_BREAKPOINT, address, handler)
        if access in [1, 2, 4, 6]:
            self._access = access
        else:
            raise Exception("Invalid memory breakpoint access: %d" % access)
        if size > 0:
            self._size = size
        else:
            raise Exception("Invalid memory breakpoint size: %d" % size)

    @property
    def access(self):
        return self._access

    @property
    def size(self):
        return self._size


class HardwareBreakpoint(Breakpoint):
    def __init__(self, address, handler, access, size):
        Breakpoint.__init__(self, BreakPointType.HARDWARE_BREAKPOINT, address, handler)
        if access in [0, 1, 2]:
            self._access = access
        else:
            raise Exception("Invalid hardware breakpoint access: %d" % access)
        if size in [0, 1, 2, 3]:
            self._size = size
        else:
            raise Exception("Invalid hardware breakpoint size: %d" % size)
        self._register = -1

    @property
    def access(self):
        return self._access

    @property
    def size(self):
        return self._size

    @property
    def register(self):
        return self._register

    @register.setter
    def register(self, reg):
        self._register = reg
