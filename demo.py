import binascii

import abapt
from modules.breakpoints import *
from modules.logger import *
from modules.utils import *

b = None

@debugged_cb
def set_flag_in_mem(**kwargs):
    print("Hello I'm in a bp!")
    proc = kwargs["process"]
    flag_addr = proc.dereference(kwargs["ctx"].Ebp + 8)
    print("flag_addr = %08x" % (flag_addr))
    print("Old flag is: %s" % proc.read_memory(flag_addr, 8).decode())
    proc.write_memory(flag_addr, b"[redacted]\x00")
    print("New flag is: %s" % proc.read_memory(flag_addr, 8).decode())


@debugged_cb
def set_zf(**kwargs):
    kwargs["ctx"].EFlags |= 0x40


@debugged_cb
def install_bp_zf(**kwargs):
    proc = kwargs["process"]
    proc.add_software_breakpoint(0x00401741, set_zf)
    proc.add_software_breakpoint(0x0040174e, set_zf)
    proc.add_software_breakpoint(0x0040175b, set_zf)
    proc.add_software_breakpoint(0x00401768, set_zf)
    proc.add_software_breakpoint(0x00401775, set_zf)
    proc.add_software_breakpoint(0x00401782, set_zf)
    proc.add_software_breakpoint(0x0040178f, set_zf)


@debugged_cb
def install_bp_writemem(**kwargs):
    proc = kwargs["process"]
    proc.add_software_breakpoint(0x0040172c, set_flag_in_mem)


def load():
    global b
    b = baf.Project('samples\\chall.exe')


def test_show_info():
    global b
    print(b.file_info)
    print(b.find_strings())


def test_debug():
    proc = b.debug()
    proc.run(arguments="testest")
    #
    proc.on_debug_start = install_bp_zf
    proc.run(arguments="foofooo")
    #
    proc.on_debug_start = install_bp_writemem
    proc.run(arguments="foofooo")


def test_disass():
    b.disass_all()
    for func in b.functions.addresses:
        print(func)
    b.functions[0x00401f20].cfg.to_dot("test.dot")


if __name__ == "__main__":
    welcome()
    set_log_level(LogLevel.DEBUG)
    load()
    test_show_info()
    test_debug()
    test_disass()
