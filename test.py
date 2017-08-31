import baf
from modules.breakpoints import *
from modules.cfg import *
from modules.logger import *
from modules.utils import *

b = None


@debugged_cb
def pouetcb(**kwargs):
    print("%08x" % kwargs["ctx"].Eip)
    print("pouet le bp")


@debugged_cb
def install_bp(**kwargs):
    proc = kwargs["process"]
    proc.add_software_breakpoint(b.pe.helper.entry_point, pouetcb)


def test():
    global b
    welcome()
    set_log_level(LogLevel.DEBUG)
    b = baf.Project('data\\explorer.exe')
    # print(b.file_info)
    # dp = b.debug()
    # dp.on_debug_start = install_bp
    # dp
    # dp.run("suce")
    # print(b.pe.helper.tls_callbacks)
    print(b.pe.helper.imports)
    # b.disass()
    # b.disass(begin=0x4023d0)
    # proc = b.run()
    # log_info("Process launched (PID: %d)" % proc.info.pid)
    # exit_code = proc.wait()
    # print("Exit code: %d (%s)" % (exit_code, format_error(exit_code)))
    # proc = b.run("suce")
    # log_info("Process launched (PID: %d)" % proc.info.pid)
    # exit_code = proc.wait()
    # print("Exit code: %d (%s)" % (exit_code, format_error(exit_code)))
    # proc = b.run_suspended("elivesuce")
    # log_info("Process launched suspended (PID: %d)" % proc.info.pid)
    # proc.load_library("test_inject.dll")
    # peb = proc.peb
    # print(peb.BeingDebugged)
    # proc.resume()
    # log_info("Process resumed (PID: %d)" % proc.info.pid)
    # exit_code = proc.wait()
    # print("Exit code: %d (%s)" % (exit_code, format_error(exit_code)))
    b.disass_all()
    for p in b.blocks.addresses:
        print(hex(p) + " -> " + hex(p + b.blocks[p].size))
    # print(b.functions)
    # for func in b.functions.addresses:
    #    print(func)
    # b.functions[0x1401385d3].cfg.to_dot("pouet.dot")
    cfg = CFG(b.blocks[0x1401385d3])
    cfg.to_dot()
    # print(b.pe.helper.timestamp)
    # for i in b.pe.sections:
    # print(hexlify(b.pe.helper.mapped[b.pe.helper.image_base + i.VirtualAddress:b.pe.helper.image_base + i.VirtualAddress + 16]))
    # b = baf.Project('C:\\Windows\\security\\database\\edb.log')
    # print(b.binary_path)
    # print(hex(b.pe.dos_header.e_magic))
    # print(dir(b.pe.data_directory))
    # print(b.pe.data_directory[ImageDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY])
    # print(b.pe.helper.signature)
    # print(hex(b.pe.optional_header.Magic))
    # print(b.pe.warnings)
    # print(hex(b.pe.helper.entry_point))
    # print(b.pe.helper.imphash)
    # print(b.pe.helper.get_section_from_rva(b.pe.helper.entry_point))
    # print("suce", b.find_xored_strings())
    # print(b.info)
    # print("mua", b.pe.helper.strings)


if __name__ == "__main__":
    test()
