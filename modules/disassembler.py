import pickle
from binascii import unhexlify
from multiprocessing import Queue

from capstone.x86 import *

from libs.pefile import SECTION_CHARACTERISTICS
from modules.constants import BinaryType
from modules.functions import *
from modules.instructions import *
from modules.logger import *
from modules.utils import get_raw_disassembler, file_exists

PROLOGUES = {
    BinaryType.SCS_32BIT_BINARY.value: [unhexlify("5589E581EC"), unhexlify("5589E55756"), unhexlify("5531C089E5")],
    BinaryType.SCS_64BIT_BINARY.value: [unhexlify("554889E5")]}


class EndOfCodeException(Exception):
    pass


class RecursiveDisassembler(object):
    def __init__(self, project):
        super(RecursiveDisassembler, self).__init__()
        self._project = project
        self._pe = project.pe
        self._block_list = BlockList()
        self._function_list = FunctionList()
        self._disassembler = get_raw_disassembler(self._pe.helper.architecture)
        self._function_queue = Queue()
        self._block_queue = Queue()
        self._import_addresses = dict()
        self._instructions_cache = dict()

        if file_exists(project.binary_path + ".cache"):
            log_info("Loading disassembled instruction cache")
            f = open(project.binary_path + ".cache", 'rb')
            self._instructions_cache = pickle.load(f)
            f.close()
        else:
            log_info("Disassembling executable section")
            for section in self._pe.sections:
                if section.Characteristics & SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
                    begin = self._pe.helper.image_base + section.VirtualAddress
                    for i in self._disassembler.disasm(self._pe.helper.mapped[begin:], begin):
                        self._instructions_cache[i.address] = Instruction(i)
            f = open(project.binary_path + ".cache", 'wb')
            pickle.dump(self._instructions_cache, f)
            f.close()

        log_info("Building basic blocks")
        for dll in self._pe.helper.imports:
            for fct in self._pe.helper.imports[dll]:
                self._import_addresses[self._pe.helper.imports[dll][fct]] = fct
        for dll in self._pe.helper.delay_imports:
            for fct in self._pe.helper.delay_imports[dll]:
                self._import_addresses[self._pe.helper.delay_imports[dll][fct]] = fct

        for section in self._pe.sections:
            if section.Characteristics & SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
                log_info("Section %s contains code" % section.Name.decode().strip("\0"))
                self._block_queue.put(self._pe.helper.image_base + section.VirtualAddress)
                if section.contains_rva(self._pe.helper.entry_point - self._pe.helper.image_base):
                    self._block_queue.put(self._pe.helper.entry_point)
                    self._function_queue.put(self._pe.helper.entry_point)

        for cb in self._pe.helper.tls_callbacks:
            self._block_queue.put(cb)
            self._function_queue.put(cb)

        log_info("    Recursive disassembly")
        self._recursive_block_disassembly()
        log_info("    Linear recursive disassembly")
        self._remaining_block_disassembly()

        log_info("    Filtering block padding")
        self._filter_block_padding()

        log_info("Function identification")
        self._function_discovery()

    @property
    def block_list(self):
        return self._block_list

    @property
    def function_list(self):
        return self._function_list

    def _filter_block_padding(self):
        for addr in self._block_list.addresses:
            bb = self._block_list[addr]
            if bb.starts_with(b"\xCC"):
                cutSize = 0
                for instr in bb.instructions:
                    if instr.bytes == b"\xCC":
                        cutSize += 1
                    else:
                        break
                if cutSize < bb.size:
                    new_block = bb.split_at(addr + cutSize)
                    self._block_list.add(new_block)
                    self._function_queue.put(new_block.start)

    def _function_discovery(self):
        while not self._function_queue.empty():
            addr = self._function_queue.get()
            if addr not in self._function_list:
                self._function_list.add(Function(self.block_list[addr]))
        count = len(self._function_list)
        log_info("    using CALL and entrypoints (%d new(s))" % count)

        prologues = PROLOGUES[self._pe.helper.architecture]
        block_function = []
        for addr in self._block_list.addresses:
            bb = self._block_list[addr]
            if not bb.has_flag(BlockFlags.BODY_OF_FUNCTION):
                is_function = False
                for prologue in prologues:
                    if bb.starts_with(prologue):
                        bb.set_flag(BlockFlags.START_OF_FUNCTION)
                        bb.set_flag(BlockFlags.BODY_OF_FUNCTION)
                        block_function.append(bb)
                        break
        for bb in block_function:
            self._function_list.add(Function(bb))
        log_info("    using prologues method (%d new(s))" % (len(self._function_list) - count))

    def _remaining_block_disassembly(self):
        for section in self._pe.sections:
            if section.Characteristics & SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
                current_va = self._pe.helper.image_base + section.VirtualAddress
                max_va = current_va + section.Misc_VirtualSize
                while current_va < max_va:
                    log_debug("rblock at %08x" % current_va)
                    if current_va not in self._block_list:
                        self._block_queue.put(current_va)
                        try:
                            self._recursive_block_disassembly()
                            if current_va in self._block_list:
                                log_debug("size : %d" % self._block_list[current_va].size)
                                current_va = self._block_list[current_va].start + self._block_list[current_va].size
                            else:
                                current_va += 1
                        except EndOfCodeException:
                            current_va = self._block_list.next_after(current_va).start
                    else:
                        log_debug("size : %d" % self._block_list[current_va].size)
                        current_va += self._block_list[current_va].size

    def _recursive_block_disassembly(self):
        while not self._block_queue.empty():
            self.__disass_block_from(self._block_queue.get())

    def __disass_block_from(self, begin, otherbranch=None):
        if begin in self._block_list:
            return self._block_list[begin]
        else:
            log_debug("block at %08x" % begin)
            block = Block()
            if begin in self._instructions_cache:
                i = self._instructions_cache[begin]
            else:
                rinsrt = list(self._disassembler.disasm(self._pe.helper.mapped[begin:begin + 16], begin))
                if len(rinsrt) > 0:
                    i = rinsrt[0]
                else:
                    i = None
            while i is not None:
                if i.address != begin and i.address in self._block_list:
                    log_debug("%08x 1-> %08x" % (
                        block.instructions[0].address, self._block_list[i.address].instructions[0].address))
                    self._block_list.add(block)
                    block.link_to(self._block_list[i.address])
                    return block
                else:
                    block.add(Instruction(i))
                    if i.mnemonic in INSTRUCTIONS_DOUBLE_DEST:
                        self._block_list.add(block)
                        if len(i.operands) == 1 and i.operands[0].type == X86_OP_IMM:
                            log_debug("%08x 2-> %08x" % (block.instructions[0].address, i.operands[0].imm))
                            block.link_to(
                                self.__disass_block_from(i.operands[0].imm, otherbranch=i.address + i.size))

                            log_debug("%08x 2-> %08x" % (block.instructions[0].address, i.address + i.size))
                            block.link_to(
                                self.__disass_block_from(i.address + i.size, otherbranch=i.operands[0].imm))
                        return block
                    elif i.mnemonic in INSTRUCTIONS_FUNCTION_CALL:
                        if i.operands[0].type == X86_OP_REG:
                            pass
                        elif i.operands[0].type == X86_OP_IMM:
                            log_debug("call %08x" % i.operands[0].imm)
                            if i.operands[0].imm not in self._import_addresses:
                                if i.operands[0].imm >= self._pe.helper.image_base:
                                    self._block_queue.put(i.operands[0].imm)
                                    self._function_queue.put(i.operands[0].imm)
                        elif i.operands[0].type == X86_OP_MEM:
                            if i.operands[0].mem.base == 0 and i.operands[0].mem.index == 0 and i.operands[
                                0].mem.disp != 0:
                                log_debug("call2 %08x" % i.operands[0].mem.disp)
                                if i.operands[0].mem.disp not in self._import_addresses:
                                    self._block_queue.put(i.operands[0].mem.disp)
                                    self._function_queue.put(i.operands[0].mem.disp)
                        else:
                            raise Exception("CALL case not implemented")
                    elif i.mnemonic in INSTRUCTIONS_FUNCTION_JMP:
                        if i.operands[0].type == X86_OP_REG:
                            self._block_list.add(block)
                            return block
                        elif i.operands[0].type == X86_OP_IMM:
                            self._block_list.add(block)
                            if i.operands[0].imm not in self._import_addresses:
                                block.link_to(self.__disass_block_from(i.operands[0].imm))
                            return block
                        elif i.operands[0].type == X86_OP_MEM:
                            self._block_list.add(block)
                            if i.operands[0].mem.base != X86_REG_INVALID:
                                if i.operands[0].mem.base == X86_REG_RIP or i.operands[0].mem.base == X86_REG_EIP:
                                    if i.operands[0].mem.disp + i.address + i.size not in self._import_addresses:
                                        block.link_to(
                                            self.__disass_block_from(i.operands[0].mem.disp + i.address + i.size))
                            else:
                                if i.operands[0].mem.disp not in self._import_addresses:
                                    block.link_to(self.__disass_block_from(i.operands[0].mem.disp))
                            return block
                        else:
                            raise Exception("JMP case not implemented")
                    elif i.mnemonic in INSTRUCTIONS_FUNCTION_END or i.bytes == b"\xcc":
                        self._block_list.add(block)
                        return block
                if i in self._instructions_cache:
                    i = self._instructions_cache[i.address + i.size]
                else:
                    rinsrt = list(
                        self._disassembler.disasm(self._pe.helper.mapped[i.address + i.size:i.address + i.size + 10],
                                                  i.address + i.size))
                    if len(rinsrt) > 0:
                        i = rinsrt[0]
                    else:
                        i = None
            if block.is_empty:
                raise EndOfCodeException("No instruction at va : %08x" % begin)
            else:
                self._block_list.add(block)
