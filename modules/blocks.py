import enum
from bisect import bisect_right


class BlockFlags(enum.Enum):
    START_OF_FUNCTION = 0x1
    BODY_OF_FUNCTION = 0x2
    END_OF_FUNCTION = 0x3


class Block(object):
    def __init__(self):
        self.__instructions = []
        self.__children = []
        self.__parents = []
        self.__size = 0
        self.__flags = 0

    @property
    def size(self):
        return self.__size

    @property
    def instructions(self):
        return self.__instructions

    @property
    def is_empty(self):
        return len(self.__instructions) == 0

    def starts_with(self, code):
        for instr in self.__instructions:
            if len(code) >= instr.size:
                if code.startswith(instr.bytes):
                    code = code[len(instr):]
                else:
                    return False
            else:
                return instr.bytes.startswith(code)

    @property
    def children(self):
        return self.__children

    @children.setter
    def children(self, children):
        self.__children = children

    def set_flag(self, flag_type):
        self.__flags = self.__flags | flag_type.value

    def has_flag(self, flag):
        return self.__flags & flag.value

    @property
    def parents(self):
        return self.__parents

    @parents.setter
    def parents(self, parents):
        self.__parents = parents

    def add(self, instr):
        self.__instructions.append(instr)
        self.__size += instr.size

    def link_to(self, block):
        if block is None:
            return
        if block not in self.children:
            self.children.append(block)
        if self not in block.parents:
            block.parents.append(self)

    @property
    def start(self):
        if len(self.__instructions) > 0:
            return self.__instructions[0].address
        else:
            return None

    @property
    def end(self):
        if len(self.__instructions) > 0:
            return self.__instructions[-1].address + self.__instructions[-1].size
        else:
            return None

    def cut_at(self, address):
        i = 0
        newsize = 0
        for instr in self.__instructions:
            if instr.address == address:
                break
            else:
                i += 1
                newsize += instr.size
        self.__instructions = self.__instructions[:i]
        self.__size = newsize

    def __repr__(self):
        return "<%s starting at 0x%08x>" % (self.__class__.__name__, self.start)


class BlockList(object):
    def __init__(self):
        self._blocks = dict()
        self._begin_block_list = []

    @property
    def begin(self):
        if len(self._blocks) > 0:
            return self._blocks[self._begin_block_list[0]]
        else:
            return None

    @property
    def end(self):
        if len(self._blocks) > 0:
            return self._blocks[self._begin_block_list[-1]]
        else:
            return None

    @property
    def count(self):
        return len(self._begin_block_list)

    @property
    def blocks(self):
        return self._blocks.values()

    @property
    def addresses(self):
        return self._begin_block_list

    def next_after(self, addr):
        return self._blocks[self._find_gt(addr)]

    def _find_le(self, x):
        return bisect_right(self._begin_block_list, x) - 1

    def _find_gt(self, x):
        i = bisect_right(self._begin_block_list, x)
        if i != len(self._begin_block_list):
            return self._begin_block_list[i]
        else:
            return self._begin_block_list[-1]

    def __contains__(self, item):
        return item in self._blocks

    def __len__(self):
        return len(self._begin_block_list)

    def __getitem__(self, item):
        return self._blocks[item]

    def add(self, block):
        begin = block.start
        if len(self._begin_block_list) == 0:
            self._begin_block_list.insert(0, begin)
            self._blocks[begin] = block
        else:
            if begin not in self._blocks:
                before = self._find_le(begin)
                block_before = self._blocks[self._begin_block_list[before]]
                if block_before.start < begin < block_before.start + block_before.size:
                    block_before.cut_at(begin)
                    block_before.children = [block]
                self._begin_block_list.insert(before + 1, begin)
                self._blocks[begin] = block

    def __repr__(self):
        return "<%s with %d blocks>" % (self.__class__.__name__, len(self._blocks))
