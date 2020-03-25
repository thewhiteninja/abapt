from modules.blocks import *
from modules.cfg import *
from modules.instructions import *


class Function(object):
    def __init__(self, root_block):
        self.__root_block = root_block
        self.__name = "sub_%08x" % self.__root_block.start
        self.__end = None
        self.__cfg = None
        self._analyse_function()

    def _analyse_function(self):
        self.__root_block.set_flag(BlockFlags.START_OF_FUNCTION)
        self.__end = self._analyse_function_rec(self.__root_block)

    def _analyse_function_rec(self, block):
        if not block.has_flag(BlockFlags.BODY_OF_FUNCTION):
            block.set_flag(BlockFlags.BODY_OF_FUNCTION)
            if block.instructions[-1].mnemonic in INSTRUCTIONS_FUNCTION_END:
                block.set_flag(BlockFlags.END_OF_FUNCTION)
                return block.instructions[-1].address + block.instructions[-1].size
            else:
                if len(block.children) > 0:
                    return max([self._analyse_function_rec(c) for c in block.children])
                else:
                    return block.instructions[-1].address + block.instructions[-1].size
        return 0

    @property
    def name(self):
        return self.__name

    def rename(self, new_name):
        self.__name = new_name

    @property
    def start(self):
        return self.__root_block.start

    @property
    def end(self):
        return self.__end

    @property
    def cfg(self):
        if self.__cfg is None:
            self.__cfg = CFG(self.__root_block)
        return self.__cfg

    def __repr__(self):
        return "<%s starting at 0x%08x>" % (self.__class__.__name__, self.start)


class FunctionList(object):
    def __init__(self):
        self._functions = dict()

    @property
    def addresses(self):
        if len(self._functions) > 0:
            return sorted(self._functions.keys())
        else:
            return []

    @property
    def begin(self):
        if len(self._functions) > 0:
            return self._functions[sorted(self._functions.keys())[0]]
        else:
            return None

    @property
    def end(self):
        if len(self._functions) > 0:
            return self._functions[sorted(self._functions.keys())[-1]]
        else:
            return None

    @property
    def count(self):
        return len(self._functions)

    def __len__(self):
        return len(self._functions)

    def __contains__(self, item):
        return item in self._functions

    def __getitem__(self, item):
        return self._functions[item]

    def add(self, func):
        self._functions[func.start] = func

    def __repr__(self):
        return "<%s with %d functions>" % (self.__class__.__name__, len(self._functions))
