INSTRUCTIONS_DOUBLE_DEST = ["jo", "jno",
                            "js", "jns",
                            "je", "jne",
                            "jz", "jnz",
                            "jb", "jnb",
                            "jae", "jnae",
                            "jc", "jnc",
                            "jbe", "jnbe",
                            "ja", "jna",
                            "jl", "jnl",
                            "jge", "jnge",
                            "jle", "jnle",
                            "jg", "jng",
                            "jp", "jpe",
                            "jnp", "jpo",
                            "jcxz", "jecxz"]

INSTRUCTIONS_FUNCTION_CALL = ["call"]

INSTRUCTIONS_FUNCTION_JMP = ["jmp"]

INSTRUCTIONS_FUNCTION_END = ["ret"]


class Instruction(object):
    def __init__(self, instr):
        self._address = instr.address
        self._mnemonic = instr.mnemonic
        self._size = instr.size
        self._op_str = instr.op_str
        self._bytes = instr.bytes
        self._operands = instr.operands

    @property
    def address(self):
        return self._address

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def bytes(self):
        return self._bytes

    @property
    def op_str(self):
        return self._op_str

    @property
    def operands(self):
        return self._operands

    @property
    def size(self):
        return self._size

    def __str__(self):
        return '{:<12}'.format(hex(self._address)[2:]) + '{:8}'.format(self._mnemonic) + self._op_str

    def __repr__(self):
        return "<%s with %d bytes>" % (self.__class__.__name__, self._size)
