class CFG(object):
    def __init__(self, root):
        self.__root = root
        self.__blocklist = set()

    @property
    def root(self):
        return self.__root

    def to_dot(self, filename=None):
        dot = "digraph sub_%08x {" % self.__root.instructions[0].address
        dot += self.__to_dot_rec(self.__root)
        dot += "}"
        if filename is None:
            filename = "sub_%08x.dot" % self.__root.instructions[0].address
        f = open(filename, "w")
        f.write(dot)
        f.close()

    def __to_dot_rec(self, block):
        if block.instructions[0].address not in self.__blocklist:
            self.__blocklist.add(block.instructions[0].address)
            dot = ""
            for c in block.children:
                dot += "\"%08x\" -> \"%08x\"\n" % (block.instructions[0].address, c.instructions[0].address)
                dot += self.__to_dot_rec(c)
            return dot
        else:
            return ""
