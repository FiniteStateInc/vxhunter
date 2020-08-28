import collections


class getLanguageObj(object):
    def __init__(self, *args, **kwargs):
        pass

    def isBigEndian(self):
        return False


class MemoryBlock(object):
    def __init__(self, start, end):
        # feel free to add other elements after offset
        mem = collections.namedtuple('mem', 'offset')
        self.start = mem(start)
        self.end = mem(end)


class MemoryClass(object):
    def __init__(self, *args, **kwargs):
        self.blocks = []
        for i in range(1):
            block = MemoryBlock(0, 0x100000)
            self.blocks.append(block)


class currentProgramObj(object):
    def __init__(self, *args, **kwargs):
        self.memory = MemoryClass()
        self.note = "I'm a ghidra currentProgram instance!"

    def getDefaultPointerSize(self):
        return 4

    def getLanguage(self):
        return getLanguageObj()

    def getImageBase(self):
        return 0
    # get_logger = MagicMock()


currentProgram = currentProgramObj()


class isRunningHeadlessObj(object):
    def __init__(self, *args, **kwargs):
        pass


isRunningHeadless = isRunningHeadlessObj()


class askChoice(object):
    def __init__(self, *args, **kwargs):
        pass


class getScriptArgs(object):
    def __init__(self, *args, **kwargs):
        pass


class toAddr(object):
    def __init__(self, *args, **kwargs):
        pass
