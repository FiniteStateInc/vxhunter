import mock


class getLanguageObj(object):
    def __init__(self, *args, **kwargs):
        pass

    def isBigEndian(self):
        return False


class currentProgramObj(object):
    def __init__(self, *args, **kwargs):
        self.memory = mock.MagicMock()
        self.note = "I'm a ghidra currentProgram instance!"

    def getDefaultPointerSize(self):
        return 4

    def getLanguage(self):
        return getLanguageObj()
        pass
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
