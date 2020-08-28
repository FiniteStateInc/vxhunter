class FlatProgramAPI(object):
    def __init__(self):
        self.note = "HAHAHAH"
        return


class GenericAddress(object):
    def __init__(self):
        return


class flatapi(object):
    def __init__(self):
        self.FlatProgramAPI = FlatProgramAPI()
        pass


class address(object):
    def __init__(self):
        self.GenericAddress = GenericAddress()
        pass


class model(object):
    def __init__(self):
        self.address = address
        pass


class program(object):
    def __init__(self):
        self.model = model()
        self.flatapi = flatapi()
        pass


class ghidra(object):
    def __init__(self):
        self.program = program()
        pass
