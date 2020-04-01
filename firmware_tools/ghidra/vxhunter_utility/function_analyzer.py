# coding=utf-8
from common import *
from common import logger as common_logger
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
from ghidra.program.database.code import DataDB


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *


vxworks_service_keyword = {
    "wdbDbg": ["wdbDbgArchInit"],
    "ftpd": ["ftpdInit"],
    "tftpd": ["tftpdInit"],
    "snmpd": ["snmpdInit"],
    "sshd": ["sshdInit"],
    "shell": ["shellInit"],
    "telnetd": ["telnetdInit"],
}

decompile_func_cache = {}

BINARY_PCODE_OPS = [PcodeOp.INT_ADD, PcodeOp.PTRSUB, PcodeOp.INT_SUB]


def get_pcode_value(pcode):
    '''
    Get the value of a pcode operation. Will recursively call `get_varnode_value` on the
    operation's operands.
    '''

    # Something might've gone wrong while backtracking (e.g. an unimplemented opcode)
    # so pcode could be None.

    if pcode is None:
        return None

    opcode = pcode.getOpcode()

    if opcode in BINARY_PCODE_OPS:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))

        if op1 is None or op2 is None:
            return None

        if opcode == PcodeOp.INT_ADD or opcode == PcodeOp.PTRSUB:
            return op1 + op2

        elif opcode == PcodeOp.INT_SUB:
            return op1 - op2

    elif opcode == PcodeOp.PTRADD:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))
        op3 = get_varnode_value(pcode.getInput(2))

        if op1 is None or op2 is None or op3 is None:
            return None

        return op1 + op2 * op3

    elif opcode == PcodeOp.INT_2COMP:
        op = get_varnode_value(pcode.getInput(0))

        if op is None:
            return None

        return -op

    elif opcode == PcodeOp.COPY or opcode == PcodeOp.CAST:
        return get_varnode_value(pcode.getInput(0))

    elif opcode == PcodeOp.LOAD:
        off = get_varnode_value(pcode.getInput(1))

        if off is None:
            return None

        addr = toAddr(off)
        space = pcode.getInput(0).getOffset()

        # The offset of the space input specifies the address space to load from.
        # Right now, we're only handling loads from RAM

        if space == SPACE_RAM:
            return get_value_from_addr(addr, pcode.getOutput().getSize())
        else:
            logging.error('Unhandled load space %d for pcode %s' % (space, pcode))
            return None

    logging.error('Unhandled pcode opcode %s pcode %s' % (pcode.getMnemonic(opcode), pcode))
    return None


def get_varnode_value(varnode):
    '''
    Get the value of a varnode. Will traverse definitions until a constant is found
    '''
    off = varnode.getOffset()
    addr = toAddr(off)

    # If the parameter is a valid address, then get the bytes in memory at that address.
    if varnode.isAddress() and varnode.getSpace() == SPACE_RAM and is_address_in_current_program(addr):
        return get_value_from_addr(addr, varnode.getSize())

    # Otherwise, recursively backtrack from the definition of this varnode.
    else:
        defn = varnode.getDef()
        return get_pcode_value(defn)


class FunctionAnalyzer(object):
    def __init__(self, func, timeout=30, logger=None):
        """
        :param function: Ghidra function object.
        :param timeout: timeout for decompile.
        :param logger: logger.
        """
        self.func= func
        self.timeout = timeout

        self.logger = logger

        if logger is None:
            self.logger = logging.getLogger('Function Analyzer')

        self.call_pcodes = {}
        self.get_all_call_pcode_ops()

    def get_high_fn(self):
        '''
        Get the high-level decompilation for the function to analyze
        '''
        decomp_iface = DecompInterface()
        decomp_iface.openProgram(cp)

        decomp_fn = decomp_iface.decompileFunction(self.func, self.timeout, getMonitor())
        return decomp_fn.getHighFunction()

    def get_all_call_pcode_ops(self):
        '''
        Get a mapping of addr -> pcode for every CALL or CALLIND
        '''
        high_fn = self.get_high_fn()

        if high_fn is None:
            return

        ops = high_fn.getPcodeOps()

        while ops.hasNext():
            pcode = ops.next()
            opcode = pcode.getOpcode()

            # We only care about CALL or CALLIND pcode ops
            if opcode not in [PcodeOp.CALL, PcodeOp.CALLIND]:
                continue

            call_addr = pcode.getInput(0).getPCAddress()
            self.call_pcodes[call_addr] = pcode

    def get_call_addr(self, func_addr):
        '''
        Get the call site to `func_addr` in the current function is it exists
        '''
        for call_addr, pcode in self.call_pcodes.items():
            to_addr = get_varnode_value(pcode.getInput(0))

            if to_addr.offset == func_addr.offset:
                return call_addr

        return None

    def get_call_addr_from_call_sites(self, call_sites):
        '''
        Return the first address of a call instruction in the current function
        that is in `call_sites`.
        '''
        for call_addr in self.call_pcodes.keys():
            if call_addr in call_sites:
                return call_addr

        return None

    def get_param_values(self, call_address):
        '''
        Get the address and pointed to value for every call.
        If a parameter is not an address, the value is the parameter itself.
        '''
        if not call_address in self.call_pcodes:
            return None

        pcode = self.call_pcodes[call_address]
        params = pcode.getInputs()[1:]

        return [get_varnode_value(param) for param in params]

    def get_all_param_values(self):
        '''
        Get the parameter value for every call within the current function
        '''
        param_vals = {}

        for call_addr, pcode in self.call_pcodes.items():
            param_vals[call_addr] = self.get_param_values(call_addr)

        return param_vals


def get_all_calls_to_addr(call_address, search_funcs=None):
    '''
    Return the functions that call the function at `call_address` along with the
    parameters passed.
    '''
    target_func = getFunctionAt(call_address)
    params_data = {}

    if not target_func:
        return params_data

    target_references = getReferencesTo(target_func.getEntryPoint())

    for target_reference in target_references:

        # We only care about calls to the target func
        reference_type = target_reference.getReferenceType()
        if not reference_type.isCall():
            continue

        call_addr = target_reference.getFromAddress()

        func = getFunctionContaining(call_addr)
        if not func:
            continue

        # Search only targeted func
        if search_funcs and func.name.strip('_') not in search_funcs:
            continue

        func_addr = func.getEntryPoint()

        # Get the func analyzer from the cache or create one
        if func_addr in decompile_func_cache:
            func_analyzer = decompile_func_cache[func_addr]
        else:
            func_analyzer = FunctionAnalyzer(func)
            decompile_func_cache[func_addr] = func_analyzer

        call_data = {
            'func_addr': func.getEntryPoint(),
            'func_name': func.name,
        }

        # Try to get the parameters to this call
        params_value = func_analyzer.get_param_values(call_addr)
        if params_value:
            call_data['params'] = params_value

        params_data[call_addr] = call_data

    return params_data


def get_calls_in_func(func, target_func_addrs=None):
    '''
    Get the functions called, and parameters passed to them, from within a function.
    '''
    func_addr = func.getEntryPoint()
    call_params = {}

    # Get the func analyzer from the cache or create one
    if func_addr in decompile_func_cache:
        func_analyzer = decompile_func_cache[func_addr]
    else:
        func_analyzer = FunctionAnalyzer(func)
        decompile_func_cache[func_addr] = func_analyzer

    # If we are not searching for any functions in specific, just return the parameters to all calls.
    if target_func_addrs is None:
        return func_analyzer.get_all_param_values()
        
    # Otherwise, return just the parameters for the target functions.
    for target_func_addr in target_func_addrs:

        # We first need to get the address of the call to our target function.
        #
        # To do this, we get all the calls to the target address and check to make
        # sure that one of the functions called in `func` is one of these references.
        refs = getReferencesTo(target_func_addr)
        refs = filter(lambda x: x.getReferenceType().isCall(), refs)

        call_sites = map(lambda x: x.getFromAddress(), refs)
        call_addr = func_analyzer.get_call_addr_from_call_sites(call_sites)

        if call_addr is None:
            continue

        params = func_analyzer.get_param_values(call_addr)
        if params is None:
            continue

        call_params[target_func_addr] = params

    return call_params

