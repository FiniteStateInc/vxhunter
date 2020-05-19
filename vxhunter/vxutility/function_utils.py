from ghidra.program.model.data import PointerDataType, CharDataType, VoidDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.lang import PrototypeModel
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.flatapi import FlatProgramAPI

from symbol import get_function
from function_analyzer import get_all_calls_to_addr
from common import print_err

from __main__ import currentProgram

cp = currentProgram
fp = FlatProgramAPI(cp)

char_dt = CharDataType()
void_dt = VoidDataType()

char_ptr_dt = PointerDataType(char_dt)
void_ptr_dt = PointerDataType(void_dt)

cpy_func_signatures = {
    'memcpy': {
        'args': [{ 'dt': void_ptr_dt, 'name': 'dst' }, { 'dt': void_ptr_dt, 'name': 'src' }],
        'retval': void_ptr_dt
    },
    'strcpy': {
        'args': [{ 'dt': char_ptr_dt, 'name': 'dst' }, { 'dt': char_ptr_dt, 'name': 'src' }],
        'retval': char_ptr_dt
    }
}

def set_function_signature(func, correct_args, correct_retval):
    '''
    Set the function signature of the given function if it doesn't match our desired signature.
    '''
    siggie = func.signature
    calling_conv = func.callingConvention

    # Check if the calling convention of the function is explicitly set
    if calling_conv is None:
        func_man = cp.functionManager
        calling_conv = func_man.defaultCallingConvention

    args = [arg.dataType for arg in siggie.arguments]
    retval = siggie.returnType

    # If the arguments don't match, set the function's arguments to what we passed
    if args != [arg['dt'] for arg in correct_args]:
        # Construct a list of arguments/params
        new_params = []

        for i, arg in enumerate(correct_args):
            arg_loc = calling_conv.getNextArgLocation(new_params, arg['dt'], cp)
            new_params.append(ParameterImpl(arg['name'], arg['dt'], arg_loc, cp, SourceType.USER_DEFINED))

        func.replaceParameters(new_params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)

    # Do the same for the return type
    if retval != correct_retval:
        func.setReturnType(correct_retval, SourceType.USER_DEFINED)


def get_func_addrs_and_set_signatures(func_sigs, script_name=None):
    '''
    Get a list of function addresses specified by func_sigs (a dictionary of names -> sigs)
    and fix said function's signatures.
    '''
    funcs = []

    for func_name, siggie in func_sigs.items():
        func = get_function(func_name)

        if func is None:
            print_err('Can\'t find %s' % func_name, script_name)
            continue

        set_function_signature(func, siggie['args'], siggie['retval'])
        funcs.append(func.entryPoint)

    return funcs


def is_func_called(func_name):
    '''
    Return whether or not a function is called.
    '''
    func = get_function(func_name)

    # You can't call a function that doesn't exist!
    if func is None:
        return False

    calls = get_all_calls_to_addr(call_address=func.entryPoint)
    return len(calls) > 0
