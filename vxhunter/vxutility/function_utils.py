from ghidra.program.model.data import PointerDataType, CharDataType, VoidDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.lang import PrototypeModel
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.flatapi import FlatProgramAPI

from symbol import get_function
from function_analyzer import get_all_calls_to_addr, get_calls_in_func
from common import print_err

from __main__ import currentProgram

cp = currentProgram
fp = FlatProgramAPI(cp)

char_dt = CharDataType()
void_dt = VoidDataType()

char_ptr_dt = PointerDataType(char_dt)
void_ptr_dt = PointerDataType(void_dt)

func_signatures = {
    'memcpy': {
        'args': [{ 'dt': void_ptr_dt, 'name': 'dst' }, { 'dt': void_ptr_dt, 'name': 'src' }],
        'retval': void_ptr_dt
    },
    'strcpy': {
        'args': [{ 'dt': char_ptr_dt, 'name': 'dst' }, { 'dt': char_ptr_dt, 'name': 'src' }],
        'retval': char_ptr_dt
    },
    'loginUserAdd': {
        'args': [{ 'dt': char_ptr_dt, 'name': 'username'}, { 'dt': char_ptr_dt, 'name': 'password' }], 
        'retval': void_dt,                                                                              
    }
}

def loginUserAdd_uses_ipcom_hash():
    loginUserAdd = get_function('loginUserAdd')
    if loginUserAdd is None:
        return False

    ipcom_auth_useradd_hash = get_function('ipcom_auth_useradd_hash')
    if ipcom_auth_useradd_hash is None:
        return False

    hash_func_addr = ipcom_auth_useradd_hash.entryPoint
    call_data = get_calls_in_func(loginUserAdd, target_func_addrs=[hash_func_addr])
    return hash_func_addr in call_data

def get_func_end_addr(func):
    insn = fp.getInstructionAt(func.entryPoint)
    end_addr = insn.address

    while insn is not None and fp.getFunctionContaining(insn.address) == func:
        end_addr = insn.address
        insn = insn.next

    return end_addr

def get_function_calling_convention(func):
    cc = func.callingConvention

    if cc is None:
        func_man = cp.functionManager
        cc = func_man.defaultCallingConvention

    return cc

def set_function_signature(func, correct_args, correct_retval):
    '''
    Set the function signature of the given function if it doesn't match our desired signature.
    '''
    siggie = func.signature
    calling_conv = get_function_calling_convention(func)

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

def fixup_function_signatures(script_name=None):
    if loginUserAdd_uses_ipcom_hash():
        func_signatures['loginUserAdd']['args'].append({ 'dt': char_ptr_dt, 'name': 'salt' })

    for func_name, siggie in func_signatures.items():
        func = get_function(func_name)

        if func is None:
            print_err('Can\'t find %s' % func_name, script_name)
            continue

        set_function_signature(func, siggie['args'], siggie['retval'])

def is_func_called_from_a_root(func_name, roots, depth=0, visited_func_addrs=[], max_depth=10):
    '''
    Return whether or not a function is called from one of the root functions specified
    '''
    func = get_function(func_name)

    # You can't call a function that doesn't exist!
    if func is None:
        return False

    func_addr = func.entryPoint

    # Make sure we don't traverse any cycles in the call graph
    visited_func_addrs.append(func_addr)

    # Check to make sure we're not too deep. No one likes a stack overflow
    depth += 1

    if depth >= max_depth:
        return False

    # Get the calls to the current node
    call_addrs = get_all_calls_to_addr(func_addr, ret_all_refs=True)

    for call_addr in call_addrs:
        # Assert that the reference is in a function
        calling_func = fp.getFunctionContaining(call_addr)

        if calling_func is None:
            continue

        # Exit early if a calling function is in the roots
        if calling_func.name.strip('_') in roots:
            return True

        # Don't try to recurse on a previously visited node, we'll probably overflow the stack if we do
        if call_addr in visited_func_addrs:
            continue

        # Recurse if it isn't (basically DFS on the call graph)
        if is_func_called_from_a_root(calling_func.name, roots, depth, visited_func_addrs, 10):
            return True

    # Alas, the function was not called
    return False
