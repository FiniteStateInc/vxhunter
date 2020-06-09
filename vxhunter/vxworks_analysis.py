import sys
sys.path.insert(0, '.')

import json
from functools import reduce

from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.data import IntegerDataType

from vxutility.common import *
from vxutility.function_analyzer import *
from vxutility.function_utils import fixup_function_signatures, is_func_called_from_a_root
from vxutility.emulation import emulate_func
from vxutility.symbol import *


SERVICE_FUNCS = {
    'wdbDbg': ['wdbDbgArchInit'],
    'ftpd': ['ftpdInit'],
    'tftpd': ['tftpdInit'],
    'snmpd': ['snmpdInit'],
    'sshd': ['sshdInit'],
    'shell': ['shellInit', 'usrShellInit'],
    'telnetd': ['telnetdInit'],
}

PROTECTION_FUNCS = {
    'write_protection': {
        5: {
            'virtual_mem_text': ['vmTextProtect'],
            'vector_table': ['intVecTableWriteProtect']
        },
        6: {
            'virtual_mem_text': ['vmTextProtect'],
            'vector_table': ['intVecTableWriteProtect'],
            'user_text': ['usrTextProtect'],
        }
    },
    'interrupt_stack_protection': {
        6: {
            'guard_zones': ['usrKernelIntStkProtect']
        }
    },
    'user_task_stack_protection': {
        6: {
            'no_exec': ['taskStackNoExecEnable'],
            'guard_zones': ['taskStackGuardPageEnable']
        }
    }
}

PROTECTION_VARS = {
    'kernel_stack_protection': {
        'guard_overflow_size_exec': 'taskKerExecStkOverflowSize',
        'guard_underflow_size_exec': 'taskKerExecStkUnderflowSize',
        'guard_overflow_size_exception': 'taskKerExcStkOverflowSize'
    },
    'user_task_stack_protection': {
        'guard_overflow_size_exec': 'taskUsrExecStkOverflowSize',
        'guard_underflow_size_exec': 'taskUsrExecStkUnderflowSize',
        'guard_overflow_size_exception': 'taskUsrExcStkOverflowSize'
    }
}

ROOTS = ['usrRoot', 'usrKernelInit', 'usrInit', 'sysInit', 'sysStart']


def get_sda_regs():
    '''
    Try to get the value of the SDA registers (PowerPC-specific) and set them in the program.
    '''
    global script_name

    target_function = get_function('vxSdaInit')

    if not target_function:
        print_err('Can\'t find vxSdaInit function in firmware', script_name)
        return

    # Make sure that vxSdaInit is called
    calls = get_all_params_passed_to_func(target_function.getEntryPoint())

    if len(calls) == 0:
        print_err('Can\'t find any calls to vxSdaInit')
        return

    '''
    #min_call_addr = min(calls.keys())
    sda_reg_vals = emulate_func(target_function)['register']
    '''

    emu = emulate_func(target_function, [])
    if emu is None:
        return

    #next_insn_addr = fp.getInstructionAfter(min_call_addr).address
    min_addr = get_main_memory().start
    max_addr = get_main_memory().end

    prog_ctx = cp.programContext
    lang = cp.language

    for name in ['r2', 'r13']:
        reg = lang.getRegister(name)
        if reg is None:
            print('Could not find register %s' % name)
            continue

        val = emu.readRegister(name)
        if val is None or val == 0:
            print('Register %s has an unknown value after emulation' % name)
            continue

        print('Setting %s to %x starting at %s' % (name, val, min_addr))
        prog_ctx.setValue(reg, min_addr, max_addr, long(val))


def create_bss():
    '''
    Get the parameters passed to bzero when called from sysStart or usrInit.
    Based on the start and length, create a bss memory region.
    '''
    global script_name

    target_function = get_function('bzero')

    if not target_function:
        print_err('Can\'t find bzero function in firmware', script_name)
        return

    # Get the parameters of all calls to bzero in sysStart and usrInit.
    calls = get_all_params_passed_to_func(target_function.getEntryPoint(), 
                                  search_funcs=['sysStart', 'usrInit'])

    for call_addr, params in calls.items():
        # bzero takes an address and size.
        if len(params) != 2: 
            continue

        bss_start, bss_len = tuple(params)

        if bss_start is None or bss_len is None:
            continue

        # TODO: Label these addresses
        bss_end = bss_start + bss_len 

        # Don't recreate the segment if we've already created it or it's already mapped.
        #
        # There are, although, some instances where we may not have the base address
        # exactly correct or bzero includes some file bytes, so if `bss_start` is sufficiently
        # large, transfer the overlap to the bss section.
        #
        # This is pretty hacky but it seems to work.
        #
        # TODO: Figure out a way to make this code prettier.
        if is_address_in_current_program(toAddr(bss_start)):
            max_addr = cp.getMaxAddress().offset + 1

            if bss_start <= max_addr - 0x2000: 
                continue

            if not split_main_memory(toAddr(bss_start)):
                print_err('Couldn\'t split main memory', script_name)
                continue

            if len(cp.memory.blocks) < 2:
                continue

            bss_file_block = cp.memory.blocks[1]

            bss_len -= max_addr - bss_end            
            bss_block = create_initialized_block('.bss', toAddr(max_addr), bss_len)

            if bss_block is None:
                print_err('Couldn\'t create bss block', script_name)
                continue

            if not join_blocks(bss_file_block, bss_block):
                print_err('Couldn\'t join blocks', script_name)
                continue

            if len(cp.memory.blocks) < 2:
                continue

            cp.memory.blocks[1].setName('.bss')
            analyzeChanges(cp)
            break

        print_out('Creating bss block from 0x%x to 0x%x' % (bss_start, bss_end), script_name)

        # Create the bss region in memory.
        if not create_initialized_block('.bss', toAddr(bss_start), bss_len):
            print_err('Can\'t create bss block, you can create it manually', script_name)

        # Ghidra can probably create more xrefs to the bss section now so let's not stop it.
        analyzeChanges(cp)

        # Once we've created the region, we're done here.
        break


def add_function_xrefs_from_symbol_find():
    '''
    Sometimes, a function will be referenced in code by:

        symFindByName(..., function name, ...)

    In which case, we want to add an xref to that function since it is an indirect
    reference Ghidra won't pick up on.
    '''
    global script_name

    target_function = get_function("symFindByName")

    if not target_function:
        print_err("Can't find symFindByName function in firmware", script_name)
        return

    calls = get_all_params_passed_to_func(target_function.entryPoint)

    print_out("Found %d symFindByName call" % len(calls), script_name)

    ref_man = cp.getReferenceManager()

    for call_addr, params in calls.items():
        # symFindByName takes a table ID, symbol name, value pointer, and a symbol type pointer
        if len(params) != 4:
            continue

        name_ptr = params[1]

        if name_ptr is None:
            continue

        # Only count symbols where we have a valid name.
        name_data = getDataAt(toAddr(name_ptr))

        if name_data is None or (not name_data.hasStringValue()): 
            continue

        name = str(name_data.getValue())

        # We only care about when the firmware is searching for a function
        to_function = get_function(name, None)

        if not to_function:
            print_out("Symbol %s is not a function" % name, script_name)
            continue

        # Add a reference to the function since Ghidra will not find this
        # out of the box.

        ref_to = to_function.getEntryPoint()
        ref_from = call_addr

        ref_man.addMemoryReference(ref_from, 
                                   ref_to, 
                                   RefType.READ,
                                   SourceType.USER_DEFINED, 
                                   0)


def get_bootline():
    '''
    Get the bootline of the firmware since it has lots of juicy information in it.
    '''
    global script_name

    # The bootline will be strcpy'd or memcpy'd at the end of the 
    # usrBootLineInit function.
    bootline_func = get_function('usrBootLineInit')

    if bootline_func is None:
        print_err('Can\'t find usrBootLineInit', script_name)
        return None

    cpy_funcs = [get_function(name) for name in ['memcpy', 'strcpy']]
    cpy_func_addrs = [func.entryPoint for func in cpy_funcs if func is not None]

    # Get the value of the second parameter to the last copy function
    # called from usrBootLineInit.
    cpy_calls = get_calls_in_func(bootline_func, cpy_func_addrs)
    cpy_calls = sorted(cpy_calls.items(), key=lambda kv: kv[0])

    for _, params in cpy_calls[::-1]:
        if len(params) < 2 or params[1] is None:
            continue

        return get_string_from_addr(toAddr(params[1]))

    print_out('Couldn\'t find a call to a copy function in usrBootLineInit', script_name)
    return None


def get_function_params(func_name, param_descs):
    global script_name

    objs = []

    target_function = get_function(func_name)

    param_idxs = [desc['idx'] for desc in param_descs.values()]
    min_num_params = max(param_idxs) + 1

    if target_function is None:
        print_err('Can\'t find function %s' % func_name, script_name)
        return objs

    # Get all calls to the login function.
    calls = get_all_params_passed_to_func(target_function.getEntryPoint())

    for call_addr, params in calls.items():
        # Make sure we at least were able to get the value of the username and password params.
        if len(params) < min_num_params: 
            continue

        obj = {}

        for param_name, param_desc in param_descs.items():
            param_idx = param_desc['idx']
            is_string = param_desc.get('is_string', False) # TODO: change to more general notion of a pointer

            if param_idx >= len(params):
                print_err('%s is not a valid param index' % param_name)

            if params[param_idx] is None:
                print_err('%s is None' % param_name)
                continue

            param = params[param_idx]
            param_val = None

            if is_string:
                param_val = get_ascii_at(fp.toAddr(param))

                if param_val is not None and len(param_val) == 0:
                    param_val = None

                # TODO: figure out a way to make this faster since there's gonna be a lot of x-refs to strcpy so it's gonna be slow
                '''
                if param_val is None and func_name != 'strcpy':
                    strcpy_params = get_function_params('strcpy', { 'dst': { 'idx': 0, 'is_string': False }, 'src': { 'idx': 1, 'is_string': True } })
                    srcs = [params['src'] for params in strcpy_params if params['dst'] == param]

                    if len(srcs) > 0 and srcs[0] is not None:
                        param_val = srcs[0]
                '''
            else:
                param_val = param

            if param_val is None:
                print_err('%s is None' % param_name)
                continue

            obj[param_name] = param_val

        objs.append(obj)

    return objs


def get_login_function(func_name, param_idxs, associated_services=[]):
    accounts = get_function_params(func_name, param_idxs)
    tmp_accounts = []

    for account in accounts:
        if len(account) == 0:
            continue

        account.update({ 
            'services': associated_services,
            'origin': func_name
        })

        tmp_accounts.append(account)

    return tmp_accounts


def get_login_accouts():
    '''
    Try to find hardcoded user accounts.
    '''
    accounts = []

    login_user_add_params = {
        'username': {'idx': 0, 'is_string': True},
        'password_hash': {'idx': 1, 'is_string': True}
    }

    ipcom_auth_useradd_params = {
        'username': {'idx': 0, 'is_string': True},
        'password': {'idx': 1, 'is_string': True}
    }

    accounts.extend(get_login_function('loginUserAdd', 
                                       login_user_add_params, 
                                       associated_services=['shell']))

    accounts.extend(get_login_function('ipcom_auth_useradd', 
                                       ipcom_auth_useradd_params, 
                                       associated_services=['ssh']))

    return accounts


def get_available_services():
    '''
    Use known function names to determine if services such as telnet, ftp, and wdbg are enabled.

    TODO: Make sure that the service isn't disabled after being enabled.
    '''
    services = []

    for service_name, funcs in SERVICE_FUNCS.items():
        service = {
            'name': service_name,
            'enabled': False
        }

        # Prefix all of the functions with underscores just in case
        funcs.extend(['_' + func for func in funcs])

        for func in funcs:
            service['enabled'] = is_func_called_from_a_root(func, ROOTS)

            # If one of the functions was called, chalk it up as a win and move on
            if service['enabled']:
                break

        services.append(service)

    return services


def get_guard_page_sizes(protections):
    # The guard page sizes are passed as parameters to taskLibInit.
    # I'm not positive that param 2 corresponds to `taskKerExcStkOverflowSize` but it makes sense.
    guard_page_params = {
        'taskUsrExcStkOverflowSize': {'idx': 1},
        'taskKerExcStkOverflowSize': {'idx': 2},
        'taskUsrExecStkOverflowSize': {'idx': 3},
        'taskUsrExecStkUnderflowSize': {'idx': 4},
        'taskKerExecStkOverflowSize': {'idx': 5},
        'taskKerExecStkUnderflowSize': {'idx': 6}
    }

    guard_page_vals = get_function_params('taskLibInit', guard_page_params)

    if len(guard_page_vals) > 0:
        guard_page_vals = guard_page_vals[0]

    for prot_category_name, category_prot_vars in PROTECTION_VARS.items():
        if prot_category_name not in protections:
            protections[prot_category_name] = {}

        for prot_name, prot_var in category_prot_vars.items():
            if prot_var in guard_page_vals:
                protections[prot_category_name][prot_name] = guard_page_vals[prot_var]

    func = get_function('usrKernelInit')
    if func is None:
        print('kernelInit is None')
        return

    int_dt = IntegerDataType()
    params = [('global_no_stack_fill', int_dt, 0)]

    funcs_to_call = []
    kernelInit = get_function('kernelInit')
    if kernelInit is not None:
        funcs_to_call.append(kernelInit.entryPoint)

    emu = emulate_func(func, params, skip_calls=True, funcs_to_call=funcs_to_call)
    if emu is None:
        return

    int_stk_var_name_mapping = {
        'vxIntStackOverflowSize': 'guard_overflow_size', 
        'vxIntStackUnderflowSize': 'guard_underflow_size'
    }

    if 'interrupt_stack_protection' not in protections:
        protections['interrupt_stack_protection'] = {}

    for var_name, key_name in int_stk_var_name_mapping.items():
        var = get_symbol(var_name)
        if var is None:
            print('Couldn\'t find symbol %s' % var_name)
            continue

        value = get_value(emu.readMemory(var.address, word_size))
        protections['interrupt_stack_protection'][key_name] = value


def get_protections(vx_ver):
    '''
    Get the memory protections (NX stack, W^X, etc.) used in the binary.
    '''
    protections = {}

    for prot_category_name, all_prot_funcs in PROTECTION_FUNCS.items():
        if vx_ver not in all_prot_funcs:
            continue

        prots = {}

        for prot_name, prot_funcs in all_prot_funcs[vx_ver].items():
            # Prefix all of the functions with underscores just in case
            prot_funcs.extend(['_' + func for func in prot_funcs])

            for func in prot_funcs:
                prots[prot_name] = is_func_called_from_a_root(func, ROOTS)

                # Like in the services, break if one of the functions is called
                if prots[prot_name]:
                    break

        protections[prot_category_name] = prots

    if vx_ver == 6:
        get_guard_page_sizes(protections)

    # TODO: Figure out a data model for protections so that non-functions don't have to be treated separately

    # Check if the `usrSecurity` function is called from a root
    protections['password_protection'] = is_func_called_from_a_root('usrSecurity', ROOTS)

    # See if the global variable `sysTextProtect` is 1
    kprotect_sym = get_symbol('sysTextProtect')

    if kprotect_sym is not None:
        write_prot_name = 'write_protection'
        if not write_prot_name in protections:
            protections[write_prot_name] = {}

        protections[write_prot_name]['kernel_text'] = get_value_from_addr(kprotect_sym.address, word_size) == 1

    # See if the global variable `globalNoStackFill` is 0
    nostackfill_sym = get_symbol('globalNoStackFill')
    global_stack_fill = False

    if nostackfill_sym is not None:
        global_stack_fill = get_value_from_addr(nostackfill_sym.address, word_size) == 0

    # Try getting the parameter passed to usrKernelInit which should overwrite globalNoStackFill.
    nostackfill_params = get_function_params('usrKernelInit', {'nostackfill': {'idx': 0}})

    # For now, assume that every call to usrKernelInit should pass 0.
    if len(nostackfill_params) > 0:
        # Wrap in a try-catch in case the nostackfill param is for some reason not an integer.
        try:
            global_stack_fill = sum([p.get('nostackfill', 0) for p in nostackfill_params]) == 0
        except TypeError:
            pass

    # Get the number of calls to the checkStack function
    check_stack_func = get_function('checkStack')
    num_check_stacks = 0

    if check_stack_func is not None:
        num_check_stacks = len(get_all_calls_to_addr(check_stack_func.entryPoint))
    
    # Since both VxWorks 5 and 6 have stack fill/checkStack, we want to set them no matter if we found them
    write_prot_name = 'user_task_stack_protection'
    if not write_prot_name in protections:
        protections[write_prot_name] = {}

    protections[write_prot_name]['global_stack_fill'] = global_stack_fill
    protections[write_prot_name]['check_stack_xrefs'] = num_check_stacks

    return protections


if __name__ == '__main__':
    script_name, vx_ver = get_args()
    if script_name is None or vx_ver is None:
        exit()

    # Try to enrich the database by adding x-refs, mapping memory, etc.
    fixup_function_signatures(script_name)
    get_sda_regs()
    create_bss()
    add_function_xrefs_from_symbol_find()

    # Look at VxWorks specific functions to try to improve the analysis report.
    accounts = get_login_accouts()
    bootline = get_bootline()
    services = get_available_services()
    protections = get_protections(vx_ver)

    if bootline is not None:
        accounts.append({
            'username': 'bootline',
            'password': bootline,
            'origin': 'usrBootLineInit',
            'services': []
        })

    for account in accounts:
        print_out('Account: %s' % json.dumps(account), script_name)

    for service in services:
        print_out('Service: %s' % json.dumps(service), script_name)

    # It's kind of gross, but since the protections aren't treated as an array, but a dictionary,
    # we print out one long line of json since we don't have the data model currently for these protections.
    print_out('Protections: %s' % json.dumps(protections), script_name)

