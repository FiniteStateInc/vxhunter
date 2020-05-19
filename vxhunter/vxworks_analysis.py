import sys
sys.path.insert(0, '.')

import json
from functools import reduce

from ghidra.program.model.symbol import RefType, SourceType

from vxutility.common import *
from vxutility.function_analyzer import *
from vxutility.function_utils import get_func_addrs_and_set_signatures, cpy_func_signatures, is_func_called
from vxutility.symbol import *


SERVICE_FUNCS = {
    'wdbDbg': ['wdbDbgArchInit'],
    'ftpd': ['ftpdInit'],
    'tftpd': ['tftpdInit'],
    'snmpd': ['snmpdInit'],
    'sshd': ['sshdInit'],
    'shell': ['shellInit'],
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
            'kernel_text': ['sysTextProtect'],
            'user_text': ['usrTextProtect'],
        }
    },
    'user_task_stack_protection': {
        6: {
            'no_exec': ['taskStackNoExecEnable'],
            'guard_zones': ['taskStackGuardPageEnable']
        }
    },
    'password_protection': {
        6: {
            'telnet': ['usrSecurity']
        }
    }
}


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
    calls = get_all_calls_to_addr(target_function.getEntryPoint())

    if len(calls) == 0:
        print_err('Can\'t find any calls to vxSdaInit')
        return

    #min_call_addr = min(calls.keys())
    sda_reg_vals = emulate_func(target_function, ['r2', 'r13'])

    #next_insn_addr = fp.getInstructionAfter(min_call_addr).address
    min_addr = get_main_memory().start
    max_addr = get_main_memory().end
    prog_ctx = cp.programContext

    for reg, val in sda_reg_vals.items():
        print('Setting %s to %x starting at %s' % (reg.name, val, min_addr))
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
    calls = get_all_calls_to_addr(target_function.getEntryPoint(), 
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

    calls = get_all_calls_to_addr(call_address=target_function.entryPoint)

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

    # Get the address for the two functions we have seen to copy the bootline.
    cpy_func_addrs = get_func_addrs_and_set_signatures(cpy_func_signatures, script_name=script_name)

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


def get_login_function(func_name, param_idxs, associated_services=[]):
    global script_name

    accounts = []

    target_function = get_function(func_name)
    min_num_params = max(param_idxs.values()) + 1

    if target_function is None:
        print_err('Can\'t find function %s' % func_name, script_name)
        return accounts

    # Get all calls to the login function.
    calls = get_all_calls_to_addr(target_function.getEntryPoint())

    for call_addr, params in calls.items():
        # Make sure we at least were able to get the value of the username and password params.
        if len(params) < min_num_params: 
            continue

        account = { 
            'services': associated_services,
            'origin': func_name
        }

        for param_name, param_idx in param_idxs.items():
            if param_idx >= len(params):
                print_err('%s is not a valid param index' % param_name)

            if params[param_idx] is None:
                print_err('%s is None' % param_name)
                continue

            param = params[param_idx]
            param_val = maybe_get_string_at(fp.toAddr(param))

            if param_val is None:
                print_err('%s is None' % param_name)
                continue

            account[param_name] = param_val

        accounts.append(account)

    return accounts


def get_login_accouts():
    '''
    Try to find hardcoded user accounts.
    '''
    accounts = []

    login_user_add_params = {
        'username': 0,
        'password_hash': 1
    }

    ipcom_auth_useradd_params = {
        'username': 0,
        'password': 1
    }

    accounts.extend(get_login_function('loginUserAdd', login_user_add_params, associated_services=['shell']))
    accounts.extend(get_login_function('ipcom_auth_useradd', ipcom_auth_useradd_params, associated_services=['ssh']))

    return accounts


def get_available_services(vx_ver):
    '''
    Use known function names to determine if services such as telnet, ftp, and wdbg are enabled.

    TODO: Make sure that the service isn't disabled after being enabled.
    '''
    services = []

    for service_name, funcs in SERVICE_FUNCS.items():
        service = {
            'name': service_name,
            'version': vx_ver,
            'enabled': False
        }

        for func in funcs:
            service['enabled'] = is_func_called(func)

            # If one of the functions was called, chalk it up as a win and move on
            if service['enabled']:
                break

        services.append(service)

    return services


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
            for func in prot_funcs:
                prots[prot_name] = is_func_called(func)

                # Like in the services, break if one of the functions is called
                if prots[prot_name]:
                    break

        protections[prot_category_name] = prots

    return protections


if __name__ == '__main__':
    script_name, vx_ver = get_args()
    if script_name is None or vx_ver is None:
        exit()

    # Try to enrich the database by adding x-refs, mapping memory, etc.
    get_sda_regs()
    create_bss()
    add_function_xrefs_from_symbol_find()

    # Look at VxWorks specific functions to try to improve the analysis report.
    accounts = get_login_accouts()
    bootline = get_bootline()
    services = get_available_services(vx_ver)
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

