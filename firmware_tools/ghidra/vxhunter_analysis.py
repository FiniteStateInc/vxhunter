import json

from ghidra.program.model.symbol import RefType, SourceType

from vxhunter_core import *
from vxhunter_utility.common import *
from vxhunter_utility.function_analyzer import *
from vxhunter_utility.symbol import *


class VxAnalyzer(object):
    def __init__(self, logger=None):
        self.vx_version = get_vxworks_version()

        # `report` is a dictionary of the results of all the different analyses.
        self.report = {}

        self.logger = logger

        if logger is None:
            self.logger = logging.getLogger('Analyzer')
            init_logger(self.logger)


    def create_bss(self):
        '''
        Get the parameters passed to bzero when called from sysStart or usrInit.
        Based on the start and length, create a bss memory region.
        '''
        logging.info('[Analyzing bss section]')

        target_function = get_function('bzero')

        if not target_function:
            logging.error('Can\'t find bzero function in firmware')
            return

        # Get the parameters of all calls to bzero in sysStart and usrInit.
        calls = get_all_call_info(target_function.getEntryPoint(), 
                                  search_funcs=['sysStart', 'usrInit'])

        for call_addr, call_data in calls.items():
            if not 'params' in call_data:
                continue

            params = call_data['params']

            # bzero takes an address and size.
            if len(params) != 2: 
                continue
 
            bss_start, bss_len = tuple(params)

            if bss_start is None or bss_len is None:
                continue

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
                    logging.error('Couldn\'t split main memory')
                    continue

                if len(cp.memory.blocks) < 2:
                    continue

                bss_file_block = cp.memory.blocks[1]

                bss_len -= max_addr - bss_end            
                bss_block = create_initialized_block('.bss', toAddr(max_addr), bss_len)

                if bss_block is None:
                    logging.error('Couldn\'t create bss block')
                    continue

                if not join_blocks(bss_file_block, bss_block):
                    logging.error('Couldn\'t join blocks')
                    continue

                if len(cp.memory.blocks) < 2:
                    continue

                cp.memory.blocks[1].setName('.bss')
                analyzeChanges(cp)
                break

            logging.info('Creating bss block from 0x%x to 0x%x' % (bss_start, bss_end))

            # Create the bss region in memory.
            if not create_initialized_block('.bss', toAddr(bss_start), bss_len):
                logging.error('Can\'t create bss block, you can create it manually')

            # Ghidra can probably create more xrefs to the bss section now so let's not stop it.
            analyzeChanges(cp)

            # Once we've created the region, we're done here.
            break


    def analyze_login_function(self, func_name, user_param_idx, pw_param_idx):
        logging.info('[Analyzing %s]' % func_name)

        target_function = get_function(func_name)

        if not target_function:
            logging.info('Can\'t find function %s' % func_name)
            return

        # Get all calls to the login function.
        calls = get_all_call_info(target_function.getEntryPoint())

        for call_addr, call_data in calls.items():
            if not 'params' in call_data:
                continue

            params = call_data['params']

            # Make sure we at least were able to get the value of the username and password params.
            if len(params) < max(user_param_idx, pw_param_idx): 
                continue

            user, pw = params[user_param_idx], params[pw_param_idx]

            user_str = get_string_from_addr(toAddr(user))
            pw_str = get_string_from_addr(toAddr(pw))

            logging.info('Found account: user: %s, password hash: %s' % (user_str, pw_str))
            self.report['accounts'].append({ 'username': user_str, 'password': pw_str })


    def analyze_login_accouts(self):
        '''
        Try to find hardcoded user accounts.
        '''
        logging.info('[Analyzing accounts]')
        self.report['accounts'] = []

        self.analyze_login_function('loginUserAdd', 0, 1)
        self.analyze_login_function('ipcom_auth_useradd', 0, 1)


    def analyze_available_services(self):
        '''
        Use known function names to determine if services such as telnet, ftp, and wdbg are enabled.

        TODO: Actually check whether or not these functions are called (and not later disabled).
        '''
        logging.info('[Analyzing services]')
        self.report['services'] = []

        for service, funcs in vxworks_service_keyword.items():
            for func in funcs:
                target_function = get_function(func)

                if target_function:
                    logging.info('%s is available' % service)
                    self.report['services'].append(service)


    def add_system_symbols(self):
        '''
        Try to analyze the system symbol table for VxWorks 5. I guess sometimes, vxSymTbl and sysSymTbl
        contain different symbols, so we want to create those symbols if they exist.
        '''
        if not self.vx_version or self.vx_version != 5:
            return

        logging.info('[Analyzing symbols]')

        # Assert that we have a valid `sysSymTbl` symbol and that it points
        # to a valid memory location.

        sys_sym_tbl = get_symbol('sysSymTbl')

        if not sys_sym_tbl:
            return

        sys_sym_tbl_addr = sys_sym_tbl.getAddress()

        if not is_address_in_current_program(sys_sym_tbl_addr):
            logging.info("sysSymTbl at 0x%08x is not a valid pointer" % sys_sym_off)
            return

        sys_sym_addr = toAddr(getInt(sys_sym_tbl_addr))
        sys_sym_off = sys_sym_addr.getOffset()

        if sys_sym_off == 0 or (not is_address_in_current_program(sys_sym_addr)):
            logging.info("sysSymTbl at 0x%08x is not a valid pointer" % sys_sym_off)
            return

        function_man = cp.getFunctionManager()
        function_count = function_man.getFunctionCount()

        logging.info(("Function count before symbol table fixup: %d" % function_count))

        # Create the symbol table.
        create_struct(sys_sym_addr, vx_5_sys_symtab)

        # Create the hash table for the symbol table.
        hash_tbl_addr = toAddr(getInt(sys_sym_addr.add(0x04)))
        create_struct(hash_tbl_addr, vx_5_hash_tbl)

        # Create the hash table list.
        hash_tbl_length = getInt(hash_tbl_addr.add(0x04))
        hash_tbl_array_addr = toAddr(getInt(hash_tbl_addr.add(0x14)))
        hash_tbl_array_data_type = ArrayDataType(vx_5_sl_list, hash_tbl_length, vx_5_sl_list.getLength())
        create_struct(hash_tbl_array_addr, hash_tbl_array_data_type)

        for i in range(hash_tbl_length):
            head = toAddr(getInt(hash_tbl_array_addr.add(i * 8)))
            tail = toAddr(getInt(hash_tbl_array_addr.add((i * 8) + 0x04)))

            if is_address_in_current_program(head) and is_address_in_current_program(tail):
                create_symbol_list(head, tail, self.vx_version)

        # Re-analyze after creating the new symbols.
        analyzeChanges(cp)

        function_count = function_man.getFunctionCount()
        logging.info("Function count after symbol table fixup: %d" % functions_count_after)


    def add_function_xrefs_from_symbol_find(self):
        '''
        Sometimes, a function will be referenced in code by:

            symFindByName(..., function name, ...)

        In which case, we want to add an xref to that function since it is an indirect
        reference Ghidra won't pick up on.
        '''
        logging.info('[Analyzing symFindByName]')

        target_function = get_function("symFindByName")

        if not target_function:
            logging.error("Can't find symFindByName function in firmware")
            return

        calls = get_all_call_info(call_address=target_function.getEntryPoint())

        logging.debug("Found %d symFindByName call" % len(calls))

        ref_man = cp.getReferenceManager()

        for call_addr, call_info in calls.items():
            if not 'params' in call_info:
                continue

            params = call_info['params']

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
                logging.error("Symbol %s is not a function" % name)
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


    def start_analyzer(self):
        self.create_bss()
        self.add_system_symbols()
        self.add_function_xrefs_from_symbol_find()
        self.analyze_login_accouts()
        self.analyze_available_services()


if __name__ == '__main__':
    analyzer = VxAnalyzer()
    analyzer.start_analyzer()
    print(analyzer.report)
