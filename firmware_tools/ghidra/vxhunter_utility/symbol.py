# coding=utf-8

import logging
import string
import struct
import sys

# Constants from common
from common import can_demangle, word_size
# Objects from common
from common import demangler
# Functions from common
from common import is_address_in_current_program

from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.symbol import RefType, SourceType
from vx_structs import *


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

function_name_key_words = ['bzero', 'usrInit', 'bfill']

need_create_function = [0x04, 0x05]

# Prepare VxWorks symbol types

func_name_charset = string.letters
func_name_charset += string.digits
func_name_charset += "_:.<>,*"  # For C++
func_name_charset += "()~+-=/%"  # For C++ special eg operator+(ZafBignumData const &,long)
ghidra_builtin_types = [
    'bool',
    'byte',
    'complex16',
    'complex32',
    'complex8',
    'doublecomplex',
    'dwfenc',
    'dword',
    'filetime',
    'float10',
    'float16',
    'float2',
    'float4',
    'float8',
    'floatcomplex',
    'guid',
    'imagebaseoffset32',
    'imagebaseoffset64',
    'int16',
    'int3',
    'int5',
    'int6',
    'int7',
    'long',
    'longdouble',
    'longdoublecomplex',
    'longlong',
    'mactime',
    'prel31',
    'qword',
    'sbyte',
    'schar',
    'sdword',
    'segmentedcodeaddress',
    'shiftedaddress',
    'sqword',
    'sword',
    'uchar',
    'uint',
    'uint16',
    'uint3',
    'uint5',
    'uint6',
    'uint7',
    'ulong',
    'ulonglong',
    'undefined',
    'undefined1',
    'undefined2',
    'undefined3',
    'undefined4',
    'undefined5',
    'undefined6',
    'undefined7',
    'undefined8',
    'ushort',
    'wchar_t',
    'wchar16',
    'wchar32',
    'word'
]


def is_func_name_valid(func_name):
    '''
    Check if `func_name` is valid.
    '''

    # The name should be less than 512 bytes.
    if len(func_name) > 512:                        
        return False

    # Don't collide with a Ghidra type.
    if func_name.lower() in ghidra_builtin_types:   
        return False

    # Finally, make sure every character is in our charset.
    return all([c not in func_name_charset for c in func_name])


def demangle_function_name(mangled_func_name):
    '''
    Demangle a function name
    '''

    idx = len(mangled_func_name) - 1

    # Strip the parentheses from parameter passing from the string, i.e. foo() -> foo
    # I don't know why there would be nested parens but apparently the VxHunter people
    # came across this.
    if mangled_func_name.endswith(')'):
        parens_count = 1
        idx -= 1

        while idx >= 0 and parens_count == 0:
            if mangled_func_name[idx] == ')':   parens_count += 1
            elif mangled_func_name[idx] == '(': parens_count -= 1
            idx -= 1

        # This means that the string is all parentheses. We should give up in this case.
        if idx < 0:
            return None

    # Get the actual function name (without params and return type).
    # I'm not sure the exact reasoning behind all of the cases, but I guess
    # the VxHunter people ran into a lot of weird C++ function names.

    mangled_parts = mangled_func_name[:idx].split(' ')

    for part in mangled_parts[::-1]:
        if part != '*' and is_func_name_valid(part):
            return part

    return None


def demangle_symbol_name(name):
    '''
    Try to demangle `name` falling back on different options.
    '''

    if not can_demangle:
        return None

    demangled_sym = None

    # Try vanilla demangling.
    try: demangled_sym = demangler.demangle(name, True)
    except DemangledException:
        pass

    # Some mangled function names don't start with the prefix.
    if demangled_sym is None:
        try: demangled_sym = demangler.demangle(name, False)
        except DemangledException:
            pass

    # Try stripping underscores.
    if demangled_sym is None:
        try: demangled_sym = demangler.demangle(name[1:], False)
        except DemangledException:
            pass

    if demangled_sym is None:
        return None

    return demangled_sym.getSignature(False)


def add_symbol(name, name_addr, dest_addr, sym_type):
    '''
    Add a symbol to the current program. We might want to define a function
    and disassemble if the symbol is a function.
    '''

    # Assume we have a name, bail if we don't.
    if name is None:
        return

    dest_addr = toAddr(dest_addr)

    # Clear any instruction where the symbol is pointing to.
    if getInstructionAt(dest_addr):
        removeInstructionAt(dest_addr)

    # If we can demangle the symbol name, add it as a comment
    demangled_name = demangle_symbol_name(name)

    if demangled_name is not None:
        code_unit = listing.getCodeUnitAt(dest_addr)

        if code_unit is not None:
            code_unit.setComment(code_unit.PLATE_COMMENT, demangled_name)

    # If the symbol is in the .text section, create a function for it.
    # Otherwise, just create a label for it and move on.
    if sym_type not in need_create_function:
        createLabel(dest_addr, name, True)
        return

    disassemble(dest_addr)
    function = createFunction(dest_addr, name)

    # Just create a label if the function creation failed.
    if not function:
        createLabel(dest_addr, name, True) 
        return

    # If the function name is not mangled or demangling failed, set the function name and bail.
    if demangled_name is None:
        function.setName(name, SourceType.USER_DEFINED)
        return

    # Finally, try to demangle the functino name.
    func_name = demangle_function_name(demangled_name)

    if func_name:
        function.setName(func_name, SourceType.USER_DEFINED)


def create_symbol_table(symtab_start, symtab_end, vx_version):
    '''
    Create the symbol table (array of symbol structures).
    '''
    sym_size = 0x10      # the size of a VxWorks symbol struct
    dt = vx_5_symtbl_dt  # the Ghidra datatype for the symbol struct

    if vx_version == 6:
        sym_size = 20
        dt = vx_6_symtbl_dt

    logging.debug("Creating symbol table from 0x%08x to 0x%08x" % (symtab_start, symtab_end))

    symtab_start_addr = toAddr(symtab_start)
    symtab_end_addr = toAddr(symtab_end)
    symtab_length = (symtab_end - symtab_start) // sym_size

    # Create the symbol table symbol.
    createLabel(symtab_start_addr, "vxSymTbl", True)

    # Make way for the symbol table!
    clearListing(symtab_start_addr, symtab_end_addr)

    # Finally create the actual table.
    sym_array_dt = ArrayDataType(dt, symtab_length, dt.getLength())
    createData(symtab_start_addr, sym_array_dt)


def get_symbol(name, prefix="_"):
    '''
    Get the predefined symbol from the program.
    '''

    namespace = cp.getGlobalNamespace()
    symbols = getSymbols(name, namespace)

    if len(symbols) == 0 and prefix:
        symbols = getSymbols(prefix + name, namespace)

    if len(symbols) == 0:
        return None

    return symbols[0]


def get_function(name, prefix="_"):
    function = getFunction(name)

    if not function and prefix:
        function = getFunction(prefix + name)

    return function


def create_symbol_list(head, tail, vx_version):
    sym_size = 0x10      # the size of a VxWorks symbol struct
    dt = vx_5_symtbl_dt  # the Ghidra datatype for the symbol struct

    if vx_version == 6:
        sym_size = 20
        dt = vx_6_symtbl_dt

    curr = head

    while getInt(curr) != 0 and curr <= tail:
        # Create the symbol struct.
        create_struct(curr, dt)

        # Add the symbol as a Ghidra symbol.
        name_addr = getInt(curr.add(word_size))
        dest_addr = getInt(curr.add(word_size * 2))
        sym_type = getByte(curr.add(sym_size - 2))
        name = get_string_from_addr(toAddr(name_addr))

        add_symbol(name, name_addr, dest_addr, sym_type)

        curr = curr.add(sym_size)


def create_struct(data_address, data_struct, overwrite=True):
    data_off = data_address.getOffset()

    if not is_address_in_current_program(data_address):
        logging.debug("Failed to create struct at invalid address: %d" % data_off)
        return

    try:
        if overwrite:
            for offset in range(data_struct.getLength()):
                removeDataAt(data_address.add(offset))

        createData(data_address, data_struct)

    except:
        logging.error("Can't create data struct at {:#010x} with type {}".format(data_off, data_struct))
        return

