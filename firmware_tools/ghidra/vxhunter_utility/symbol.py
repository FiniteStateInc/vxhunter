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

    function.setName(name, SourceType.USER_DEFINED)


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

