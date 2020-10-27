import string
import struct
import sys
import ghidra
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.data import ArrayDataType

from common import word_size, cp, fp, is_address_in_current_program, print_out, print_err
from vx_structs import *


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

    dest_addr = fp.toAddr(dest_addr)

    # Clear any instruction where the symbol is pointing to.
    if fp.getInstructionAt(dest_addr):
        fp.removeInstructionAt(dest_addr)

    # If the symbol is in the .text section, create a function for it.
    # Otherwise, just create a label for it and move on.
    if sym_type not in need_create_function:
        fp.createLabel(dest_addr, name, True)
        return

    # Strip "_" from the beginning of functions
    name = name.lstrip("_")
    fp.disassemble(dest_addr)
    function = fp.createFunction(dest_addr, name)

    # Just create a label if the function creation failed.
    if not function:
        fp.createLabel(dest_addr, name, True)
        return

    try:
        function.setName(name, SourceType.USER_DEFINED)
    except ghidra.util.exception.DuplicateNameException:
        # if something already exists here, just continue
        pass


def create_symbol_table(symtab_start, symtab_end, vx_version):
    '''
    Create the symbol table (array of symbol structures).
    '''
    sym_size = 0x10      # the size of a VxWorks symbol struct
    dt = vx_5_symtbl_dt  # the Ghidra datatype for the symbol struct

    if vx_version == 6 or vx_version == 7:
        sym_size = 20
        dt = vx_6_symtbl_dt

    # Set symtab_end to point to the *end* of the last symbol.
    symtab_end += sym_size

    symtab_start_addr = fp.toAddr(symtab_start)
    symtab_end_addr = fp.toAddr(symtab_end)
    symtab_length = (symtab_end - symtab_start) // sym_size

    # Create the symbol table symbol.
    fp.createLabel(symtab_start_addr, "vxSymTbl", True)

    # Make way for the symbol table (end address is inclusive)!
    fp.clearListing(symtab_start_addr, symtab_end_addr.subtract(1))

    # Finally create the actual table.
    sym_array_dt = ArrayDataType(dt, symtab_length, dt.getLength())

    try:
        fp.createData(symtab_start_addr, sym_array_dt)
    except CodeUnitInsertionException:
        return


def get_symbol(name, prefix="_"):
    '''
    Get the predefined symbol from the program.
    '''
    namespace = cp.getGlobalNamespace()
    symbols = fp.getSymbols(name, namespace)

    if len(symbols) == 0 and prefix:
        symbols = fp.getSymbols(prefix + name, namespace)

    if len(symbols) == 0:
        return None

    return symbols[0]


def get_function(name, prefix="_"):
    function = fp.getFunction(name)

    if not function and prefix:
        function = fp.getFunction(prefix + name)

    return function


def create_struct(data_address, data_struct, overwrite=True):
    data_off = data_address.getOffset()

    if not is_address_in_current_program(data_address):
        print_err("Failed to create struct at invalid address: %d" % data_off)
        return

    try:
        if overwrite:
            for offset in range(data_struct.getLength()):
                fp.removeDataAt(data_address.add(offset))

        fp.createData(data_address, data_struct)

    except CodeUnitInsertionException:
        print_err("Can't create data struct at {:#010x} with type {}".format(data_off, data_struct))
        return

