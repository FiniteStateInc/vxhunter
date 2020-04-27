# coding=utf-8
import logging

from vxhunter_utility.common import get_vxworks_version, get_main_memory, auto_analyze, get_memory_blocks
from vxhunter_utility.symbol import add_symbol, get_symbol, create_symbol_table
from vxhunter_utility.symbol_table import get_symtab_bounds
from analysis import VxAnalyzer


def define_symbol_table():
    # Don't do anything if the symbol table already exists.
    if get_symbol('vxSymTbl') is not None:
        return True

    '''
    blk = get_main_memory()
    if blk is None:
        logging.error('No main memory block in program.')
        return False
    '''

    # Try to get the symbol table bounds
    symtab_bounds = None

    for blk in get_memory_blocks():
        symtab_bounds = get_symtab_bounds(blk,
                                          vx_ver,
                                          add_symbol_wrapper,
                                          verbose=True,
                                          logger=logging)

        if symtab_bounds is not None:
            break


    if symtab_bounds is None:
        logging.error('Could not find symbol table bounds.')
        return False

    logging.info(symtab_bounds)
    symtab_start, symtab_end = symtab_bounds

    # Create the symbol table struct.
    create_symbol_table(symtab_start, symtab_end, vx_ver)

    return True


def add_symbol_wrapper(sym):
    add_symbol(sym['name'], sym['name_addr'], sym['dest_addr'], sym['flag'])


if __name__ == '__main__':
    # Start by getting the VxWorks version (currently only 5 and 6 are supported).
    vx_ver = get_vxworks_version()

    if vx_ver is None:
        logging.error('Couldn\'t get a VxWorks version. Aborting.')
        exit()

    # Only perform the analysis if we have a symbol table.
    if not define_symbol_table():
        # Since we run this script before Ghidra auto-analysis, if we don't
        # find a symbol, table we should at least auto-analyze the program.
        auto_analyze()
        exit()

    analyzer = VxAnalyzer()
    analyzer.analyze()

    print(analyzer.report)

