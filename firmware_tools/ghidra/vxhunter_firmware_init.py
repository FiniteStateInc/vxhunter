# coding=utf-8
import logging

from vxhunter_core import VxTarget
from vxhunter_utility.common import *
from vxhunter_utility.symbol import add_symbol, create_symbol_table

from ghidra.util.task import TaskMonitor


def rebase_image(target):
    '''
    Rebase the firmware to the load address found the base finder
    '''
    load_address = target.load_address

    # Rebase the image.
    blocks = cp.memory.blocks

    if len(blocks) == 0:
        logging.error('No valid memory blocks on the program')
        return False

    target_block = cp.memory.blocks[0]
    address = toAddr(load_address)

    logging.info("Rebasing to 0x%08x" % address.offset)

    return move_block(target_block, address)


def process_symbol_table(target):
    '''
    Create the symbol table and add all of the symbols.
    '''
    if not target.has_symbol_table():
        logging.error('No symbol table found in binary. Aborting.')
        return

    logging.info("Creating symbol table")

    symtab_start = target.symtab_start + target.load_address
    symtab_end = target.symtab_end + target.load_address

    # Create the symbol table struct.
    create_symbol_table(symtab_start, symtab_end, vx_version)

    # Define each symbol individually.
    for symbol in target.symbols:
        add_symbol(symbol['name'], 
                   symbol['name_addr'], 
                   symbol['dest_addr'], 
                   symbol['flag'])


if __name__ == '__main__':
    # Start by getting the VxWorks version (currently only 5 and 6 are supported)
    vx_version = get_vxworks_version()

    if vx_version is None:
        exit()

    # Get some metadata about the program needed to find the base address
    firmware_path = cp.domainFile.getMetadata()['Executable Location']
    firmware = open(firmware_path, 'rb').read()

    # VxTarget's init will exit if a valid base address isn't found, therefore we don't have to check after here
    target = VxTarget(firmware_path=firmware_path, 
                      firmware=firmware, 
                      vx_version=vx_version, 
                      big_endian=is_big_endian, 
                      word_size=word_size)

    # If we can't rebase the image, it's not even worth going on.
    if not rebase_image(target):
        exit()

    process_symbol_table(target)

    # Ghidra probably has something to say after all the changes we've made.
    #logging.info('Re-analyzing')
    #analyze(cp)

