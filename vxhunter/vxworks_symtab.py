import sys

sys.path.insert(0, '.')

from vxutility.common import get_memory_blocks, print_err, print_out, get_args, get_image_base, maybe_get_string_at
from vxutility.symbol import add_symbol, get_symbol, create_symbol_table
from vxutility.symbol_table import get_symtab_bounds, fix_image_base

SYMBOL_KEYS = ['name', 'name_addr', 'dest_addr', 'flag']


def add_symbol_wrapper(sym):
    if not all([k in sym for k in SYMBOL_KEYS]):
        return

    add_symbol(*[sym[k] for k in SYMBOL_KEYS])


def define_symbol_table(vx_ver):
    global script_name

    # Don't do anything if the symbol table already exists.
    if get_symbol('vxSymTbl') is not None:
        print_out('Symbol table already defined', script_name)
        return True

    # It's possible that our firmware has been loaded with multiple memory blocks, maybe by a previous add-on.
    # The symbol table could be in any of them so we hafta search them all
    # Try to get the symbol table bounds
    symtab_bounds = None
    for blk in get_memory_blocks():
        symtab_bounds = get_symtab_bounds(blk, vx_ver, add_symbol_wrapper)

        if symtab_bounds is not None:
            break

    if symtab_bounds is None:
        #print_err('Could not find symbol table bounds', script_name)
        raise RuntimeError('Could not find symbol table bounds', script_name)
        # analyzeAll(currentProgram)
        #return False

    symtab_start, symtab_end = symtab_bounds
    print_out('Symbol table found from %08x to %08x' % (symtab_start, symtab_end))

    # Create the symbol table struct.
    create_symbol_table(symtab_start, symtab_end, vx_ver)

    return True


if __name__ == '__main__':
    script_name, vx_ver = get_args()
    if script_name is None or vx_ver is None:
        exit()

    # Try to get the symbol table/define the symbols.
    try:
       define_symbol_table(vx_ver)
    except (ghidra.util.exception.InvalidInputException, RuntimeError):
        # stuff went wrong!!! we should try see if rebasing will work
        if 0 == get_image_base().offset and 1 == len(get_memory_blocks()):
            # 0 should not be a valid memory address, and we have a monolithic image
            # so proceed with trying to determine the base
            blk = get_memory_blocks()[0]
            base = fix_image_base(blk, vx_ver)
            if base:
                print_out('Fixed Base: 0x%08x' % base)

                define_symbol_table(vx_ver)
            else:
                print_err('Sorry couldn\'t rebase the binary')