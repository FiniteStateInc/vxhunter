import sys
sys.path.insert(0, '.')

from vxutility.common import get_main_memory, auto_analyze, get_memory_blocks, print_err, print_out, get_args
from vxutility.symbol import add_symbol, get_symbol, create_symbol_table
from vxutility.symbol_table import get_symtab_bounds

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

    # Try to get the symbol table bounds
    symtab_bounds = None

    # It's possible that our firmware has been loaded with multiple memory blocks, maybe by a previous add-on.
    # The symbol table could be in any of them so we hafta search them all.
    for blk in get_memory_blocks():
        symtab_bounds = get_symtab_bounds(blk,
                                          vx_ver,
                                          add_symbol_wrapper)

        if symtab_bounds is not None:
            break


    if symtab_bounds is None:
        print_err('Could not find symbol table bounds', script_name)
        analyzeAll(currentProgram)
        return False

    print_out('Symbol table found from %08x to %08x' % symtab_bounds, script_name)
    symtab_start, symtab_end = symtab_bounds

    # Create the symbol table struct.
    create_symbol_table(symtab_start, symtab_end, vx_ver)

    return True


if __name__ == '__main__':
    script_name, vx_ver = get_args()
    if script_name is None or vx_ver is None:
        exit()

    # Try to get the symbol table/define the symbols.
    define_symbol_table(vx_ver)

