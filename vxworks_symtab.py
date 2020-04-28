import sys
sys.path.insert(0, '.')

from utility.common import get_main_memory, auto_analyze, get_memory_blocks, print_err, print_out, SUPPORTED_VX_VERSIONS
from utility.symbol import add_symbol, get_symbol, create_symbol_table
from utility.symbol_table import get_symtab_bounds

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
        return False

    print_out('Symbol table found from %08x to %08x' % symtab_bounds, script_name)
    symtab_start, symtab_end = symtab_bounds

    # Create the symbol table struct.
    create_symbol_table(symtab_start, symtab_end, vx_ver)

    return True


script_name = None
vx_ver = None

if isRunningHeadless():
    # Start by making sure we were passed a script name and a VxWorks version (5 or 6)
    args = getScriptArgs()

    if len(args) < 2:
        print_err('Must pass a script name and a VxWorks version')
        exit()

    # Make sure our VxWorks version is valid
    script_name = args[0]
    vx_ver = args[1]
else:
    script_name = sys.argv[0]
    vx_ver = int(askChoice('Pick a VxWorks Version', '...if you dare!', SUPPORTED_VX_VERSIONS, SUPPORTED_VX_VERSIONS[0]))

if vx_ver not in SUPPORTED_VX_VERSIONS:
    print_err('VxWorks version must be in %s' % ', '.join([int(v) for v in SUPPORTED_VX_VERSIONS]), script_name)
    exit()

# Try to get the symbol table/define the symbols.
define_symbol_table(vx_ver)

