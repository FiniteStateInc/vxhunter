import struct as st

from common import endy_str, word_str, word_size, read_data_at, get_string_from_addr

# VxWorks versions supported
SUPPORTED_VX_VERSIONS = [5, 6]

# Symbol types for VxWorks 5.5
VX5_SYM_TYPES = [
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x06,  # Local Data
    0x07,  # Global Data
    0x08,  # Local BSS
    0x09,  # Global BSS
    0x12,  # Local Common symbol
    0x13,  # Global Common symbol
    0x40,  # Local Symbols related to a PowerPC SDA section
    0x41,  # Global Symbols related to a PowerPC SDA section
    0x80,  # Local symbols related to a PowerPC SDA2 section
    0x81,  # Local symbols related to a PowerPC SDA2 section
]

# Symbol types for VxWorks 6.8
VX6_SYM_TYPES = [
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x08,  # Local Data
    0x09,  # Global Data
    0x10,  # Local BSS
    0x11,  # Global BSS
    0x20,  # Local Common symbol
    0x21,  # Global Common symbol
    0x40,  # Local Symbols
    0x41,  # Global Symbols
]

# Dictionary mapping vx version to symbol types
SYM_TYPES = {
    5: VX5_SYM_TYPES,
    6: VX6_SYM_TYPES
}

# Symbol types that live in the .text section
TEXT_SYM_TYPES = {
    5: [4, 5],
    6: [4, 5]
}

# Symbol types that live in the .data section
DATA_SYM_TYPES = {
    5: [6, 7],
    6: [8, 9]
}

# The amount of entries in a candidate symbol table needed for it to be chosen as the actual symbol table
SYMTAB_MIN_COUNT = 100


def log(s, logger, verbose):
    if not verbose:
        return

    # TODO: Figure out how to make this formatting not look weird
    if logger is None: print(s)
    else:              logger.info(s)



def get_symbol_fmt(endy_str, word_size_str, vx_ver):
    '''
    Return the `struct` format for the symbol struct depending on the VxWorks version and the size of said struct.
    Note: This function assumes that `vx_ver` has already been validated.
    '''
    if vx_ver == 5: fmt = endy_str + (word_size_str * 3) + 'H' + 'BB'
    else:           fmt = endy_str + (word_size_str * 4) + 'H' + 'BB'

    return fmt, st.calcsize(fmt)



def sym_dict(offset, name_ptr, val_ptr, grp, sym_type, null):
    return { 
        'name_addr': name_ptr, 
        'dest_addr': val_ptr, 
        'flag': sym_type, 
        'offset': offset 
    }



def is_sym_valid(sym_types, name_ptr, val_ptr, grp, sym_type, null):
    is_sym = True
    is_sym &= sym_type in sym_types # expect that the symbol type is in the list of symbol types for the vx version
    is_sym &= null == 0             # expect that the null struct-terminator is indeed null
    is_sym &= grp == 0              # expect that the symbol group is null
    is_sym &= name_ptr != 0         # expect that the symbol name is not null
    return is_sym



def parse_sym(offset, sym_st_fmt, sym_size, sym_types, verbose=False, logger=None):
    '''
    Return a symbol dictionary and whether or not said symbol is valid for the current VxWorks version.
    '''
    bs = read_data_at(offset, sym_size)
    fields = list(st.unpack(sym_st_fmt, bs))

    # if the symbol is a VxWorks 6 symbol, delete the fourth field since it's not checked anyways
    if len(fields) == 7:
        del fields[3]

    # the first field doesn't matter either, trim it
    del fields[0]

    # return the symbol and whether or not it is valid
    return sym_dict(offset, *fields), is_sym_valid(sym_types, *fields)
    

def get_symtab_bounds(blk, vx_ver, symbol_fn, verbose=False, logger=None):
    '''
    Try to get the VxWorks 5 or 6 symbol table.
    '''
    if vx_ver not in SUPPORTED_VX_VERSIONS:
        log('VxWorks version ', vx_ver, ' is currently not supported', logger, True)
        return []

    sym_st_fmt, sym_st_size = get_symbol_fmt(endy_str, word_str, vx_ver)
    sym_types = SYM_TYPES[vx_ver]

    symtab = []
    i = blk.start.offset

    while i < blk.end.offset - sym_st_size:
        sym, sym_valid = parse_sym(i, sym_st_fmt, sym_st_size, sym_types, verbose, logger)

        # if the current symbol struct is not a valid symbol, only increment the cursor by `word_size` bytes
        # in case we are unaligned with the symbol table (this assumes the symbol table is word-aligned)
        if sym is None or not sym_valid:
            symtab = []
            i += word_size
            continue

        name_addr = sym['name_addr']

        # the name pointer must be within the bounds of the memory block
        if name_addr < blk.start.offset or name_addr >= blk.end.offset:
            symtab = []
            i += word_size
            continue

        sym_type = sym['flag']

        # if the symbol type resides in the .text or .data section, make sure it's dest pointer is within the block
        if sym_type in TEXT_SYM_TYPES[vx_ver] or sym_type in DATA_SYM_TYPES[vx_ver]:
            dest_addr = sym['dest_addr']

            if dest_addr < blk.start.offset or dest_addr >= blk.end.offset:
                symtab = []
                i += word_size
                continue

        if i == 0x636168:
            print('dest address in')

        symtab.append(sym)

        # increase the cursor by the symbol size since we have a valid symbol
        i += sym_st_size

        # if we have 100 consecutive symbols, assume that this is indeed the symbol table
        if len(symtab) >= SYMTAB_MIN_COUNT:
            break

    
    # throw out the candidate symbol table and return if it's below the threshold count
    if len(symtab) < SYMTAB_MIN_COUNT:
        log('Only %d consecutive symbols found' % len(symtab), logger, verbose)
        return None

    symtab = sorted(symtab, key=lambda x: x['offset'])
    symtab_start = symtab[0]['offset']
    symtab_end = symtab[-1]['offset']

    # add the current symbols to the program
    for sym in symtab:
        sym['name'] = get_string_from_addr(sym['name_addr'])
        symbol_fn(sym)
    
    # get the rest of the symbol table and them to the program
    for i in range(i, blk.end.offset - sym_st_size, sym_st_size):
        sym, sym_valid = parse_sym(i, sym_st_fmt, sym_st_size, sym_types, verbose, logger)

        # once we have seen an invalid symbol or failed at reading, break out of the loop
        if sym is None or not sym_valid:
            break

        # update the symbol table end and add the symbol to the program
        symtab_end = sym['offset']

        sym['name'] = get_string_from_addr(sym['name_addr'])
        symbol_fn(sym)

    log('Symbol table ends at 0x%08x' % (i - sym_st_size), logger, verbose)

    return symtab_start, symtab_end


