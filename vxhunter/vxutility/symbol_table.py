import re
import struct
import struct as st
import sys

from common import endy_str, word_str, word_size, read_data_at, maybe_get_string_at, is_offset_in_current_program, \
    find_bytes_address, print_out, set_base_address, get_is_big_endian

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

# Symbol types for VxWorks 6.8 -- also 7
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
    6: VX6_SYM_TYPES,
    7: VX6_SYM_TYPES  # same as 6
}

# Symbol types that live in the .text section
TEXT_SYM_TYPES = {5: [4, 5], 6: [4, 5], 7: [4, 5]}

# Symbol types that live in the .data section
DATA_SYM_TYPES = {5: [6, 7], 6: [8, 9], 7: [8, 9]}

# The amount of entries in a candidate symbol table needed for it to be chosen as the actual symbol table
SYMTAB_MIN_COUNT = 100


def get_symbol_fmt(endy_str, word_size_str, vx_ver):
    '''
    Return the `struct` format for the symbol struct depending on the VxWorks version and the size of said struct.
    Note: This function assumes that `vx_ver` has already been validated.
    '''
    if vx_ver == 5:
        fmt = endy_str + (word_size_str * 3) + 'H' + 'BB'
    else:
        fmt = endy_str + (word_size_str * 4) + 'H' + 'BB'

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
    is_sym &= sym_type in sym_types  # expect that the symbol type is in the list of symbol types for the vx version
    is_sym &= null == 0  # expect that the null struct-terminator is indeed null
    is_sym &= grp == 0  # expect that the symbol group is null
    is_sym &= name_ptr != 0  # expect that the symbol name is not null
    return is_sym


def parse_sym(offset, sym_st_fmt, sym_size, sym_types):
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


def fix_image_base(blk, vx_ver):
    """Note: this may seem redundant to duplicate effort, trying to find symtable here and then again
    in get_symtab_bounds(). However rebasing is needed
    """
    sym_st_fmt, sym_st_size = get_symbol_fmt(endy_str, word_str, vx_ver)
    sym_types = SYM_TYPES[vx_ver]

    left_off, symtab = find_sym_table(blk, blk.start.offset, sym_st_fmt, sym_st_size, sym_types, vx_ver)
    if len(symtab) < SYMTAB_MIN_COUNT:
        # If no matches were found it could be that they were thrown out because the offset is so large
        # that none of the syms match fall in the memory range of the image.
        # Try again, this time without verifying the addresses.
        left_off, symtab = find_sym_table(blk, blk.start.offset, sym_st_fmt, sym_st_size, sym_types, vx_ver,
                                          verify_addresses=False)

        # throw out the candidate symbol table and return if it's below the threshold count
        if len(symtab) < SYMTAB_MIN_COUNT:
            return None

    #for sym in symtab:
    #    print_out("name 0x%08x" %sym['name_addr'])

    symtab = sorted(symtab, key=lambda x: x['offset'])

    # if we have a block at offset zero, it's probably not correct...
    if 0 == blk.start.offset:
        new_base = try_rebase(blk, symtab, vx_ver)
        if new_base:
            return new_base

    return None


def get_symtab_bounds(blk, vx_ver, symbol_fn):
    '''
    Try to get the VxWorks 5, 6, or 7 symbol table.
    '''
    sym_st_fmt, sym_st_size = get_symbol_fmt(endy_str, word_str, vx_ver)
    sym_types = SYM_TYPES[vx_ver]

    left_off, symtab = find_sym_table(blk, blk.start.offset, sym_st_fmt, sym_st_size, sym_types, vx_ver)

    # throw out the candidate symbol table and return if it's below the threshold count
    if len(symtab) < SYMTAB_MIN_COUNT:
        return None

    symtab = sorted(symtab, key=lambda x: x['offset'])
    symtab_start = symtab[0]['offset']
    symtab_end = symtab[-1]['offset']

    print_out('Initial Symbol table found from %08x to %08x' % (symtab_start, symtab_end))

    # add the current symbols to the program
    for sym in symtab:
        name = maybe_get_string_at(sym['name_addr'])
        sym['name'] = name

        if name is not None:
            symbol_fn(sym)

    # get the rest of the symbol table and them to the program
    for i in range(left_off, blk.end.offset - sym_st_size, sym_st_size):
        sym, sym_valid = parse_sym(i, sym_st_fmt, sym_st_size, sym_types)

        # once we have seen an invalid symbol or failed at reading, break out of the loop
        if sym is None or not sym_valid:
            break

        # update the symbol table end and add the symbol to the program
        symtab_end = sym['offset']

        name = maybe_get_string_at(sym['name_addr'])
        sym['name'] = name

        if name is not None:
            symbol_fn(sym)

    return symtab_start, symtab_end


def find_sym_table(blk, start_addr, sym_st_fmt, sym_st_size, sym_types, vx_ver, verify_addresses=True):
    i = start_addr
    symtab = []
    while i < blk.end.offset - sym_st_size:

        sym, sym_valid = parse_sym(i, sym_st_fmt, sym_st_size, sym_types)

        # if the current symbol struct is not a valid symbol, only increment the cursor by `word_size` bytes
        # in case we are unaligned with the symbol table (this assumes the symbol table is word-aligned)
        if sym is None or not sym_valid:
            symtab = []
            i += word_size
            continue

        name_addr = sym['name_addr']

        # the name pointer must be within the bounds of the memory block
        # if name_addr < blk.start.offset or name_addr >= blk.end.offset:
        if verify_addresses:
            if not is_offset_in_current_program(name_addr):
                symtab = []
                i += word_size
                continue

        sym_type = sym['flag']

        # if the symbol type resides in the .text or .data section, make sure it's dest pointer is within the block
        if sym_type in TEXT_SYM_TYPES[vx_ver] or sym_type in DATA_SYM_TYPES[vx_ver]:
            dest_addr = sym['dest_addr']

            # if dest_addr < blk.start.offset or dest_addr >= blk.end.offset:
            if verify_addresses:
                if not is_offset_in_current_program(dest_addr):
                    symtab = []
                    i += word_size
                    continue

        sys.stdout.write('.')
        symtab.append(sym)

        # increase the cursor by the symbol size since we have a valid symbol
        i += sym_st_size

        # if we have 100 consecutive symbols, assume that this is indeed the symbol table
        if len(symtab) >= SYMTAB_MIN_COUNT:
            break

    return i, symtab


def try_rebase(blk, sym_table, vx_ver):
    '''Detected that base is probably not right. This will cause symbols to not be generated correctly
    So try to find the strings table with function symbol names
    Find the highest pointer to a function name,
    Subtract the two, AND by 0xFFFF0000 to get an offset that we can apply
    '''
    sym_address = None

    # 'VxWorks' occurs just before the table of function name strings. this doesn't need to be perfect
    # just need something close to the start of the table will do.
    # Probably need to make this more robust, need to test with a larger set of images.
    if vx_ver > 5:
        search_str = '\x00VxWorks\x00'
    else:
        search_str = '\x00_GLOBAL_\x00'

    search_result = find_bytes_address(blk.start.offset, search_str)
    if search_result:
        sym_address = int(search_result.toString(), 16)
        # since we're searching with a leading null, we need to increment address by 1.
        sym_address = sym_address + 1

        max_ptr = 0
        for sym in sym_table:
            if sym['name_addr'] > max_ptr:
                max_ptr = sym['name_addr']

        print_out(
            'Base doesn\'t look correct... trying to verify base is correct (name_addr)%08x - (Key_string)%08x' % (
                max_ptr, sym_address))
        initial_offset = (max_ptr - sym_address) & 0xFFF00000
        print_out('initial_offset: 0x%08x' % initial_offset)

        offset = fuzzy_search_for_function_names(initial_offset, sym_table)

        if offset:
            print_out('Believe the base address is incorrect... trying to fix it... Fingers crossed')
            set_base_address(offset)
            return offset

    return None


def is_valid_function_name(name):
    return re.search(r'^[A-Za-z_0-9-]+$', name)


def fuzzy_search_for_function_names(offset, sym_table):
    """There doesn't seem to be a specific MASK that we can apply that works for all images, so lets try incrementing
    with 0x1000 steps, and determine if there is an offset where all the names resolve correctly.
    """
    for i in range(0, 0xF0000, 0x1000):
        invalid_function_found = False
        curr_offset = offset + i
        print('Testing using offset 0x%08x' % curr_offset)
        for sym in sym_table:
            name = maybe_get_string_at(sym['name_addr'] - curr_offset)
            if name:
                if not is_valid_function_name(name):
                    invalid_function_found = True
                    print("name invalid %s" % name)
                    break
                else:
                    print("VALID: %s" % name)
            else:
                print("invalid (%s) name at %08x" %( name, sym['name_addr'] - curr_offset))
                invalid_function_found = True
                break

        if not invalid_function_found:
            # If all symbols resolved with sane function names, then we have a match.
            return curr_offset
