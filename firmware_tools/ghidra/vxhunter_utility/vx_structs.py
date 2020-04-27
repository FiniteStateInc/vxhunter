# coding=utf-8

# TODO: Change struct field sizes to be dependent on word size

from ghidra.program.model.data import (
    ArrayDataType,
    ByteDataType,
    CharDataType,
    EnumDataType,
    Integer16DataType,
    IntegerDataType,
    PointerDataType,
    ShortDataType,
    StructureDataType,
    UnsignedInteger16DataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
    UnsignedShortDataType,
    VoidDataType
)


# Init data type
ptr_data_type = PointerDataType()
byte_data_type = ByteDataType()
char_data_type = CharDataType()
void_data_type = VoidDataType()
unsigned_int_type = UnsignedIntegerDataType()
unsigned_int16_type = UnsignedInteger16DataType()
int_type = IntegerDataType()
int16_type = Integer16DataType()
unsigned_long_type = UnsignedLongDataType()
short_data_type = ShortDataType()
unsigned_short_data_type = UnsignedShortDataType()
char_ptr_type = ptr_data_type.getPointer(char_data_type, 4)
void_ptr_type = ptr_data_type.getPointer(void_data_type, 4)


#######################
# VxWorks 5.x Structs #
#######################
vx_5_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x06: "Local Data",
    0x07: "Global Data",
    0x08: "Local BSS",
    0x09: "Global BSS",
    0x12: "Local Common symbol",
    0x13: "Global Common symbol",
    0x40: "Local Symbols related to a PowerPC SDA section",
    0x41: "Global Symbols related to a PowerPC SDA section",
    0x80: "Local symbols related to a PowerPC SDA2 section",
    0x81: "Global symbols related to a PowerPC SDA2 section"
}

vx_5_sym_enum = EnumDataType("Vx5symType", 1)
for flag in vx_5_symbol_type_enum:
    vx_5_sym_enum.add(vx_5_symbol_type_enum[flag], flag)

vx_5_symtbl_dt = StructureDataType("VX_5_SYMBOL_IN_TBL", 0x10)
vx_5_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_5_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_5_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_5_symtbl_dt.replaceAtOffset(0x0c, short_data_type, 4, "symGroup", "")
vx_5_symtbl_dt.replaceAtOffset(0x0e, vx_5_sym_enum, 1, "symType", "")
vx_5_symtbl_dt.replaceAtOffset(0x0f, byte_data_type, 1, "End", "")


vx_5_sys_symtab = StructureDataType("VX_5_SYSTEM_SYMBOL_TABLE", 0x3C)
vx_5_sys_symtab.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_sys_symtab.replaceAtOffset(0x04, void_ptr_type, 4, "nameHashId", "Pointer to HASH_TBL")
vx_5_sys_symtab.replaceAtOffset(0x08, char_data_type, 0x28, "symMutex", "symbol table mutual exclusion sem")
vx_5_sys_symtab.replaceAtOffset(0x30, void_ptr_type, 4, "symPartId", "memory partition id for symbols")
vx_5_sys_symtab.replaceAtOffset(0x34, unsigned_int_type, 4, "sameNameOk", "symbol table name clash policy")
vx_5_sys_symtab.replaceAtOffset(0x38, unsigned_int_type, 4, "PART_ID", "current number of symbols in table")


vx_5_hash_tbl = StructureDataType("VX_5_HASH_TABLE", 0x18)
vx_5_hash_tbl.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x04, unsigned_int_type, 4, "elements", "Number of elements in table")
vx_5_hash_tbl.replaceAtOffset(0x08, void_ptr_type, 4, "keyCmpRtn", "Comparator function")
vx_5_hash_tbl.replaceAtOffset(0x0c, void_ptr_type, 4, "keyRtn", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x10, unsigned_int_type, 4, "keyArg", "Hash function argument")
vx_5_hash_tbl.replaceAtOffset(0x14, void_ptr_type, 4, "*pHashTbl", "Pointer to hash table array")

vx_5_sl_list = StructureDataType("VX_5_HASH_TABLE_LIST", 0x08)
vx_5_sl_list.replaceAtOffset(0x00, void_ptr_type, 4, "head", "head of list")
vx_5_sl_list.replaceAtOffset(0x04, void_ptr_type, 4, "tail", "tail of list")



#######################
# VxWorks 6.x Structs #
#######################
vx_6_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x08: "Local Data",
    0x09: "Global Data",
    0x10: "Local BSS",
    0x11: "Global BSS",
    0x20: "Local Common symbol",
    0x21: "Global Common symbol",
    0x40: "Local Symbols",
    0x41: "Global Symbols"
}

vx_6_sym_enum = EnumDataType("Vx6symType", 1)
for flag in vx_6_symbol_type_enum:
    vx_6_sym_enum.add(vx_6_symbol_type_enum[flag], flag)


vx_6_symtbl_dt = StructureDataType("VX_6_SYMBOL_IN_TBL", 0x14)
vx_6_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_6_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_6_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPtr", "")
vx_6_symtbl_dt.replaceAtOffset(0x0c, unsigned_int_type, 4, "symRef", "moduleId of module, or predefined SYMREF")
vx_6_symtbl_dt.replaceAtOffset(0x10, short_data_type, 4, "symGroup", "")
vx_6_symtbl_dt.replaceAtOffset(0x12, vx_6_sym_enum, 1, "symType", "")
vx_6_symtbl_dt.replaceAtOffset(0x13, byte_data_type, 1, "End", "")
