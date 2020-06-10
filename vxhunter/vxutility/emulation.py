from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TimeoutTaskMonitor
from ghidra.util.exception import TimeoutException

from java.util.concurrent import TimeUnit

from function_utils import *
from common import *

free_head = 0

def find_free_memory(size):
    addr_space_max = (1 << (word_size * 8)) - 1 # I don't think this is generally correct
    blocks = get_memory_blocks()

    start = None
    first_block = blocks[0]
    last_block = blocks[-1]

    if addr_space_max - last_block.end.offset >= size:
        start = fp.toAddr(addr_space_max - size)
    else:
        for i in reversed(range(len(blocks) - 1)):
            first_block = blocks[i]
            second_block = blocks[i+1]

            if second_block.start.offset - first_block.end.offset >= size:
                start = first_block.end
                break

        if first_block.start.offset >= size:
            start = fp.toAddr(first_block.start.offset - size)

    return start

def create_tmp_stack(min_size=0x1000):
    stack_start = find_free_memory(min_size)

    if stack_start is None:
        print('Could not find suitable space for a %s byte stack' % hex(min_size))
        return None

    return create_initialized_block('dummy_stack', stack_start, min_size)

def create_tmp_heap(min_size=0x1000):
    heap_start = find_free_memory(min_size)

    if heap_start is None:
        print('Could not find suitable space for a %s byte heap' % hex(min_size))
        return None

    global free_head
    free_head = heap_start.offset

    return create_initialized_block('dummy_heap', heap_start, min_size)

def teardown_tmp_stack(stack):
    remove_block(stack)

def teardown_tmp_heap(heap):
    global free_head
    free_head = 0
    remove_block(heap)

def emu_malloc(n):
    global free_head

    old_free_head = free_head
    free_head += n

    return fp.toAddr(old_free_head)

def write_arr(arr, addr, emu):
    for val in addr:
        emu.writeMemoryValue(addr, 1, val)
        addr = addr.add(1)

def set_numeric_variable_value(val, loc, emu):
    if loc.isRegisterStorage():
        reg = loc.register
        emu.writeRegister(reg, val)

    elif loc.isStackStorage():
        stack_off = loc.stackOffset
        emu.writeStackValue(stack_off, loc.size(), val)

    elif loc.isMemoryStorage():
        addr = loc.minAddress
        emu.writeMemoryValue(addr, loc.size(), val)

    else:
        raise NotImplementedError('Cannot set variable value for location: %s' % loc)

def set_variable_value(val, dt, loc, emu):
    if isinstance(dt, PointerDataType):
        ptr = emu_malloc(len(val))
        write_arr(val, ptr, emu)
        val = ptr

    set_numeric_variable_value(val, loc, emu)

def set_param_values(func, params, emu):
    cc = get_function_calling_convention(func)
    set_params = []

    for name, dt, val in params:
        loc = cc.getNextArgLocation(set_params, dt, cp)
        set_variable_value(val, dt, loc, emu)

        impl = ParameterImpl(name, dt, loc, cp, SourceType.USER_DEFINED)
        set_params.append(impl)

def read_pc(emu):
    return emu.readRegister(emu.getPCRegister())

def write_pc(emu, pc_val):
    emu.writeRegister(emu.getPCRegister(), pc_val)

def read_sp(emu):
    return emu.readRegister(emu.getStackPointerRegister())

def write_sp(emu, sp_val):
    emu.writeRegister(emu.getStackPointerRegister(), sp_val)

def get_called_func_addr(emu):
    pc = fp.toAddr(read_pc(emu))
    refs = fp.getReferencesFrom(pc)
    if len(refs) == 0:
        return None

    call_refs = [ref for ref in refs if ref.referenceType.isCall()]
    if len(call_refs) == 0:
        return None

    call_ref = call_refs[0] # can there be more than one call ref? doesn't make sense to me
    return call_ref.toAddress

def skip_curr_insn(emu):
    pc = fp.toAddr(read_pc(emu))
    curr_insn = fp.getInstructionAt(pc)
    if curr_insn is None:
        return False

    next_insn = curr_insn.next
    if next_insn is None:
        return False

    write_pc(emu, next_insn.address.offset)
    return True

def run_emulation_until(end_addr, emu, skip_calls, funcs_to_call):
    emu.setBreakpoint(end_addr)

    monitor = TimeoutTaskMonitor.timeoutIn(2, TimeUnit.SECONDS)
    while not monitor.isCancelled() and read_pc(emu) != end_addr.offset:
        if skip_calls:
            called_func_addr = get_called_func_addr(emu)
            if called_func_addr is not None and called_func_addr not in funcs_to_call:
                if not skip_curr_insn(emu):
                    break

                continue

        try:
            if not emu.step(monitor):
                print('An error occurred during emulation: %s' % emu.lastError)
                break
        except TimeoutException:
            print('Emulator timed out')
            break

def set_known_register_values(emu):
    prog_ctx = cp.programContext
    min_addr = get_main_memory().start

    for reg in prog_ctx.registersWithValues:
        val = prog_ctx.getValue(reg, min_addr, False) # look for global, static registers (i.e. PPC SDA)
        if val is None or val == 0:
            continue

        emu.writeRegister(reg, val)

def emulate_func(func, params, skip_calls=False, funcs_to_call=[]):
    """
    skip_calls and funcs_to_call are hacks to work around disassembly errors.

    At least in the cases implemented thusfar, we don't really care about the behavior of functions called 
    from an emulated function, we're just trying to pull out some memory or register values.

    If we therefore skip over any calls (that we don't care about), then our chances of encountering
    a disassembly error and breaking the emulatino is lower.

    However, we want to emulate the call from usrKernelInit -> kernelInit since the interrupt guard page
    sizes are parameters to kernelInit, so funcs_to_call is a whitelist (TODO: change wording) of calls
    not to skip.
    """

    stack = create_tmp_stack()
    heap = create_tmp_heap()

    if stack is None or heap is None:
        return None

    sp_off = stack.end.offset - word_size * (1 + len(params)) # add one for return address if applicable

    emu = EmulatorHelper(cp)

    write_sp(emu, sp_off)
    write_pc(emu, func.entryPoint.offset)

    set_known_register_values(emu)
    set_param_values(func, params, emu)

    end_addr = get_func_end_addr(func)
    run_emulation_until(end_addr, emu, skip_calls, funcs_to_call)

    teardown_tmp_stack(stack)
    teardown_tmp_heap(heap)

    return emu
