from idaapi import *
import idaapi
import idc
import idautils
from prettytable import PrettyTable

if idaapi.IDA_SDK_VERSION > 700:
    import ida_search
    from idc import (
        print_operand
    )
    from ida_bytes import (
        get_strlit_contents
    )
else:
    from idc import (
        GetOpnd as print_operand,
    )
    from ida_bytes import get_strlit_contents
    def get_strlit_contents(*args): return get_strlit_contents(args[0])

DEBUG = True

# fgetc,fgets,fread,fprintf,
# vspritnf

# set function_name
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]

# describe arg num of function

one_arg_function = [
    "getenv",
    "system",
    "unlink"
]

two_arg_function = [
    "strcpy", 
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat", 
    "memcpy",
    "execve",
    "read"
]

reg_x64 = [
    "di",
    "si", 
    "dx",
    "cx",
    "r8",
    "r9"
]

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}


def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Auditing " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

def getFormatString(addr):
    op_num = 1
    # idc.get_operand_type Return value
    #define o_void        0  // No Operand                           ----------
    #define o_reg         1  // General Register (al, ax, es, ds...) reg
    #define o_mem         2  // Direct Memory Reference  (DATA)      addr
    #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    #define o_imm         5  // Immediate Value                      value
    #define o_far         6  // Immediate Far Address  (CODE)        addr
    #define o_near        7  // Immediate Near Address (CODE)        addr
    # 如果第二个不是立即数则下一个
    if(idc.get_operand_type(addr ,op_num) != 2):
        op_num = op_num + 1
    if idc.get_operand_type(addr ,op_num) != 2:
        return "get fail"
    op_string = print_operand(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
    string_addr = idc.get_name_ea_simple(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
    return [string_addr, string]

# 获取参数地址
def get_arg_addr(start_addr, regNum):
    scan_deep = 50
    count = 0
    reg = reg_x64[regNum]
    # try to get before
    before_addr = get_first_cref_to(start_addr)
    while before_addr != BADADDR:
        if reg in print_operand(before_addr, 0):
            Mnemonics = print_insn_mnem(before_addr)
            if Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break 
        before_addr = get_first_cref_to(before_addr)
    return BADADDR

# 处理寄存器, 从line向上遍历，到satrt_ea返回， 找到第一次对reg_target的操作，返回
# 递归查找，找出不是单纯一个寄存器的
def find_reg(current, start_ea, reg_target):
    if(current >= start_ea):
        current = idc.prev_head(current)
        if(idc.print_operand(current, 0) == reg_target):
            if(idc.get_operand_type(current, 1) != 1):
                if(print_insn_mnem(current)[0:1] != 'j'):
                    return idc.print_operand(current, 1)
                else:
                    return find_reg(current, start_ea, reg_target)
            else:
                return find_reg(current, start_ea, idc.print_operand(current, 1))
        else:
            return find_reg(current, start_ea, reg_target)
    return reg_target

# 找出影响参数的东西
def get_input_from_op(arg_addr):
    Mnemonics = print_insn_mnem(arg_addr) 
    if Mnemonics[0:3] == "add":
        if print_operand(arg_addr, 2) == "":
            arg = print_operand(arg_addr, 0) + "+" + print_operand(arg_addr, 1)
        else:
            arg = print_operand(arg_addr, 1) + "+" +  print_operand(arg_addr, 2)
    elif Mnemonics[0:3] == "sub":
        if print_operand(arg_addr, 2) == "":
            arg = print_operand(arg_addr, 0) + "-" + print_operand(arg_addr, 1)
        else:
            arg = print_operand(arg_addr, 1) + "-" +  print_operand(arg_addr, 2)
    elif "mov" in Mnemonics or "lea" in Mnemonics:
        # 参数不是寄存器
        if(idc.get_operand_type(arg_addr, 1) != 1):
            arg = print_operand(arg_addr, 1) 
        else:
            arg = find_reg(arg_addr, idaapi.get_func(arg_addr).start_ea, idc.print_operand(arg_addr, 1))
    else:
        arg = GetDisasm(arg_addr).split("#")[0]
    return arg

def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    count = 1
    ret_list = [func_name, addr]
    args= ""
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 236")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    print(hex(call_addr), func_name, "args: ", idaapi.get_arg_addrs(call_addr))

    for arg_addr in idaapi.get_arg_addrs(call_addr):
        arg = get_input_from_op(arg_addr)
        idc.set_cmt(arg_addr, "arg" + str(count) + " : " + arg, 0)
        args += arg + ", "
        count = count + 1
        ret_list.append(arg) 
    ret_list.append(local_buf_size)
    if len(args):
        idc.set_cmt(call_addr, func_name + "(" + args[:-2] + ")", 0)
    return ret_list

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 252")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for arg_addr in idaapi.get_arg_addrs(call_addr):
        ret_list.append(get_input_from_op(arg_addr)) 
    fmt_arg_addr = get_arg_addr(call_addr, format_function_offset_dict[func_name])
    string_and_addr =  getFormatString(fmt_arg_addr)
    format_and_value = []
    if string_and_addr == "get fail":
        ret_list.append("get fail")
    else:
        string_addr = "0x%x" % string_and_addr[0]
        format_and_value.append(string_addr)
        string = string_and_addr[1]
        fmt_num = string.count("%")
        format_and_value.append(fmt_num)
        # x86 arg reg is rdi, rsi, rdx, rcx, r8, r9
        if fmt_num > 5:
            fmt_num = fmt_num - format_function_offset_dict[func_name] - 1
        for num in range(0,fmt_num):
            if arg_num + num > 5:
                break
            format_and_value.append(get_input_from_op(get_arg_addr(call_addr, arg_num + num)))
        ret_list.append(format_and_value)
    ret_list.append(local_buf_size)
    return ret_list

# 扫描同种函数，根据是否带有格式化字符串分类，先确定好参数个数
def audit(func_name):
    func_addr = getFuncAddr(func_name)  
    if func_addr == False:
        return False

    if idc.get_segm_name(func_addr) == 'extern':
        func_addr = list(idautils.CodeRefsTo(func_addr, 0))[0]

    # get arg num and set table
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print("The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name)
        return
    table_head = ["func_name", "addr"]
    for num in range(0,arg_num):
        table_head.append("arg"+str(num+1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get first call
    call_addr_list = idautils.CodeRefsTo(func_addr, 0)
    for call_addr in call_addr_list:
        idc.set_color(call_addr, idc.CIC_ITEM, 0x00ff00)
        Mnemonics = print_insn_mnem(call_addr)
        if func_name in format_function_offset_dict:
            info = auditFormat(call_addr, func_name, arg_num)
            # info = [1 for i in range(arg_num+4)]
        else:
            info = auditAddr(call_addr, func_name, arg_num)
        # print("info: ")
        # print(info)
        table.add_row(info)
    print(table)

# 扫描
def auditAll():
    # the word create with figlet
    print("Auditing dangerous functions ......")
    for func_name in dangerous_functions:
        audit(func_name)
        
    print("Auditing attention function ......")
    for func_name in attention_function:
        audit(func_name)

    print("Auditing command execution function ......")
    for func_name in command_execution_function:
        audit(func_name)
        
    print("Finished! Enjoy the result ~")


if __name__ == '__main__':
    auditAll()