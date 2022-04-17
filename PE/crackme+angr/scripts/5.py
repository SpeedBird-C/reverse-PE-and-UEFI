from idaapi import *
from idautils import *
from idc import *

start_address = inf_get_min_ea()
if start_address == BADADDR:
    qexit(1)
    
print ("Start")
cnt = 0

for address in Heads(get_segm_start(start_address), get_segm_end(start_address)):
    if is_code(get_full_flags(address)):
       if ("int" == print_insn_mnem(address) and "2d" == print_operand(address, 0)) or ("ss" == print_insn_mnem(address)):
        print(address," : ",generate_disasm_line(address,0))
        cnt+=1
print ("Found ", cnt," rare instructions")
print ("End")
