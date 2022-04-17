from idaapi import *
from idautils import *
from idc import *
  
start_address = inf_get_min_ea() 

if start_address == BADADDR:
    qexit(1)
print ("Start") 
for address in Heads(get_segm_start(start_address), get_segm_end(start_address)):
    if is_code(get_full_flags(address)):
       if "call" in print_insn_mnem(address) and "OutputDebugString" in print_operand(address, 0):
        print(address," : ",generate_disasm_line(address,0))
        cnt+=1
print ("Found ", cnt," OutputDebugString")
print ("End")
