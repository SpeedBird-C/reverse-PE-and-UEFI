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
       if "rdtsc" in print_insn_mnem(address) or "GetTickCount" in print_insn_mnem(address):
        print(address," : ",generate_disasm_line(address,0))
        cnt+=1
print ("Found ", cnt," time measurments")
print ("End")
