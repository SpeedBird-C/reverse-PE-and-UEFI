from idaapi import *
from idautils import *
from idc import *
start_address = inf_get_min_ea()  
if start_address == BADADDR:
    qexit(1)
print("Start") 
cnt = 0

for address in Heads(get_segm_start(start_address), get_segm_end(start_address)):
    if is_code(get_full_flags(address)):
       if generate_disasm_line(address,0).startswith("xor "):
            cnt+=1
print ("Found ", cnt," xors")
print ("End")
