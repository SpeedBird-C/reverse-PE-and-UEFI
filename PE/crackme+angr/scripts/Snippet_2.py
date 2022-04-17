from idaapi import *
from idautils import *
from idc import *
import string

CODE_REFERENCE = "Code"
DATA_REFERENCE = "Data"
  
  
start_address = inf_get_min_ea()
  

if start_address == BADADDR:
    qexit(1)
print ("Start") 
cnt = 0
good=0
string_tmp=""
string_candidates=list()
#Get list of segments (sections) in the binary image
for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        functionName = get_func_name(funcea)
        for (startea, endea) in Chunks(funcea):
            for address in Heads(startea, endea):
                try:
                	if is_code(get_full_flags(address)):
                		if "mov" == print_insn_mnem(address) and print_operand(address, 1) == "0" and good > 3:
                			string_candidates.append(string_tmp)
                			good = 0
                			string_tmp=""
                			cnt+=1
                		if "mov" == print_insn_mnem(address) and idc.get_operand_type(address,1) == 5:
                			string_tmp+=chr(int(print_operand(address, 1)[:-1],base=16) ^ 0x22)
                			good+=1
                		else:
                			good = 0
                			string_tmp="" 
                except Exception:
                    continue             
print ("Found ", cnt," xored strings")
print (string_candidates)
print ("End")
