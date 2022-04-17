import angr
import claripy
import logging

def main():
    flag = claripy.BVS('flag', 37 * 8, explicit_name=True) # 37 мин размер длины пароля 
    buf = 0x606000 # место в памяти для буффера
    func = 0x401450 # функция проверки 
    goal = 0x004015E8 # выход з функции 

    avoids = [0x004014B7, 0x004015B4,0x00401AE0] # 1 - проверка на длину; 2 - если проверка байтов не прошла v2=0; 3- избегать ветки, где нет b на конце

    proj = angr.Project(r".\crackme1.exe")
    state = proj.factory.blank_state(addr=func)
    state.memory.store(buf, flag, endness='Iend_BE')
    state.stack_push(buf)
    state.stack_push(buf)
    state.memory.store(buf + 37, b'\0')
    for i in range(36):
        state.solver.add(flag.get_byte(i) >= 0x30) # диапозон символов для пароля
        state.solver.add(flag.get_byte(i) <= 0x7f)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=goal, avoid=avoids)
    found = simgr.found[0]
    print(found.solver.eval(flag, cast_to=bytes))
    return 1

logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
main()
