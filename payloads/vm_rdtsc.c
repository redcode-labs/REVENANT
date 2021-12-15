//Detects VM by checking RDTSC inconsistency delay
int first_tick = __rdtsc();
int second_tick = __rdtsc();
if ((second_tick-first_tick) < 512){
    VM_ACTION;
}