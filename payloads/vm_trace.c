//Detect VM by ptrace(0, 1, 0, 0) x 0x02
int shared_lock = 0;
if (__syscall(101, 0, 0, 1, 0) == 0){
    shared_lock++;
}
if (__syscall(101, 0, 0, 1, 0) == -1){
    shared_lock++;
}
if (shared_lock != 2){
    VM_ACTION;
}
