//Forks and traces itself
if (fork() == 0){
    __syscall(SYS_PTRACE, PTRACE_ATTACH, getppid(), __undefined);
}