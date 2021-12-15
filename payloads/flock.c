//Implements a basic blocking mutex
__syscall(SYS_FLOCK, open("/tmp/.lck", O_RDWR | O_CREAT, 00400 | 00200), 2);