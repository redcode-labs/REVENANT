//Detects VM by checking for time accelleration mechanism
struct timespec interval;
interval.tv_sec = 5;
interval.tv_nsec = 0;
int t_1 = time(0);
nanosleep((struct timespec * )&interval, 0);
int t_2 = time(0);
if ((t_2-t_1) > 5) {
    VM_ACTION;
}