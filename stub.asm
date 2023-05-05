global _start

_start: 
  mov rdi, 1 
  lea rsi, [rel msg]
  mov rdx, 5
  mov rax, 1 
  syscall

  mov rdi, 0
  mov rax, 60 
  syscall

msg: db "HELLO"
