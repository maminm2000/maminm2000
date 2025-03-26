# NTDLL.dll kernel gate 

## syscall : 

thread is jump to kernel an run its code in kernel 

### MSR regisre : 
+ ia32_lstar : after syscall jump to  this adress and windows save a adress
for see msr :
```
Rdmsr 0xc0000082

```
lkd> Rdmsr 0xc0000082
msr[c0000082] = fffff807`192191c0

```
u kisystemcall64
```
```
ln fffff807`192191c0
```

microsoft windows systemcalls : [https://j00ru.vexillium.org/syscalls/nt/64/]

### way of a function : 
createfile ---ntdll---> ntcreatefile ---syscall---> kisystemcall64  and pass 55h and search in kiservicetable 

### system 32 : 
win32k.sys --> gui functions 


### object and handles 
