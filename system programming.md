dll base adress  find export func 


## get handle from process :
```c++
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main()
{
    const wchar_t* processname = L"svchost.exe";
    DWORD pid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[X] Failed to take snapshot of processes.\n");
        return -1;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);


    if (!Process32FirstW(hSnapshot, &pe))
    {
        wprintf(L"[X] Process32FirstW failed.\n");
        CloseHandle(hSnapshot);
        return -1;
    }

    HANDLE hProcess = NULL;

    do {
        if (_wcsicmp(processname, pe.szExeFile) == 0)
        {
            pid = pe.th32ProcessID;
            wprintf(L"[!] Found %ls with PID %d\n", processname, pid);

            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                   FALSE, pid);

            if (hProcess == NULL)
            {
                wprintf(L"[X] Could not open handle to PID %d (error %lu), continuing...\n", pid, GetLastError());
            }
            else
            {
                wprintf(L"[+] Successfully opened handle to PID %d\n", pid);
                CloseHandle(hProcess);
                break;
            }
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return 0;
}


```

## write code with vector for get from more process :

```c++
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>
#include <string>

int main()
{
    // List of target process names
    std::vector<std::wstring> targetProcesses = {
        \L"svchost.exe",
        L"notepad.exe",
        L"explorer.exe"
    };

    // Take a snapshot of all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[X] Failed to take snapshot of processes.\n");
        return -1;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe))
    {
        wprintf(L"[X] Process32FirstW failed.\n");
        CloseHandle(hSnapshot);
        return -1;
    }

    do {
        for (const auto& procName : targetProcesses)
        {
            if (_wcsicmp(procName.c_str(), pe.szExeFile) == 0)
            {
                DWORD pid = pe.th32ProcessID;
                wprintf(L"[!] Found %ls with PID %d\n", procName.c_str(), pid);

                HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                    FALSE, pid);

                if (hProcess == NULL)
                {
                    wprintf(L"[X] Could not open handle to PID %d (error %lu), continuing...\n", pid, GetLastError());
                }
                else
                {
                    wprintf(L"[+] Successfully opened handle to PID %d (%ls)\n", pid, procName.c_str());
                    
                }
            }
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return 0;
}

```





## process structure :
### user mode : 
peb 
### user mode : 
EPROCESS
KPROCESS
All Process linked as doubly linked-list 



# PPL protected process level 
for user admin and privilage SEdebug 
first microsoft give this for video and audio --> people have to sighn in microxoft and get certificate 
image has level in process protected 
protec process is a concept of user mode not in kernel 
after its be protected process light 
we cant hijack in these because need to dll sighn 
### werfaut and secure 

### PDB :
is a debuger and has symbols and .... and rootkit and in the EProcess  


## process protected light 
0. none
1. authenticode
2. codeGen
3. .
4. .
5. .
6. .
7. .

 


# set symbol for WINDBG : 
```
set _NT_SYMBOL_PATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

```



## windbg : 
### first chance :


### secend chance :




```
dt nt!_peb @$peb
```
dt ntdll!_EPROCESS
```
```
```
```
```
```



##AMSI : 

mov [rsp+8], rbx      ; Save registers
mov [rsp+10h], rsi
push rdi
sub rsp, 20h
xor eax, eax          ; Set return value to 0 (AMSI_RESULT_CLEAN)
add rsp, 20h          ; Restore stack
pop rdi               ; Restore registers
mov rsi, [rsp+10h]
mov rbx, [rsp+8]
ret                   ; Return to caller

https://github.com/EvilBytecode/Ebyte-AMSI-ProxyInjector






## mailslot 

driver and process want to connect together 

## pip



AWRC priject : https://github.com/stdevPavelmc/awrc





### Wmiprovider :
WMIProvider refers to a component or class that supplies data to Windows Management Instrumentation (WMI) — a powerful Microsoft technology used for monitoring and managing Windows-based systems.










