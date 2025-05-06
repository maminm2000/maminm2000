dll base adress  find export func 



```
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
