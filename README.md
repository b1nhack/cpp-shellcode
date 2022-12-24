# cpp-shellcode
`cpp-shellcode` is A repository of Windows Shellcode runners. The applications load and execute Shellcode using various API calls or techniques.

:smiling_imp: THANKS @[go-shellcode](https://github.com/Ne0nd0g/go-shellcode) 

The available Shellcode runners include:

1. [CreateFiber](#CreateFiber)
2. [CreateRemoteThread](#CreateRemoteThread)
3. [CreateThread](#CreateThread)
4. [EtwpCreateEtwThread](#EtwpCreateEtwThread)
5. [NtQueueApcThreadEx-Local](#NtQueueApcThreadEx-Local)

## CreateFiber

This application leverages the Windows [CreateFiber](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber) function from the `Kernel32.dll` to execute shellcode within this application's process. This is usefull when you want to avoid remote process injection and want to avoid calling `CreateThread`.

## CreateRemoteThread

This application leverages the Windows CreateRemoteThread function from Kernel32.dll to execute shellocde in a remote process. The application requires that the target process to inject into is already running. The program default injecting `Explorer.exe`

## CreateThread

This application leverages the Windows CreateThread function from Kernel32.dll to execute shellcode within this application's process. This is usefull when you want to avoid remote process injection. 

## EtwpCreateEtwThread

This application leverages the Windows EtwpCreateEtwThread function from ntdll.dll to execute shellcode within this application's process. Original work by TheWover. This is usefull when you want to avoid remote process injection.

## NtQueueApcThreadEx-Local

 This application uses the undocumented [NtQueueApcThreadEx](https://docs.rs/ntapi/0.3.1/ntapi/ntpsapi/fn.NtQueueApcThreadEx.html) to create a "Special User APC" in the current thread of the current process to execute shellcode. Because the shellcode is loaded and executed in the current process, it is "local". This same technique can be used for a remote process. *NOTE:* This will only work on Windows 7 or later. Reference [APC Series: User APC API](https://repnz.github.io/posts/apc/user-apc/).
