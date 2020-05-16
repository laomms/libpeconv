# libpeconv from hasherezade
 (https://github.com/hasherezade/libpeconv)    

重新编译版,dll和crt_dll
 
 UnManaged Dll:
 ```C
EXPORTS
alloc_aligned;
free_aligned;
load_file;
free_file;
load_pe_executable_dll;
load_pe_executable;
load_pe_module;
load_pe_module_dll;
load_resource_data;
free_pe_buffer;
get_entry_point_rva;
get_sections_count;
get_section_hdr;
get_image_base;
get_image_size;
get_subsystem;
get_export_directory;
get_file_hdr;
pe_realign_raw_to_virtual;
pe_virtual_to_raw;
dump_to_file;
find_padding_cave;
is_module_dll;
is64bit;
has_relocations;
has_valid_relocation_table
read_from_file;
relocate_module;
update_entry_point_rva;
validate_ptr;
 
```

Managed Dll(CLR .net4.5),不改变原有函数声明.
 ```C
#pragma once
#include <windows.h>
#include <vcclr.h>
#using <System.dll>
#include <string>
#include <iostream>

using namespace System::Runtime::InteropServices;
using namespace System;
using namespace peconv;
//using namespace std;


#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif 



namespace PeconvCLR {
    public ref class FuncLists
    {
    public:
        static IntPtr LoadFile(IN String^ filename, OUT size_t read_size)  
        {
            return (IntPtr)load_file(IN(char*)(void*)Marshal::StringToHGlobalAnsi(filename),  read_size);
        }
        static  void FreeFile(IN IntPtr buffer)
        {
            return free_file((PBYTE)buffer.ToPointer());
        }
        static IntPtr AllocAligned(size_t buffer_size, int protect, ULONGLONG desired_base)
        {
            return (IntPtr)alloc_aligned(buffer_size, protect, desired_base);
        }
        static  bool FreeaLigned(IntPtr buffer, unsigned  int buffer_size)
        {
            return free_aligned((PBYTE)buffer.ToPointer(), buffer_size);
        }
        static IntPtr LoadPeExecutable_Dll(IntPtr dllRawData, size_t r_size, size_t v_size, IntPtr import_resolver)
        {
            return (IntPtr)load_pe_executable_dll((BYTE*)dllRawData.ToPointer(), r_size, v_size, (t_function_resolver*)&import_resolver);
        }
        static IntPtr LoadPeExecutable(String^ my_path, OUT size_t v_size, IntPtr import_resolver)
        {
            char* mypath = (char*)(void*)Marshal::StringToHGlobalAnsi(my_path);
            return  (IntPtr)load_pe_executable(mypath, OUT v_size, (t_function_resolver*)&import_resolver);
        }
        static IntPtr LoadPeModule(String^ filename, OUT size_t v_size, bool executable, bool relocate)
        {
            char* filename_ = (char*)(void*)Marshal::StringToHGlobalAnsi(filename);
            return (IntPtr)load_pe_module(filename_, OUT  v_size, executable, relocate);
        }
        static IntPtr LoadPeModule_Dll(IntPtr dllRawData, size_t r_size, OUT size_t v_size, bool executable, bool relocate)
        {
            return (IntPtr)load_pe_module_dll((BYTE*)dllRawData.ToPointer(), r_size, OUT  v_size, executable, relocate);
        }
        static IntPtr LoadreSourceData(OUT size_t out_size, int res_id, String^ res_type, IntPtr hInstance)
        {
            return (IntPtr)load_resource_data(OUT out_size, res_id, (char*)Marshal::StringToHGlobalAnsi(res_type).ToPointer(), (HMODULE)hInstance.ToPointer());
        }
        static bool FreePeBuffer(IntPtr buffer, size_t buffer_size)
        {
            return free_pe_buffer((PBYTE)buffer.ToPointer(), buffer_size);
        }
        static DWORD GetEntrypoint_Rva(IN IntPtr pe_buffer)
        {
            return get_entry_point_rva((BYTE *) pe_buffer.ToPointer());
        }
        static size_t GetSectionsCount(IN IntPtr payload, IN const size_t buffer_size)
        {
            return get_sections_count(IN (BYTE*) payload.ToPointer(), buffer_size);
        }
        static IntPtr GetSectionHdr(IN IntPtr payload, IN const size_t buffer_size, IN size_t section_num)        
        {   
            return (IntPtr) get_section_hdr(IN (BYTE*) payload.ToPointer(), IN  buffer_size, IN  section_num);
        }
        static ULONGLONG GetImagebase(IN IntPtr pe_buffer)
        {
            return get_image_base((BYTE*)pe_buffer.ToPointer());
        }
        static DWORD GetImagesize(IN IntPtr payload)
        {
            return get_image_size(IN (BYTE*) payload.ToPointer());
        }
        static WORD GetSubsystem(IN IntPtr payload)
        {
            return get_subsystem((BYTE*)payload.ToPointer());
        }
        static IMAGE_EXPORT_DIRECTORY* GetExportDirectory(IN IntPtr modulePtr)
        {
            return get_export_directory((HMODULE)modulePtr.ToPointer());
        }
        static IntPtr PeRealignRawToVirtual(IN IntPtr payload, IN size_t in_size, IN ULONGLONG loadBase, OUT size_t& out_size)
        {
            return (IntPtr)pe_realign_raw_to_virtual(IN(BYTE*)payload.ToPointer(), IN in_size, IN loadBase, OUT  out_size);
        }
        static IntPtr PeVirtualToRaw(IN IntPtr payload, IN size_t in_size, IN ULONGLONG loadBase, OUT size_t& out_size, IN OPTIONAL bool rebuffer)
        {
            return (IntPtr)pe_virtual_to_raw(IN (BYTE*)payload.ToPointer(), IN  in_size, IN  loadBase, OUT  out_size, IN OPTIONAL  rebuffer);
        }
        static bool DumpFile(IN const char* out_path, IN PBYTE dump_data, IN size_t dump_size)
        {
            return dump_to_file(IN  out_path, IN  dump_data, IN  dump_size);
        }
        static PBYTE FindPaddingCave(IntPtr modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact)
        {
            return find_padding_cave((BYTE*)modulePtr.ToPointer(), moduleSize, minimal_size, req_charact);
        }
        static bool IsDll(IN IntPtr payload)
        {
            return is_module_dll(IN (BYTE*)payload.ToPointer());
        }
        static bool Is64(IN IntPtr pe_buffer)
        {
            return is64bit(IN(BYTE*)pe_buffer.ToPointer());
        }
        static bool HasRelocations(IN IntPtr pe_buffer)
        {
            return has_relocations(IN(BYTE*)pe_buffer.ToPointer());
        }
        static bool HasValidRelocationTable(IN const PBYTE modulePtr, IN const size_t moduleSize)
        {
            return has_valid_relocation_table(IN  modulePtr, IN  moduleSize);
        }
        static Byte ReadFromFile(IN String^ in_path, IN OUT size_t read_size)
        {
            return (Byte)read_from_file(IN(char*)(void*)Marshal::StringToHGlobalAnsi(in_path), IN OUT  read_size);
        }
        static bool RelocateModule(IN IntPtr modulePtr, IN size_t moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
        {
            return relocate_module(IN (BYTE*)modulePtr.ToPointer(), IN  moduleSize, IN newBase, IN oldBase);
        }
        static bool UpdateEntrypointRva(IN OUT IntPtr pe_buffer, IN DWORD value)
        {
            return update_entry_point_rva(IN OUT(BYTE*)pe_buffer.ToPointer(), IN  value);
        }
        static bool ValidatePtr(IN const IntPtr buffer_bgn, IN size_t buffer_size, IN const void* field_bgn, IN size_t field_size)
        {
            return validate_ptr(IN (void*) buffer_bgn, IN  buffer_size, IN  field_bgn, IN  field_size);
        }
        static bool is_compatibile(IntPtr implant_dll);
    };
}
```


example


```vb.net
Imports System.Runtime.InteropServices

Module Module1

    Sub Main()
        Dim mapped As IntPtr = map_dll_image("C:\Windows\System32\KernelBase.dll")
        Dim v_size As UInteger = 0
        Dim implant_dll = PeconvCLR.FuncLists.LoadPeExecutable("test.dll", v_size, 0)
        If implant_dll <> IntPtr.Zero Then
            Console.WriteLine("Failed to load the implant!")
        End If
        If PeconvCLR.FuncLists.is_compatibile(implant_dll) Then
            If PeconvCLR.FuncLists.RelocateModule(implant_dll, v_size, mapped, implant_dll) Then
                If overwrite_mapping(mapped, implant_dll, v_size) Then
                    Dim ep_rva As UInteger = PeconvCLR.FuncLists.GetEntrypoint_Rva(implant_dll)
                    Dim is_dll As Boolean = PeconvCLR.FuncLists.IsDll(implant_dll)
                    run_implant(mapped, ep_rva, is_dll)
                    PeconvCLR.FuncLists.FreePeBuffer(implant_dll, 0)
                    implant_dll = Nothing
                End If
            End If
        End If
    End Sub
    
    Private Function map_dll_image(ByVal dll_name As String) As IntPtr
        Dim hFile As IntPtr = CreateFileA(dll_name, GENERIC_READ, 0, Nothing, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, Nothing)
        If hFile = IntPtr.Zero Then
            Return Nothing
        End If
        Dim hSection As IntPtr = Nothing
        Dim status = NtCreateSection(hSection, SECTION_ALL_ACCESS, Nothing, 0, PAGE_READONLY, SEC_IMAGE, hFile)
        If status <> 0 Then
            Return Nothing
        End If
        CloseHandle(hFile)
        Dim sectionBaseAddress As IntPtr = Nothing
        Dim viewSize As IntPtr = Nothing
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), sectionBaseAddress, Nothing, Nothing, Nothing, viewSize, SECTION_INHERIT.ViewShare, Nothing, PAGE_EXECUTE_READWRITE)
        If status = 0 Then
            Return Nothing
        End If
        Return sectionBaseAddress
    End Function

    Private Function overwrite_mapping(ByVal mapped As IntPtr, ByRef implant_dll As Byte, ByVal implant_size As UInteger) As Boolean
        Dim hProcess As IntPtr = GetCurrentProcess()
        Dim oldProtect As UInteger = 0

        Dim prev_size As UInteger = PeconvCLR.FuncLists.GetImagesize(mapped)
        If prev_size <> 0 Then
            If Not VirtualProtect(DirectCast(mapped, Object), prev_size, PAGE_READWRITE, oldProtect) Then
                Return False
            End If
            MemSet(mapped, 0, prev_size)
            If Not VirtualProtect(DirectCast(mapped, Object), prev_size, PAGE_READONLY, oldProtect) Then
                Return False
            End If
        End If
        If Not VirtualProtect(DirectCast(mapped, Object), implant_size, PAGE_READWRITE, oldProtect) Then
            If implant_size > prev_size Then
                Console.Write("[-] The implant is too big for the target!" & vbLf)
            End If
            Return False
        End If
        CopyMemory(mapped, implant_dll, implant_size)
        Return True

        ' set access:
        If Not set_sections_access(mapped, implant_dll, implant_size) Then
            Return False
        End If
    End Function
    
    Private Function set_sections_access(ByVal mapped As IntPtr, ByRef implant_dll As IntPtr, ByVal implant_size As UInteger) As Boolean
        Dim oldProtect As UInteger = 0
        ' protect PE header
        If Not VirtualProtect(DirectCast(mapped, Object), &H1000, PAGE_READONLY, oldProtect) Then
            Return False
        End If
        'protect sections:
        Dim count = PeconvCLR.FuncLists.GetSectionsCount(implant_dll, implant_size)
        For i As UInteger = 0 To count - 1
            Dim next_sec As IMAGE_SECTION_HEADER = Marshal.PtrToStructure(PeconvCLR.FuncLists.GetSectionHdr(implant_dll, implant_size, i), GetType(IMAGE_SECTION_HEADER))
            Dim sec_protect As UInteger = translate_protect(next_sec.Characteristics)
            Dim sec_offset As UInteger = next_sec.VirtualAddress
            Dim sec_size As UInteger = next_sec.Misc.VirtualSize
            If Not VirtualProtect(IntPtr.Add(mapped, sec_offset), sec_size, sec_protect, oldProtect) Then
                Return False
            End If
        Next i
        Return True
    End Function
    
    Private Function translate_protect(ByVal sec_charact As UInteger) As UInteger
        If (sec_charact And IMAGE_SCN_MEM_EXECUTE) <> 0 AndAlso (sec_charact And IMAGE_SCN_MEM_READ) <> 0 AndAlso (sec_charact And IMAGE_SCN_MEM_WRITE) <> 0 Then
            Return PAGE_EXECUTE_READWRITE
        End If
        If (sec_charact And IMAGE_SCN_MEM_EXECUTE) <> 0 AndAlso (sec_charact And IMAGE_SCN_MEM_READ) <> 0 Then
            Return PAGE_EXECUTE_READ
        End If
        If (sec_charact And IMAGE_SCN_MEM_EXECUTE) <> 0 Then
            Return PAGE_EXECUTE_READ
        End If

        If (sec_charact And IMAGE_SCN_MEM_READ) <> 0 AndAlso (sec_charact And IMAGE_SCN_MEM_WRITE) <> 0 Then
            Return PAGE_READWRITE
        End If
        If (sec_charact And IMAGE_SCN_MEM_READ) <> 0 Then
            Return PAGE_READONLY
        End If
        Return PAGE_READWRITE
    End Function
    
    Private Sub run_implant(ByVal mapped As Object, ByVal ep_rva As UInteger, ByVal is_dll As Boolean)
        Dim implant_ep As IntPtr = DirectCast(mapped, IntPtr) + ep_rva
        Console.Write("[*] Executing Implant's Entry Point: ")
        Console.Write("{0:x}", implant_ep)
        Console.Write("{0:x}", vbLf)
        If is_dll Then
            'run the implant as a DLL:
            Dim dll_main As dll_mainDelegate = Marshal.GetDelegateForFunctionPointer(implant_ep, GetType(dll_mainDelegate))
            dll_main(mapped, 1, 0)
        Else
            'run the implant as EXE:
            Dim exe_main As exe_mainDelegate = Marshal.GetDelegateForFunctionPointer(implant_ep, GetType(exe_mainDelegate))
            exe_main()
        End If
    End Sub
    
    '==================================================================================================================
    <UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet:=CharSet.Unicode)>
    Public Delegate Function dll_mainDelegate(ByVal HINSTANCE As IntPtr, ByVal DWORD As UInteger, ByVal LPVOID As IntPtr) As Boolean
    <UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet:=CharSet.Unicode)>
    Public Delegate Function exe_mainDelegate() As Boolean
    Public Const STANDARD_RIGHTS_REQUIRED As UInteger = &HF0000
    Public Const SECTION_QUERY As UInteger = &H1
    Public Const SECTION_MAP_WRITE As UInteger = &H2
    Public Const SECTION_MAP_READ As UInteger = &H4
    Public Const SECTION_MAP_EXECUTE As UInteger = &H8
    Public Const SECTION_EXTEND_SIZE As UInteger = &H10
    Public Const SECTION_ALL_ACCESS As UInteger = STANDARD_RIGHTS_REQUIRED Or SECTION_QUERY Or SECTION_MAP_WRITE Or SECTION_MAP_READ Or SECTION_MAP_EXECUTE Or SECTION_EXTEND_SIZE
    Public Const pageSize As ULong = 81920
    Public Const OPEN_EXISTING As Integer = 3
    Public GENERIC_READ As UInteger = &H80000000UI
    Public FILE_ATTRIBUTE_NORMAL As UInteger = &H80
    Public Const PAGE_READONLY As Integer = &H2
    Public Const SEC_IMAGE As UInteger = &H1000000
    Public Const PAGE_EXECUTE_READWRITE As Long = &H40
    Public Const PAGE_READWRITE As Integer = 4
    Public IMAGE_SCN_MEM_EXECUTE As UInteger = &H20000000
    Public IMAGE_SCN_MEM_READ As UInteger = &H40000000
    Public IMAGE_SCN_MEM_WRITE As Long = &H80000000
    Public PAGE_EXECUTE_READ As UInteger = &H20
    Public Enum SECTION_INHERIT
        ViewShare = 1
        ViewUnmap = 2
    End Enum
    Public Enum ACCESS_MASK : Uint32
        DELETE = &H10000
        READ_CONTROL = &H20000
        WRITE_DAC = &H40000
        WRITE_OWNER = &H80000
        SYNCHRONIZE = &H100000
        STANDARD_RIGHTS_REQUIRED = &HF0000
        STANDARD_RIGHTS_READ = &H20000
        STANDARD_RIGHTS_WRITE = &H20000
        STANDARD_RIGHTS_EXECUTE = &H20000
        STANDARD_RIGHTS_ALL = &H1F0000
        SPECIFIC_RIGHTS_ALL = &HFFFF
        ACCESS_SYSTEM_SECURITY = &H1000000
        MAXIMUM_ALLOWED = &H2000000
        GENERIC_READ = &H80000000
        GENERIC_WRITE = &H40000000
        GENERIC_EXECUTE = &H20000000
        GENERIC_ALL = &H10000000
        DESKTOP_READOBJECTS = &H1
        DESKTOP_CREATEWINDOW = &H2
        DESKTOP_CREATEMENU = &H4
        DESKTOP_HOOKCONTROL = &H8
        DESKTOP_JOURNALRECORD = &H10
        DESKTOP_JOURNALPLAYBACK = &H20
        DESKTOP_ENUMERATE = &H40
        DESKTOP_WRITEOBJECTS = &H80
        DESKTOP_SWITCHDESKTOP = &H100
        WINSTA_ENUMDESKTOPS = &H1
        WINSTA_READATTRIBUTES = &H2
        WINSTA_ACCESSCLIPBOARD = &H4
        WINSTA_CREATEDESKTOP = &H8
        WINSTA_WRITEATTRIBUTES = &H10
        WINSTA_ACCESSGLOBALATOMS = &H20
        WINSTA_EXITWINDOWS = &H40
        WINSTA_ENUMERATE = &H100
        WINSTA_READSCREEN = &H200
        WINSTA_ALL_ACCESS = &H37F
    End Enum
    Public Structure Misc
        Public PhysicalAddress As System.UInt32
        Public VirtualSize As System.UInt32
    End Structure
    Public Structure IMAGE_SECTION_HEADER
        Public Name As System.Byte
        Public Misc As Misc
        Public VirtualAddress As System.UInt32
        Public SizeOfRawData As System.UInt32
        Public PointerToRawData As System.UInt32
        Public PointerToRelocations As System.UInt32
        Public PointerToLinenumbers As System.UInt32
        Public NumberOfRelocations As System.UInt16
        Public NumberOfLinenumbers As System.UInt16
        Public Characteristics As System.UInt32
    End Structure
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function CreateFileA(lpFileName As String, dwDesiredAccess As UInteger, dwShareMode As UInteger, lpSecurityAttributes As IntPtr, dwCreationDisposition As UInteger, dwFlagsAndAttributes As UInteger, hTemplateFile As IntPtr) As IntPtr
    End Function
    <DllImport("ntdll.dll", SetLastError:=True)>
    Public Function NtCreateSection(ByRef SectionHandle As IntPtr, ByVal DesiredAccess As UInteger, ByVal ObjectAttributes As IntPtr, ByRef MaximumSize As ULong, ByVal SectionPageProtection As UInteger, ByVal AllocationAttributes As UInteger, ByVal FileHandle As IntPtr) As UInteger
    End Function
    <DllImport("ntdll.dll", SetLastError:=True)>
    Public Function NtMapViewOfSection(ByVal SectionHandle As IntPtr, ByVal ProcessHandle As IntPtr, ByRef BaseAddress As IntPtr, ByVal ZeroBits As UIntPtr, ByVal CommitSize As UIntPtr, ByRef SectionOffset As ULong, ByRef ViewSize As UInteger, ByVal InheritDisposition As UInteger, ByVal AllocationType As UInteger, ByVal Win32Protect As UInteger) As UInteger
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function CloseHandle(ByVal hObject As IntPtr) As Boolean
    End Function
    <DllImport("kernel32.dll")>
    Public Function GetCurrentProcess() As IntPtr
    End Function
    <DllImport("msvcrt.dll", EntryPoint:="memset", CallingConvention:=CallingConvention.Cdecl, SetLastError:=False)>
    Public Function MemSet(dest As IntPtr, c As Integer, byteCount As Integer) As IntPtr
    End Function
    <DllImport("msvcrt.dll", EntryPoint:="memcpy", CallingConvention:=CallingConvention.Cdecl)>
    Public Sub CopyMemory(ByVal dest As IntPtr, ByVal src As IntPtr, ByVal count As Integer)
    End Sub

    <DllImport("kernel32", CharSet:=CharSet.Auto, SetLastError:=True)>
    Public Function VirtualProtectEx(ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal flNewProtect As UInteger, ByRef lpflOldProtect As UInteger) As Boolean
    End Function
    <DllImport("kernel32", CharSet:=CharSet.Auto, SetLastError:=True)>
    Public Function VirtualProtect(ByVal lpAddress As IntPtr, ByVal dwSize As Integer, ByVal flNewProtect As Integer, ByRef lpflOldProtect As UInteger) As Boolean
    End Function

End Module

```
