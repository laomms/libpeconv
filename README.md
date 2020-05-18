# libpeconv from hasherezade
 (https://github.com/hasherezade/libpeconv)    

Managed Dll(CLR .net4.5),不改变原有函数声明.支持非托管和托管程序直接调用.     
添加两个函数:   
添加区段：AddSection(test.exe/test.dll,.mysection,0x100,text(data/rdata),out)   
SectionRVA= AddSection <file_name> <section_name> <VirtualSize> <Characteristics> <RvaRawData>    
内部函数转导出函数: AddExtFuncton(test.exe/test.dll,.mysection,myfunc,0x1102)     
AddExtFuncton <file_name> <section_name> <FuncName> <FuncRva>   
 
 
 ```C
#pragma once
#include <windows.h>
#include <vcclr.h>
#using <System.dll>
#include <string>
#include <iostream>
#include "add_section.h"

using namespace System::Runtime::InteropServices;
using namespace System;
using namespace peconv;


#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif 

namespace PeconvCLR {
    public ref class FuncLists
    {
    public:
        static IntPtr LoadFile(IN String^ filename, size_t^% read_size)
        {
            size_t readsize=0;
            ALIGNED_BUF ret=load_file((char*)(void*)Marshal::StringToHGlobalAnsi(filename), readsize);
            read_size = readsize;
            return (IntPtr)ret;
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
        static IntPtr LoadPeExecutable_Dll(IntPtr dllRawData, size_t r_size,  size_t^ % v_size, IntPtr import_resolver)
        {
             size_t vsize = 0;
             BYTE * ret = load_pe_executable_dll((BYTE*)dllRawData.ToPointer(), r_size,  vsize, (t_function_resolver*)&import_resolver);
             v_size = vsize;
             return (IntPtr)ret;
        } 
        static IntPtr LoadPeExecutable(String^ my_path, size_t^% v_size, IntPtr import_resolver)
        {       
            size_t vsize = (size_t)v_size;
            BYTE* ret = load_pe_executable((char*)(void*)Marshal::StringToHGlobalAnsi(my_path),  vsize, (t_function_resolver*)&import_resolver);
            v_size = vsize;
            return  (IntPtr)ret;
        }
        static IntPtr LoadPeModule(String^ filename, size_t^% v_size, bool executable, bool relocate)
        {
            size_t vsize = 0;
            BYTE* ret = load_pe_module((char*)(void*)Marshal::StringToHGlobalAnsi(filename),  vsize, executable, relocate);
            v_size = vsize;
            return (IntPtr)ret;
        }
        static IntPtr LoadPeModule_Dll(IntPtr dllRawData, size_t r_size, size_t^% v_size, bool executable, bool relocate)
        {
            size_t vsize = 0;
            BYTE* ret = load_pe_module_dll((BYTE*)dllRawData.ToPointer(), r_size, vsize, executable, relocate);
            v_size = vsize;
            return (IntPtr)ret;
        }
        static IntPtr LoadreSourceData(size_t^% out_size, int res_id, String^ res_type, IntPtr hInstance)
        {
            size_t outsize = 0;
            ALIGNED_BUF ret = load_resource_data(outsize, res_id, (char*)Marshal::StringToHGlobalAnsi(res_type).ToPointer(), (HMODULE)hInstance.ToPointer());
            out_size = outsize;
            return (IntPtr)ret;
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
            return get_sections_count((BYTE*) payload.ToPointer(), buffer_size);
        }
        static IntPtr GetSectionHdr(IN IntPtr payload, IN const size_t buffer_size, IN size_t section_num)        
        {   
            return (IntPtr) get_section_hdr((BYTE*) payload.ToPointer(), buffer_size, section_num);
        }
        static ULONGLONG GetImagebase(IN IntPtr pe_buffer)
        {
            return get_image_base((BYTE*)pe_buffer.ToPointer());
        }
        static DWORD GetImagesize(IN IntPtr payload)
        {
            return get_image_size((BYTE*) payload.ToPointer());
        }
        static WORD GetSubsystem(IN IntPtr payload)
        {
            return get_subsystem((BYTE*)payload.ToPointer());
        }
        static IMAGE_EXPORT_DIRECTORY* GetExportDirectory(IN IntPtr modulePtr)
        {
            IMAGE_EXPORT_DIRECTORY* ret = get_export_directory((HMODULE)modulePtr.ToPointer());
            PIMAGE_EXPORT_DIRECTORY structs = (PIMAGE_EXPORT_DIRECTORY) & *ret;
            return structs;
        }
        static IntPtr PeRealignRawToVirtual(IN IntPtr payload, IN size_t in_size, IN ULONGLONG loadBase, size_t^% out_size)
        {
            size_t outsize =0;
            BYTE* ret = pe_realign_raw_to_virtual((BYTE*)payload.ToPointer(), in_size, loadBase, outsize);
            out_size = outsize;
            return (IntPtr)ret;
        }
        static IntPtr PeVirtualToRaw(IN IntPtr payload, IN size_t in_size, IN ULONGLONG loadBase,OUT size_t^% out_size, IN OPTIONAL bool rebuffer)
        {
            size_t outsize = 0;
            BYTE* ret = pe_virtual_to_raw( (BYTE*)payload.ToPointer(), in_size,loadBase,outsize,rebuffer);
            out_size = outsize;
            return (IntPtr)ret;
        }
        static bool DumpFile(IN String^ out_path, IN IntPtr dump_data, IN size_t dump_size)
        {
            array<Byte>^ bytedata = gcnew array<Byte>(dump_size);
            Marshal::Copy(dump_data, bytedata, 0, dump_size);
            pin_ptr<Byte> p = &bytedata[0];
            Byte* dumpdata = p;
            return dump_to_file((const char*)(void*)Marshal::StringToHGlobalAnsi(out_path), dumpdata,  dump_size);
        }
        static IntPtr FindPaddingCave(IntPtr modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact)
        {
            return (IntPtr)find_padding_cave((BYTE*)modulePtr.ToPointer(), moduleSize, minimal_size, req_charact);
        }
        static bool IsDll(IN IntPtr payload)
        {
            return is_module_dll((BYTE*)payload.ToPointer());
        }
        static bool Is64(IN IntPtr pe_buffer)
        {
            return is64bit(IN(BYTE*)pe_buffer.ToPointer());
        }
        static bool HasRelocations(IntPtr pe_buffer)
        {
            return has_relocations((BYTE*)pe_buffer.ToPointer());
        }
        static bool HasValidRelocationTable(IN IntPtr module_Ptr, IN const size_t moduleSize)
        {
           return process_relocation_table((PVOID)module_Ptr, moduleSize, nullptr);
        }
        static IntPtr ReadFromFile(IN String^ in_path, size_t^% read_size)
        {
            size_t readsize = 0;
            ALIGNED_BUF ret = read_from_file((const char*)(void*)Marshal::StringToHGlobalAnsi(in_path),  readsize);
            read_size = readsize;
            return (IntPtr)ret;
        }
        static bool RelocateModule(IN IntPtr modulePtr, IN size_t moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
        {
            return relocate_module((BYTE*)modulePtr.ToPointer(), moduleSize, newBase, oldBase);
        }
        static bool UpdateEntrypointRva(IN OUT IntPtr pe_buffer, IN DWORD value)
        {
            return update_entry_point_rva((BYTE*)pe_buffer.ToPointer(),value);
        }
        static bool ValidatePtr(IN const IntPtr buffer_bgn, IN size_t buffer_size, IN IntPtr field_bgn, IN size_t field_size)
        {
            return validate_ptr((void*) buffer_bgn, buffer_size, (void*) field_bgn, field_size);
        }
        static bool is_compatibile(IntPtr implant_dll);
        static IntPtr GetFileHdr(IN IntPtr payload, IN const size_t buffer_size)
        {
            const IMAGE_FILE_HEADER* ret = get_file_hdr((BYTE*)payload.ToPointer(), buffer_size);   
            PIMAGE_FILE_HEADER structs =(PIMAGE_FILE_HEADER) & *ret;
            return (IntPtr)structs;
        }      
        static IntPtr GetDirectoryEntry(IN  IntPtr pe_buffer, IN DWORD dir_id, IN bool allow_empty)
        {
            IMAGE_DATA_DIRECTORY* ret = get_directory_entry( (const BYTE*) pe_buffer.ToPointer(),  dir_id, allow_empty);
            PIMAGE_FILE_HEADER structs = (PIMAGE_FILE_HEADER) & *ret;
            return (IntPtr)structs;
        }
        static IntPtr GettyPeDirectory(IN IntPtr modulePtr, IN DWORD dir_id)
        {
            IMAGE_EXPORT_DIRECTORY *ret= get_type_directory<IMAGE_EXPORT_DIRECTORY>((HMODULE)modulePtr.ToPointer(),  dir_id);
            return (IntPtr)ret;
        }  
        static size_t RedirectToLocal64(IntPtr ptr, DWORD new_offset, IntPtr backup)
        {
            return peconv::redirect_to_local64((void*)ptr, new_offset, (PatchBackup*)backup.ToPointer());
        }
        static size_t RedirectToLocal32(IntPtr ptr, DWORD new_offset, IntPtr backup)
        {
            return peconv::redirect_to_local32((void*)ptr, new_offset, (PatchBackup*)backup.ToPointer());
        }
        static size_t RedirectToLocal(IntPtr ptr, IntPtr new_function_ptr, IntPtr backup)
        {
            return peconv::redirect_to_local((void*)ptr, (void*)new_function_ptr, (PatchBackup*)backup.ToPointer());
        }
        static FARPROC GetExportedFunc(IntPtr modulePtr, String^ wanted_name)
        {
            return peconv::get_exported_func((PVOID)modulePtr, (LPSTR) &wanted_name);
        }
        static FARPROC ResolveFunc(String^ lib_name, String^ func_name)
        {
            t_function_resolver* func_resolver;
            return func_resolver->resolve_func((LPSTR)&lib_name, (LPSTR)&func_name);
        }
        static size_t GetExportedNames(IntPtr modulePtr, array<String^>^ names_list)
        {
            return peconv::get_exported_names((PVOID)modulePtr,(std::vector<std::string>&) names_list);
        }
        static bool ProcessImportTable(IN IntPtr modulePtr, IN SIZE_T moduleSize, IN IntPtr callback)
        {
            return peconv::process_import_table((BYTE*)modulePtr.ToPointer(), moduleSize, (ImportThunksCallback*) callback.ToPointer());
        }
        static HMODULE GetModuleViaPeb(IN OPTIONAL String^ module_name)
        {
            return peconv::get_module_via_peb((LPWSTR)&module_name);
        }
        static size_t GetModuleSizeViaPeb(IN OPTIONAL IntPtr hModule)
        {
            return peconv::get_module_size_via_peb((HMODULE)hModule.ToPointer());
        }
        static bool ReplaceTarget(array<System::Byte>^ patch_ptr, ULONGLONG dest_addr)
        {
            return peconv::replace_target((BYTE*)&patch_ptr, dest_addr);
        }
        static bool AddSection(String^ path, String^ wc_section_name, DWORD VirtualSize, String^ str_Characteristics)
        {
            return add_section((PWSTR)&path, (PWSTR)&wc_section_name, VirtualSize, (PWSTR)&str_Characteristics);
        }
    };
}

```


# module_overloading example:     
https://github.com/hasherezade/module_overloading/blob/master/project_template/main.cpp


```vb.net
Imports System.Runtime.InteropServices

#If WIN64 Then
Imports SizeT = System.UInt64
#ElseIf WIN32 Then
Imports SizeT = System.UInt32
#End If
Module Module1

    Sub Main()
        Dim mapped As IntPtr = map_dll_image("C:\Windows\System32\KernelBase.dll")
        Dim v_size As UInteger
        Dim implant_dll = PeconvCLR.FuncLists.LoadPeExecutable("test.dll", v_size, 0)
        If implant_dll = IntPtr.Zero Then
            Console.WriteLine("Failed to load the implant!")
        End If
        If PeconvCLR.FuncLists.is_compatibile(implant_dll) Then
            If PeconvCLR.FuncLists.RelocateModule(implant_dll, v_size, mapped, implant_dll.ToInt64) Then
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

    Private Function overwrite_mapping(mapped As IntPtr, implant_dll As IntPtr, implant_size As UInteger) As Boolean
        Dim hProcess As IntPtr = GetCurrentProcess()
        Dim oldProtect As UInteger = 0

        Dim prev_size As UInteger = PeconvCLR.FuncLists.GetImagesize(mapped)
        If prev_size <> 0 Then
            If Not VirtualProtect(mapped, prev_size, PAGE_READWRITE, oldProtect) Then
                Return False
            End If
            MemSet(mapped, 0, prev_size)
            If Not VirtualProtect(mapped, prev_size, PAGE_READONLY, oldProtect) Then
                Return False
            End If
        End If
        If Not VirtualProtect(mapped, implant_size, PAGE_READWRITE, oldProtect) Then
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
        If Not VirtualProtect(mapped, &H1000, PAGE_READONLY, oldProtect) Then
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
        If sec_charact And IMAGE_SCN_MEM_EXECUTE <> 0 AndAlso sec_charact And IMAGE_SCN_MEM_READ <> 0 AndAlso sec_charact And IMAGE_SCN_MEM_WRITE <> 0 Then
            Return PAGE_EXECUTE_READWRITE
        End If
        If sec_charact And IMAGE_SCN_MEM_EXECUTE <> 0 AndAlso sec_charact And IMAGE_SCN_MEM_READ <> 0 Then
            Return PAGE_EXECUTE_READ
        End If
        If sec_charact And IMAGE_SCN_MEM_EXECUTE <> 0 Then
            Return PAGE_EXECUTE_READ
        End If
        If sec_charact And IMAGE_SCN_MEM_READ <> 0 AndAlso sec_charact And IMAGE_SCN_MEM_WRITE <> 0 Then
            Return PAGE_READWRITE
        End If
        If sec_charact And IMAGE_SCN_MEM_READ <> 0 Then
            Return PAGE_READONLY
        End If
        Return PAGE_READWRITE
    End Function
    Private Sub run_implant(ByVal mapped As IntPtr, ByVal ep_rva As UInteger, ByVal is_dll As Boolean)
        Dim implant_ep As IntPtr = IntPtr.Add(mapped, ep_rva)
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
![image](https://github.com/laomms/libpeconv/blob/master/test.png)   

# pe_to_shellcode sample:   
https://github.com/hasherezade/pe_to_shellcode/blob/master/pe2shc/main.cpp   
```vb.net
Imports System.Runtime.InteropServices

#If Win64 Then
Imports SizeT = System.UInt64
#ElseIf Win32 Then
Imports SizeT = System.UInt32
#End If

Module Module1

    Private Function overwrite_hdr(ByRef my_exe As IntPtr, ByVal raw As SizeT) As Boolean
        Dim redircode() As Byte = New Byte() {&H4D, &H5A, &H45, &H52, &HE8, &H0, &H0, &H0, &H0, &H5B, &H48, &H83, &HEB, &H9, &H53, &H48, &H81, &HC3, &H59, &H4, &H0, &H0, &HFF, &HD3, &HC3, &H0}
        Buffer.BlockCopy(BitConverter.GetBytes(raw), 0, redircode, 18, 4)
        Marshal.Copy(redircode, 0, my_exe, redircode.Length)
        Return True
    End Function

    Private Function shellcodify(ByRef my_exe As IntPtr, ByVal exe_size As SizeT, ByRef out_size As SizeT, ByVal is64b As Boolean) As IntPtr
        out_size = 0
        Dim stub_size As SizeT
        Dim stub As IntPtr
        If is64b Then
            stub_size = My.Resources.stub64.Length
            stub = Marshal.AllocHGlobal(My.Resources.stub64.Length)
            Marshal.Copy(My.Resources.stub64, 0, stub, My.Resources.stub64.Length)
        Else
            stub_size = My.Resources.stub32.Length
            stub = Marshal.AllocHGlobal(My.Resources.stub32.Length)
            Marshal.Copy(My.Resources.stub32, 0, stub, My.Resources.stub32.Length)
        End If
        Dim ext_size As SizeT = exe_size + stub_size
        Dim ext_buf As IntPtr = PeconvCLR.FuncLists.AllocAligned(ext_size, &H4, 0)
        If ext_buf = IntPtr.Zero Then
            Return Nothing
        End If
        memcpy(ext_buf, my_exe, exe_size)
        memcpy(ext_buf + exe_size, stub, stub_size)
        Dim raw_addr As SizeT = exe_size
        overwrite_hdr(ext_buf, raw_addr)
        out_size = ext_size
        Return ext_buf
    End Function

    Private Function has_tls_callbacks(ByRef my_exe As IntPtr, ByVal exe_size As SizeT) As Boolean
        Dim Ptls_dir As IntPtr = PeconvCLR.FuncLists.GetDirectoryEntry(my_exe, IMAGE_DIRECTORY_ENTRY_TLS, False)
        If Ptls_dir = IntPtr.Zero Then
            Return False
        End If
        Dim tls_dir As IMAGE_DATA_DIRECTORY = Marshal.PtrToStructure(Ptls_dir, GetType(IMAGE_DATA_DIRECTORY))
        Dim Ptls As IntPtr = PeconvCLR.FuncLists.GettyPeDirectory(my_exe, IMAGE_DIRECTORY_ENTRY_TLS)
        If Ptls = IntPtr.Zero Then
            Return False
        End If
        Dim tls As IMAGE_TLS_DIRECTORY = Marshal.PtrToStructure(Ptls, GetType(IMAGE_TLS_DIRECTORY))
        Dim base As ULong = PeconvCLR.FuncLists.GetImagebase(my_exe)
        Dim callback_rva As ULong = tls.AddressOfCallBacks
        If callback_rva > base Then
            callback_rva -= base
        End If
        If Not PeconvCLR.FuncLists.ValidatePtr(my_exe, exe_size, IntPtr.Add(my_exe, callback_rva), Len(New ULong())) Then
            Return False
        End If
        Dim callback_addr As ULong = CULng(my_exe + callback_rva)
        If callback_addr = Nothing Then
            Return False
        End If
        If callback_addr = Nothing Then
            Return False
        End If
        Return True
    End Function

    Private Function is_supported_pe(ByRef my_exe As IntPtr, ByVal exe_size As SizeT) As Boolean
        If my_exe = IntPtr.Zero Then
            Return False
        End If
        If Not PeconvCLR.FuncLists.HasRelocations(my_exe) Then
            Console.WriteLine("[-] The PE must have relocations!")
            Console.WriteLine(ControlChars.Lf)
            Return False
        End If
        If PeconvCLR.FuncLists.GetSubsystem(my_exe) <> 2 Then
            Console.WriteLine("[WARNING] This is a console application! The recommended subsystem is GUI.")
            Console.WriteLine(ControlChars.Lf)
        End If
        Dim p_dotnet_dir As IntPtr = PeconvCLR.FuncLists.GetDirectoryEntry(my_exe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, False)
        If p_dotnet_dir = IntPtr.Zero Then
            Console.WriteLine("[-] .NET applications are not supported!")
            Console.WriteLine(ControlChars.Lf)
            Return False
        End If
        Dim dotnet_dir As IMAGE_DATA_DIRECTORY = Marshal.PtrToStructure(p_dotnet_dir, GetType(IMAGE_DATA_DIRECTORY))
        Dim p_tls_dir As IntPtr = PeconvCLR.FuncLists.GetDirectoryEntry(my_exe, IMAGE_DIRECTORY_ENTRY_TLS, False)
        Dim tls_dir As IMAGE_DATA_DIRECTORY = Marshal.PtrToStructure(p_tls_dir, GetType(IMAGE_DATA_DIRECTORY))
        If tls_dir.Size <> 0 Then
            Dim has_callback As Boolean = False
            If Not PeconvCLR.FuncLists.Is64(my_exe) Then
                If has_tls_callbacks(my_exe, exe_size) Then
                    has_callback = True
                End If
            Else
                If has_tls_callbacks(my_exe, exe_size) Then
                    has_callback = True
                End If
            End If
            If has_callback Then
                Console.WriteLine("[WARNING] This application has TLS callbacks, which are not supported!")
                Console.WriteLine(ControlChars.Lf)
            End If
        End If
        Return True
    End Function

    Private Function is_supported_pe(ByVal in_path As String) As Boolean
        Console.WriteLine("Reading module from: ")
        Console.WriteLine(in_path)
        Console.WriteLine(ControlChars.Lf)
        Dim exe_size As SizeT = 0
        Dim my_exe As IntPtr = PeconvCLR.FuncLists.LoadPeModule(in_path, exe_size, False, False)
        If my_exe = IntPtr.Zero Then
            Console.WriteLine("[-] Could not read the input file!")
            Console.WriteLine(ControlChars.Lf)
            Return False
        End If

        Dim is_ok As Boolean = is_supported_pe(my_exe, exe_size)
        PeconvCLR.FuncLists.FreePeBuffer(my_exe, 0)

        If Not is_ok Then
            Console.WriteLine("[-] Not supported input file!")
            Console.WriteLine(ControlChars.Lf)
            Return False
        End If
        Return True
    End Function

    Private Function make_out_name(ByVal input_file As String) As String
        Dim found_indx As SizeT = input_file.LastIndexOfAny((Convert.ToString(".")).ToCharArray())
        Dim ext As String = input_file.Substring(found_indx + 1)
        Dim name As String = input_file.Substring(0, found_indx)
        Return name & ".shc." & ext
    End Function

    Sub Main()
        Dim in_path As String = "test.exe"
        Dim out_str As String = make_out_name(in_path)

        Dim exe_size As SizeT = 0
        Dim my_exe As IntPtr = PeconvCLR.FuncLists.LoadFile(in_path, exe_size)
        If my_exe = IntPtr.Zero Then
            Console.WriteLine("[-] Could not read the input file!")
            Console.WriteLine(ControlChars.Lf)
        End If

        Dim is64b As Boolean = PeconvCLR.FuncLists.Is64(my_exe)
        Dim ext_size As SizeT = 0
        Dim ext_buf As IntPtr = shellcodify(my_exe, exe_size, ext_size, is64b)
        If ext_buf = IntPtr.Zero Then
            Console.WriteLine("[-] Adding the stub failed!")
            Console.WriteLine(ControlChars.Lf)
            PeconvCLR.FuncLists.FreeFile(my_exe)
        End If
        If PeconvCLR.FuncLists.DumpFile(out_str, ext_buf, ext_size) Then
            Console.WriteLine("[+] Saved as: ")
            Console.WriteLine(out_str)
            Console.WriteLine(ControlChars.Lf)
        Else
            Console.WriteLine("[-] Failed to save the output!")
            Console.WriteLine(ControlChars.Lf)
        End If
        PeconvCLR.FuncLists.FreeFile(my_exe)
        PeconvCLR.FuncLists.FreeaLigned(ext_buf, 0)
        runshc(out_str)


    End Sub
    Private Sub runshc(in_path As String)
        Dim exe_size As SizeT = 0

        Console.WriteLine("[*] Reading module from: ")
        Console.WriteLine(in_path)
        Console.WriteLine(ControlChars.Lf)
        Dim my_exe As IntPtr = PeconvCLR.FuncLists.LoadFile(in_path, exe_size)
        If my_exe = 0 Then
            Console.WriteLine("[-] Loading file failed")
            Console.WriteLine(ControlChars.Lf)
        End If
        Dim test_buf As IntPtr = PeconvCLR.FuncLists.AllocAligned(exe_size, PAGE_EXECUTE_READWRITE, 0)
        If test_buf = IntPtr.Zero Then
            PeconvCLR.FuncLists.FreeFile(my_exe)
            Console.WriteLine("[-] Allocating buffer failed")
            Console.WriteLine(ControlChars.Lf)
        End If
        memcpy(test_buf, my_exe, exe_size)

        'free the original buffer:
        PeconvCLR.FuncLists.FreeFile(my_exe)
        my_exe = Nothing

        Console.WriteLine("[*] Running the shellcode:")
        Console.WriteLine(ControlChars.Lf)
        'run it:
        Dim my_main As my_mainDelegate = Marshal.GetDelegateForFunctionPointer(test_buf, GetType(my_mainDelegate))
        Dim ret_val As Integer = my_main()

        PeconvCLR.FuncLists.FreeaLigned(test_buf, exe_size)
        Console.WriteLine("[+] The shellcode finished with a return value: ")
        Console.WriteLine("{0:x}", ret_val)
        Console.WriteLine("{0:x}", ControlChars.Lf)
    End Sub
    Public Const IMAGE_DIRECTORY_ENTRY_TLS As UInteger = &H2
    Public Const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR As Integer = 14
    Public Const PAGE_EXECUTE_READWRITE As UInteger = &H40UI
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_DATA_DIRECTORY
        Public VirtualAddress As UInteger
        Public Size As UInteger
    End Structure
    <StructLayout(LayoutKind.Sequential)>
    Public Structure IMAGE_TLS_DIRECTORY
        Public StartAddressOfRawData As UIntPtr
        Public EndAddressOfRawData As UIntPtr
        Public AddressOfIndex As UIntPtr
        Public AddressOfCallBacks As UIntPtr
        Public SizeOfZeroFill As UInt32
        Public Characteristics As UInt32
    End Structure

    <UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet:=CharSet.Unicode)>
    Public Delegate Function my_mainDelegate() As Integer

    <DllImport("msvcrt.dll", EntryPoint:="memcpy", CallingConvention:=CallingConvention.Cdecl)>
    Public Sub memcpy(ByVal dest As IntPtr, ByVal src As IntPtr, ByVal count As Integer)
    End Sub
    <DllImport("kernel32.dll", SetLastError:=True)>
    Function FindResource(ByVal hModule As IntPtr, ByVal lpName As String, ByVal lpType As String) As IntPtr
    End Function
    <DllImport("kernel32.dll")>
    Function FindResource(ByVal hModule As IntPtr, ByVal lpID As Integer, ByVal lpType As String) As IntPtr
    End Function
    <DllImport("kernel32.dll", EntryPoint:="RtlFillMemory", SetLastError:=False)>
    Public Sub FillMemory(ByVal destination As IntPtr, ByVal length As UInteger, ByVal fill As Byte)
    End Sub
End Module

```
