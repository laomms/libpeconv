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

[![Build status](https://ci.appveyor.com/api/projects/status/pqo6ob148pf5b352?svg=true)](https://ci.appveyor.com/project/hasherezade/libpeconv)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/55911b033cf145d38d6e38a0c005b686)](https://www.codacy.com/manual/hasherezade/libpeconv?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=hasherezade/libpeconv&amp;utm_campaign=Badge_Grade)

A library to load and manipulate PE files.<br/>
<br/>

### Basic example

*The simplest usecase*: use libPeConv to manually load and run an EXE of you choice.

```C

### Read more
+   [Docs](https://hasherezade.github.io/libpeconv/)
+   [Examples](https://github.com/hasherezade/libpeconv/tree/master/tests)
+   [Tutorials](https://hshrzd.wordpress.com/tag/libpeconv/)
+   [Project template](https://github.com/hasherezade/libpeconv_project_template)
