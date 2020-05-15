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

Managed Dll(CLR .net4.5):
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

namespace PeconvCLR {
    public ref class FuncLists
    {
    public:
        static IntPtr LoadFile(IN String^ filename, OUT unsigned int read_size)  //unsigned __int64 for x64
        {
            char* filename_ = (char*)(void*)Marshal::StringToHGlobalAnsi(filename);
            return (IntPtr)load_file(IN filename_, OUT read_size);
        }
        static  void FreeFile(IN Byte buffer)
        {
            return free_file((PBYTE)buffer);
        }
        static IntPtr AllocAligned(unsigned int buffer_size, int protect, ULONGLONG desired_base)
        {
            return (IntPtr)alloc_aligned(buffer_size, protect, desired_base);
        }
        static  bool FreeaLigned(Byte buffer, unsigned  int buffer_size)
        {
            return free_aligned((PBYTE)buffer, buffer_size);
        }
        static IntPtr LoadPeExecutable_Dll(array<Byte>^ dllRawData, unsigned int r_size, unsigned int v_size, IntPtr import_resolver)
        {
            cli::pin_ptr<Byte> p = &dllRawData[0];
            BYTE* dll_RawData = p;
            return (IntPtr)load_pe_executable_dll(dll_RawData, r_size, v_size, (t_function_resolver*)&import_resolver);
        }
        static IntPtr LoadPeExecutable(String^ my_path, OUT unsigned int v_size, IntPtr import_resolver)
        {
            char* mypath = (char*)(void*)Marshal::StringToHGlobalAnsi(my_path);
            return  (IntPtr)load_pe_executable(mypath, OUT v_size, (t_function_resolver*)&import_resolver);
        }
        static IntPtr LoadPeModule(String^ filename, OUT unsigned int v_size, bool executable, bool relocate)
        {
            char* filename_ = (char*)(void*)Marshal::StringToHGlobalAnsi(filename);
            return (IntPtr)load_pe_module(filename_, OUT  v_size, executable, relocate);
        }
        static IntPtr LoadPeModule_Dll(BYTE* dllRawData, unsigned int r_size, OUT unsigned int v_size, bool executable, bool relocate)
        {
            cli::pin_ptr<Byte> p = &dllRawData[0];
            BYTE* dll_RawData = p;
            return (IntPtr)load_pe_module_dll(dll_RawData, r_size, OUT  v_size, executable, relocate);
        }
        static IntPtr LoadreSourceData(OUT unsigned int out_size, int res_id, String^ res_type, IntPtr hInstance)
        {
            char buffer[1024];
            IntPtr hglob = Marshal::StringToHGlobalAnsi(res_type);
            char* restype = static_cast<char*>(hglob.ToPointer());
            strcpy(buffer, restype);
            Marshal::FreeHGlobal(hglob);
            return (IntPtr)load_resource_data(OUT out_size, res_id, restype, (HMODULE)hInstance.ToPointer());
        }
        static bool FreePeBuffer(Byte buffer, unsigned int buffer_size)
        {
            return free_pe_buffer((PBYTE)buffer, buffer_size);
        }
        static DWORD GetEntrypoint_Rva(IN const array<Byte>^ pe_buffer)
        {
            cli::pin_ptr<Byte> p = &pe_buffer[0];
            BYTE* pebuffer = p;
            return get_entry_point_rva(pebuffer);
        }
        static unsigned int GetSectionsCount(IN const array<Byte>^ payload, IN const unsigned int buffer_size)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return get_sections_count(IN payload_, buffer_size);
        }
        static PIMAGE_SECTION_HEADER GetSectionHdr(IN const array<Byte>^ payload, IN const unsigned int buffer_size, IN unsigned int section_num)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return get_section_hdr(IN payload_, IN  buffer_size, IN  section_num);
        }
        static ULONGLONG GetImagebase(IN const array<Byte>^ pe_buffer)
        {
            cli::pin_ptr<Byte> p = &pe_buffer[0];
            BYTE* pebuffer = p;
            return get_image_base(pebuffer);
        }
        static DWORD GetImagesize(IN const array<Byte>^ payload)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return get_image_size(IN  payload_);
        }
        static WORD GetSubsystem(IN const array<Byte>^ payload)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return get_subsystem(payload_);
        }
        static IMAGE_EXPORT_DIRECTORY* GetExportDirectory(IN IntPtr modulePtr)
        {
            return get_export_directory((HMODULE)modulePtr.ToPointer());
        }
        static IntPtr PeRealignRawToVirtual(IN const array<Byte>^ payload, IN unsigned int in_size, IN ULONGLONG loadBase, OUT unsigned int& out_size)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return (IntPtr)pe_realign_raw_to_virtual(IN payload_, IN in_size, IN loadBase, OUT  out_size);
        }
        static IntPtr PeVirtualToRaw(IN array<Byte>^ payload, IN unsigned int in_size, IN ULONGLONG loadBase, OUT unsigned int& out_size, IN OPTIONAL bool rebuffer)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return (IntPtr)pe_virtual_to_raw(IN  payload_, IN  in_size, IN  loadBase, OUT  out_size, IN OPTIONAL  rebuffer);
        }
        static bool DumpFile(IN const char* out_path, IN PBYTE dump_data, IN unsigned int dump_size)
        {
            return dump_to_file(IN  out_path, IN  dump_data, IN  dump_size);
        }
        static PBYTE FindPaddingCave(array<Byte>^ modulePtr, unsigned int moduleSize, const unsigned int minimal_size, const DWORD req_charact)
        {
            cli::pin_ptr<Byte> p = &modulePtr[0];
            BYTE* modulePtr_ = p;
            return find_padding_cave(modulePtr_, moduleSize, minimal_size, req_charact);
        }
        static bool IsDll(IN const array<Byte>^ payload)
        {
            cli::pin_ptr<Byte> p = &payload[0];
            BYTE* payload_ = p;
            return is_module_dll(IN  payload_);
        }
        static bool Is64(IN const array<Byte>^ pe_buffer)
        {
            cli::pin_ptr<Byte> p = &pe_buffer[0];
            BYTE* pebuffer = p;
            return is64bit(IN  pebuffer);
        }
        static bool HasRelocations(IN const array<Byte>^ pe_buffer)
        {
            cli::pin_ptr<Byte> p = &pe_buffer[0];
            BYTE* pebuffer = p;
            return has_relocations(IN  pebuffer);
        }
        static bool HasValidRelocationTable(IN const PBYTE modulePtr, IN const unsigned int moduleSize)
        {
            return has_valid_relocation_table(IN  modulePtr, IN  moduleSize);
        }
        static Byte ReadFromFile(IN const char* in_path, IN OUT unsigned int& read_size)
        {
            return (Byte)read_from_file(IN  in_path, IN OUT  read_size);
        }
        static bool RelocateModule(IN array<Byte>^ modulePtr, IN unsigned int moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
        {
            cli::pin_ptr<Byte> p = &modulePtr[0];
            BYTE* modulePtr_ = p;
            return relocate_module(IN modulePtr_, IN  moduleSize, IN newBase, IN oldBase);
        }
        static bool UpdateEntrypointRva(IN OUT array<Byte>^ pe_buffer, IN DWORD value)
        {
            cli::pin_ptr<Byte> p = &pe_buffer[0];
            BYTE* pebuffer = p;
            return update_entry_point_rva(IN OUT  pebuffer, IN  value);
        }
        static bool ValidatePtr(IN const IntPtr buffer_bgn, IN unsigned int buffer_size, IN const IntPtr field_bgn, IN unsigned int field_size)
        {

            return validate_ptr(IN (void*) buffer_bgn, IN  buffer_size, IN(void*)field_bgn, IN  field_size);
        }
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
