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

Managed Dll(CLR):
 ```C
#pragma once
#include <windows.h>
#include <vcclr.h>
#using <System.dll>

using namespace System;

namespace PeconvCLR {   
	public ref class Class1
	{
	public:
         peconv::ALIGNED_BUF load_file(IN const char* filename, OUT size_t & read_size)
        {
            return load_file(IN filename, OUT  read_size);
        }
          void free_file(IN peconv::ALIGNED_BUF buffer)
        {
            return free_file(IN  buffer);
        }
         peconv::ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
        {
            return alloc_aligned(buffer_size, protect, desired_base);
        }
          bool free_aligned(peconv::ALIGNED_BUF buffer, size_t buffer_size)
        {
            return free_aligned(buffer, buffer_size);
        }
         BYTE * load_pe_executable_dll(BYTE * dllRawData, size_t r_size, OUT size_t & v_size, t_function_resolver * import_resolver)
        {
            return load_pe_executable_dll(dllRawData, r_size, OUT  v_size, import_resolver);
        }
         BYTE * load_pe_executable(const char* my_path, OUT size_t & v_size, t_function_resolver * import_resolver)
        {
            return load_pe_executable(my_path, OUT v_size, import_resolver);
        }
         BYTE * load_pe_module(const char* filename, OUT size_t & v_size, bool executable, bool relocate)
        {
            return load_pe_module(filename, OUT  v_size, executable, relocate);
        }
         BYTE * load_pe_module_dll(BYTE * dllRawData, size_t r_size, OUT size_t & v_size, bool executable, bool relocate)
        {
            return load_pe_module_dll(dllRawData, r_size, OUT  v_size, executable, relocate);
        }
         peconv::ALIGNED_BUF load_resource_data(OUT size_t & out_size, int res_id, const LPSTR res_type, HMODULE hInstance)
        {
            return load_resource_data(OUT out_size, res_id, res_type, hInstance);
        }
         bool free_pe_buffer(peconv::ALIGNED_BUF buffer, size_t buffer_size)
        {
            return free_pe_buffer(buffer, buffer_size);
        }
         DWORD get_entry_point_rva(IN const BYTE * pe_buffer)
        {
            return get_entry_point_rva(pe_buffer);
        }
         size_t get_sections_count(IN const BYTE * payload, IN const size_t buffer_size)
        {
            return get_sections_count(IN payload, buffer_size);
        }
         PIMAGE_SECTION_HEADER get_section_hdr(IN const BYTE * payload, IN const size_t buffer_size, IN size_t section_num)
        {
            return get_section_hdr(IN payload, IN  buffer_size, IN  section_num);
        }
         ULONGLONG get_image_base(IN const BYTE * pe_buffer)
        {
            return get_image_base(pe_buffer);
        }
         DWORD get_image_size(IN const BYTE * payload)
        {
            return get_image_size(IN  payload);
        }
         WORD get_subsystem(IN const BYTE * payload)
        {
            return get_subsystem(payload);
        }
         IMAGE_EXPORT_DIRECTORY * get_export_directory(IN HMODULE modulePtr)
        {
            return get_export_directory(modulePtr);
        }
         BYTE * pe_realign_raw_to_virtual(IN const BYTE * payload, IN size_t in_size, IN ULONGLONG loadBase, OUT size_t & out_size)
        {
            return pe_realign_raw_to_virtual(IN payload, IN in_size, IN loadBase, OUT  out_size);
        }
         BYTE * pe_virtual_to_raw(IN BYTE * payload, IN size_t in_size, IN ULONGLONG loadBase, OUT size_t & out_size, IN OPTIONAL bool rebuffer)
        {
            return pe_virtual_to_raw(IN  payload, IN  in_size, IN  loadBase, OUT  out_size, IN OPTIONAL  rebuffer);
        }
         bool dump_to_file(IN const char* out_path, IN PBYTE dump_data, IN size_t dump_size)
        {
            return dump_to_file(IN  out_path, IN  dump_data, IN  dump_size);
        }
         PBYTE find_padding_cave(BYTE * modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact)
        {
            return find_padding_cave(modulePtr, moduleSize, minimal_size, req_charact);
        }
         bool is_module_dll(IN const BYTE * payload)
        {
            return is_module_dll(IN  payload);
        }
         bool is64bit(IN const BYTE * pe_buffer)
        {
            return is64bit(IN  pe_buffer);
        }
         bool has_relocations(IN const BYTE * pe_buffer)
        {
            return has_relocations(IN  pe_buffer);
        }
         bool has_valid_relocation_table(IN const PBYTE modulePtr, IN const size_t moduleSize)
        {
            return has_valid_relocation_table(IN  modulePtr, IN  moduleSize);
        }
         peconv::ALIGNED_BUF read_from_file(IN const char* in_path, IN OUT size_t & read_size)
        {
            return read_from_file(IN  in_path, IN OUT  read_size);
        }
         bool relocate_module(IN BYTE * modulePtr, IN SIZE_T moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
        {
            return relocate_module(IN modulePtr, IN  moduleSize, IN newBase, IN oldBase);
        }
         bool update_entry_point_rva(IN OUT BYTE * pe_buffer, IN DWORD value)
        {
            return update_entry_point_rva(IN OUT  pe_buffer, IN  value);
        }
         bool validate_ptr(IN const void* buffer_bgn, IN SIZE_T buffer_size, IN const void* field_bgn, IN SIZE_T field_size)
        {
            return validate_ptr(IN  buffer_bgn, IN  buffer_size, IN  field_bgn, IN  field_size);
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
