# libpeconv from hasherezade
 (https://github.com/hasherezade/libpeconv)    

重新编译版,dll和crt_dll
 
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
