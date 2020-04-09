# composer
This should become a collection of tools I wrote to tamper with ELF files.

## What is it?
The goal of this project is to provide python code, that makes the manipulation of ELF files easy. Currently it is possible to read and modify
- ELF header members
- section header members
- program header members
- symbols in sections
I plan to add
- handling/modification of relocation entries
- some higher-level functionality like reconstruction section headers and different code injection techniques
- handling loaded elf files (i.e. reading elf-files from memory)

## How do I use it?
*composer* provides a interface for working with ELF files:
```python
>>> from elf import *
>>> e = ELFFile("/tmp/some_elf")
>>> e.header.e_phnum
11
>>> for segment in e.segments:
...     segment.header.p_type
...
6
3
1
1
1
1
2
4
1685382480
1685382481
1685382482
>>> e.header.e_phnum = 8
>>> len(e.segments)
8
>>> for s in e.sections:
...     print(s)  # prints the name of the section using the .strtab and sh_name
...

.interp
.note.gnu.build-id
  <-- snip -->
.shstrtab
>>> e.sections[10].header.sh_info
22
>>> SHT_SYMTAB = 2
>>> SHT_DYNSYM = 11
>>> holds_symbols = [s for s in e.sections if s.header.sh_type in [SHT_SYMTAB, SHT_DYNSYM]]
>>> for sym in holds_symbols[0].symbols:
...     print(sym)  # prints the name of the section using the .strtab and st_name
...


m_clones
dtors_aux_fini_array_entry
array_entry
.c

``` 

## What is it good for?
*composer* shall help to do different offensive and forensic tasks like reconstruction, instrumentation, and infection of ELF binaries.

A very simple example is `injector.py` which hijacks the execution flow of an ELF file by appending some shellcode to the file, modifying a `PLT_NOTE` segment header and setting the entry point to the injected shellcode.

[![asciicast](https://asciinema.org/a/u5l3rqWWZihe3irHYSzJR8S50.svg)](https://asciinema.org/a/u5l3rqWWZihe3irHYSzJR8S50)

The functionality is far from complete, I plan to add funcitonality to handle/modify relocation entries and symbols.
