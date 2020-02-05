# composer
This should become a collection of tools I wrote to tamper with ELF files.

## What is it?
The goal is to make the manipulation of ELF files easy in python. An example is `injector.py` which hijacks the
execution flow of an ELF file by appending some shellcode to the file, modifying a PLT_NOTE segment
header and setting the entry point to the injected shellcode.

[![asciicast](https://asciinema.org/a/u5l3rqWWZihe3irHYSzJR8S50.svg)](https://asciinema.org/a/u5l3rqWWZihe3irHYSzJR8S50)

The functionality is far from complete, I plan to add funcitonality to handle/modify relocation entries and symbols.
