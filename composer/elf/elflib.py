"""
Provides abstraction to modify ELF executables in a comfortable
way on a low level.
"""

import os
from abc import ABC, abstractmethod
from composer.extensions import elf_handler

SHT_SYMTAB = 2
SHT_DYNSYM = 11
EI_NIDENT = 16


E_HEADER_MEMBERS = {
    "e_type", "e_machine", "e_version", "e_entry",
    "e_phoff", "e_shoff", "e_flags", "e_ehsize",
    "e_phentsize", "e_phnum", "e_shentsize", "e_phnum",
    "e_shnum", "e_shstrndx"
}

S_HEADER_MEMBERS = {
    "sh_name", "sh_type", "sh_flags", "sh_addr",
    "sh_offset", "sh_size", "sh_link", "sh_info",
    "sh_addralign", "sh_entsize"
}

P_HEADER_MEMBERS = {
    "p_type", "p_flags", "p_offset", "p_vaddr",
    "p_paddr", "p_filesz", "p_memsz", "p_align"
}

SYMBOL_MEMBERS = {
    "st_name", "st_other", "st_shndx", "st_value", "st_size"
}


class ELFFile:
    """
    A ELF executable that can be read and modified.

    Changes to this object will be written directly to the file so
    be careful!
    """
    def __init__(self, path, force=False):
        self.__path = path

        print(self.header.e_ident[0:4])
        if not self.header.e_ident[0:4] == bytearray(b"\x7fELF") and not force:
            msg = "The given file is not an ELF file (set optional argument "\
                  "'force=True' to force loading)"
            raise IOError(msg)

    @property
    def header(self):
        """The ELF header of the executable."""
        return ELFHeader(self.__path)

    @property
    def section_headers(self):
        """The section headers of the executable."""
        return [SectionHeader(self.__path, i)
                for i in range(self.header.e_shnum)]

    @property
    def sections(self):
        """The section headers of the executable."""
        return [Section(self.__path, i)
                for i in range(self.header.e_shnum)]

    @property
    def segments(self):
        """The section headers of the executable."""
        return [Segment(self.__path, i)
                for i in range(self.header.e_phnum)]

    @property
    def program_headers(self):
        """The program headers of the executable."""
        return [ProgramHeader(self.__path, i)
                for i in range(self.header.e_phnum)]

    def insert_at(self, offset, data):
        """
        Insert data at given position.

        The data is /inserted/ i.e. the data after the specifieid offset
        is moved after the inserted data block.

        Args:
            offset (int): file offset to write data at
            data (bytes): the data to write
        """
        with open(self.__path, "wb+") as elf_file:
            elf_file.seek(offset)
            rest = elf_file.read()
            elf_file.seek(offset)
            elf_file.write(data + rest)

    def overwrite_at(self, offset, data):
        """
        Insert data at given position.

        The data at the given position is overwritten.

        Args:
            offset (int): file offset to write data at
            data (bytes): the data to write
        """
        with open(self.__path, "r+b") as elf_file:
            elf_file.seek(offset)
            elf_file.write(data)

    @property
    def size(self):
        """Size of ELF file."""
        return os.path.getsize(self.__path)

    def read_at(self, offset, length):
        """
        Read raw data from file.

        offset (int): offet into the file
        length (int): length of the data block to read
        """
        with open(self.__path, "rb") as elf_file:
            elf_file.seek(offset)
            data = elf_file.read(length)

        return bytearray(data)


class EIdent:
    """Represents an e_ident entry in the ELF file header."""

    def __init__(self, path):
        self._path = path

    def __getitem__(self, index):
        return elf_handler.read_elf_header_e_ident(self._path)[index]

    def __setitem__(self, index, value):
        e_ident = elf_handler.read_elf_header_e_ident(self._path)
        e_ident[index] = value
        elf_handler.write_elf_header_e_ident(self._path, e_ident)

    def __len__(self):
        return EI_NIDENT

    def __iter__(self):
        for byte in self[:EI_NIDENT]:
            yield byte


class ELFStructure(ABC):
    """An abstract header."""

    def __init__(self, path):
        self._path = path

    def __getattr__(self, name):
        if name in self._members:
            return self._read(name)

        msg = "'{}' has no attribute '{}'"
        raise AttributeError(msg.format(type(self).__name__, name))

    def __setattr__(self, name, value):
        if name in self._members:
            self._write(name, value)

        object.__setattr__(self, name, value)

    @abstractmethod
    def _read(self, name):
        raise NotImplementedError()

    @abstractmethod
    def _write(self, name, value):
        raise NotImplementedError()

    @property
    @abstractmethod
    def _members(self):
        raise NotImplementedError()


class ELFHeader(ELFStructure):
    """An ELF file header"""

    @property
    def e_ident(self):
        """e_ident member of ELF program header."""
        return EIdent(self._path)

    def _read(self, name):
        return elf_handler.read_elf_header(self._path, name)

    def _write(self, name, value):
        elf_handler.write_elf_header(self._path, name, value)

    @property
    def _members(self):
        return E_HEADER_MEMBERS


class SectionHeader(ELFStructure):
    """An ELF section header"""

    def __init__(self, path, index):
        super().__init__(path)
        self._index = index

    def _read(self, name):
        return elf_handler.read_section_header(self._path, name, self._index)

    def _write(self, name, value):
        elf_handler.write_section_header(self._path, name, self._index, value)

    @property
    def _members(self):
        return S_HEADER_MEMBERS


class ProgramHeader(ELFStructure):
    """An ELF program header"""

    def __init__(self, path, index):
        super().__init__(path)
        self._index = index

    def _read(self, name):
        return elf_handler.read_program_header(self._path, name, self._index)

    def _write(self, name, value):
        elf_handler.write_program_header(self._path, name, self._index, value)

    @property
    def _members(self):
        return P_HEADER_MEMBERS


class Symbol(ELFStructure):
    """An ELF symbol"""
    def __init__(self, path, sindex, symnr):
        super().__init__(path)
        self._sindex = sindex
        self._symnr = symnr

    def _read(self, name):
        return elf_handler.read_elf_symbol(self._path, name, self._sindex,
                                           self._symnr)

    def _write(self, name, value):
        elf_handler.write_elf_symbol(self._path, name, self._sindex,
                                     self._symnr, value)

    @property
    def _members(self):
        return SYMBOL_MEMBERS

    def __str__(self):
        return read_strtab(self._path, self.st_name)


class Section:
    """A section in an ELF file."""
    def __init__(self, path, index):
        self._path = path
        self._index = index
        self._header = SectionHeader(path, index)

    @property
    def header(self):
        """Section header of this section."""
        return self._header

    @property
    def symbols(self):
        """
        Get symbols in this section if it holds any.

        Raises:
            IOError if section is not of type SHT_SYMTAB
        """
        if self._header.sh_type not in [SHT_SYMTAB, SHT_DYNSYM]:
            raise IOError("This section does not have type SHT_SYMTAB")

        syms = []
        for i, _ in enumerate(range(0, self.header.sh_size,
                                    self.header.sh_entsize)):
            syms.append(Symbol(self._path, self._index, i))

        return syms

    def raw_bytes(self):
        """Get raw data from sections."""
        with open(self._path, "rb") as elf_file:
            elf_file.seek(self._header.sh_offset)
            data = elf_file.read(self._header.sh_size)

        return data

    def __str__(self):
        return read_shstrtab(self._path, self._header.sh_name)


class Segment:
    """A segment in an ELF file."""
    def __init__(self, path, index):
        self._path = path
        self._index = index
        self._header = ProgramHeader(path, index)

    @property
    def header(self):
        """Segment header of this segment."""
        return self._header

    @property
    def dynamic_entries(self):
        """Dynamic (struct) entries (if there are any)"""
        raise NotImplementedError()

    def raw_bytes(self):
        """Get raw data from segment."""
        with open(self._path, "rb") as elf_file:
            elf_file.seek(self._header.p_offset)
            data = elf_file.read(self._header.p_filesz)

        return data


def read_shstrtab(path, str_offset):
    """
    Args:
        path (str): path to ELF file
        str_offset (int): offset into the string table

    Returns:
        String from .shstrtab section at given offset
    """
    shstr_index = elf_handler.read_elf_header(path, "e_shstrndx")
    shstr_offset = elf_handler.read_section_header(path, "sh_offset",
                                                   shstr_index)

    return read_stringtable(path, shstr_offset, str_offset)


def read_strtab(path, str_offset):
    """
    Args:
        path (str): path to ELF file
        str_offset (int): offset into the string table

    Returns:
        String from .strtab section at given offset
    """

    elf_file = ELFFile(path)
    for section in elf_file.sections:
        if str(section) == ".strtab":
            strtab_offset = section.header.sh_offset
            return read_stringtable(path, strtab_offset, str_offset)

    raise IOError("ELF file does not have a section named .strtab")


def read_stringtable(path, table_offset, str_offset):
    """
    Read string from a stringtable at given offset in ELF file.

    Args:
        path (str): path to ELF file
        table_offset (int): offset of string table in file
        str_index (int): offset into the string table

    Returns:
        String at the given offset.
    """

    with open(path, "br") as elf_file:
        elf_file.seek(table_offset + str_offset)

        string = b""
        name_byte = elf_file.read(1)
        while name_byte != b"\x00":
            string += name_byte
            name_byte = elf_file.read(1)

        return string.decode()
