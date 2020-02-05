"""
Should provide the tools to modify ELF executables in a comfortable
way on a low level.
"""

from abc import ABC, abstractmethod
import os
import elf_handler

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


class ELFFile:
    """
    A ELF executable that can be read and modified.

    Changes to this object will be written directly to the file so
    be careful!
    """
    def __init__(self, path):
        self.__path = path

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
        elf_handler.insert_bytes(self.__path, offset, data, overwrite=False)

    def overwrite_at(self, offset, data):
        """
        Insert data at given position.

        The data at the given position is overwritten.

        Args:
            offset (int): file offset to write data at
            data (bytes): the data to write
        """
        elf_handler.insert_bytes(self.__path, offset, data, overwrite=True)

    @property
    def size(self):
        """Size of ELF file."""
        return os.path.getsize(self.__path)

class Header(ABC):
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


class ELFHeader(Header):
    """An ELF file header"""

    def _read(self, name):
        return elf_handler.read_elf_header(self._path, name)

    def _write(self, name, value):
        elf_handler.write_elf_header(self._path, name, value)

    @property
    def _members(self):
        return E_HEADER_MEMBERS


class SectionHeader(Header):
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

class ProgramHeader(Header):
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
