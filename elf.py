import elf_handler
from abc import ABC, abstractmethod

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
    def __init__(self, path):
        self.__path = path

    @property
    def header(self):
        return ELFHeader(self.__path)

    @property
    def section_headers(self):
        return [SectionHeader(self.__path, i)
                for i in range(self.header.e_shnum)]

    @property
    def program_headers(self):
        return [ProgramHeader(self.__path, i)
                for i in range(self.header.e_phnum)]


class Header(ABC):
    def __init__(self, path):
        self._path = path

    @abstractmethod
    def __getattr__(self, name):
        ...

    def __setattr__(self, name, value):
        ...


class ELFHeader(Header):
    def __getattr__(self, name):
        if name in E_HEADER_MEMBERS:
            return elf_handler.read_elf_header(self._path, name)

        msg = "'{}' has no attribute '{}'"
        raise AttributeError(msg.format(type(self).__name__, name))

    def __setattr__(self, name, value):
        if name in E_HEADER_MEMBERS:
            elf_handler.write_elf_header(self._path, name, value)

        object.__setattr__(self, name, value)


class SectionHeader(Header):
    def __init__(self, path, index):
        super().__init__(path)
        self._index = index

    def __getattr__(self, name):
        if name in S_HEADER_MEMBERS:
            return elf_handler.read_section_header(self._path, name, self._index)

        msg = "'{}' has no attribute '{}'"
        raise AttributeError(msg.format(type(self).__name__, name))

    def __setattr__(self, name, value):
        if name in S_HEADER_MEMBERS:
            elf_handler.write_section_header(self._path, name, self._index, value)

        object.__setattr__(self, name, value)


class ProgramHeader(Header):
    def __init__(self, path, index):
        super().__init__(path)
        self._index = index

    def __getattr__(self, name):
        if name in P_HEADER_MEMBERS:
            return elf_handler.read_program_header(self._path, name, self._index)

        msg = "'{}' has no attribute '{}'"
        raise AttributeError(msg.format(type(self).__name__, name))

    def __setattr__(self, name, value):
        if name in P_HEADER_MEMBERS:
            elf_handler.write_program_header(self._path, name, self._index, value)

        object.__setattr__(self, name, value)
