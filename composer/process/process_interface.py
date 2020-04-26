"""
Parse data in /proc/$PID/
"""

import os


class ProcMaps:
    """
    Description of process memory (parses /proc/$PID/maps)
    """

    def __init__(self, pid):
        self.__pid = pid

    def __get_chunks(self):
        if not os.path.isdir("/proc/{}".format(self.__pid)):
            raise FileNotFoundError()

        mem_chunks = []
        with open("/proc/{}/maps".format(self.__pid), "r") as maps:
            for line in maps.readlines():
                while "  " in line:
                    line = line.replace("  ", " ")

                mem_chunks.append(line.split(" ", maxsplit=5))

        return mem_chunks

    def __iter__(self):
        for address, perms, offset, dev, inode, pathname in\
                self.__get_chunks():
            yield {"address": (int(address.split("-")[0], base=16),
                               int(address.split("-")[1], base=16)),
                   "perms": perms,
                   "offset": int(offset, base=16),
                   "dev": dev,
                   "inode": inode,
                   "pathname": pathname}

    def __getitem__(self, index):
        return list(self)[index]

    @property
    def pid(self):
        """PID getter"""
        return self.__pid


class ProcessMemory:
    """Abstraction to interact with process memory."""
    def __init__(self, pid):
        self.__pid = pid
        self.__maps = ProcMaps(pid)

    @property
    def pid(self):
        """PID getter"""
        return self.__pid

    def __getitem__(self, index):
        return MemoryChunk(self.__pid, self.__maps[index])

    def __len__(self):
        return len(list(self.__maps))


class MemoryChunk:
    """Abstraction for a junk of memory a process allocated."""
    def __init__(self, pid, chunk_map):
        self.__pid = pid
        self.__map = chunk_map

    def read(self, length=-1):
        """
        Read memory contents from this chunk.

        length (int): number of bytes to read
        """
        with open("/proc/{}/mem".format(self.__pid), "rb") as memfile:
            memfile.seek(self.start)

            if length >= 0:
                return memfile.read(length)
            return memfile.read(self.end - self.start)

    def write(self, offset, data):
        """Write data at given offset"""
        assert offset + len(data) < self.end - self.start
        assert offset >= 0

        with open("/proc/{}/mem".format(self.__pid), "r+b") as memfile:
            memfile.seek(self.start + offset)

            return memfile.write(data)

    @property
    def start(self):
        """Start address of memory chunk"""
        return self.__map["address"][0]

    @property
    def end(self):
        """End address of memory chunk"""
        return self.__map["address"][1]

    @property
    def perms(self):
        """Memory permissions"""
        return self.__map["perms"]

    @property
    def offset(self):
        """Offset into the file"""
        return self.__map["offset"]

    @property
    def dev(self):
        """Major:minor of the memory device"""
        return self.__map["dev"]

    @property
    def inode(self):
        """Inode of memory device"""
        return self.__map["inode"]

    @property
    def pathname(self):
        """File backing the mapping"""
        return self.__map["pathname"]
