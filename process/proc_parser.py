"""
Parse data in /proc/$PID/
"""

import os


class ProcessMemory:
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

                print(line.split(" "), len(line.split(" ")))
                mem_chunks.append(line.split(" ", maxsplit=5))

        return mem_chunks

    def __iter__(self):
        for address, perms, offset, dev, inode, pathname in self.__get_chunks():
            yield {"address": (int(address.split("-")[0], base=16),
                               int(address.split("-")[1], base=16)),
                   "perms": perms,
                   "offset": int(offset, base=16),
                   "dev": dev,
                   "indoe": inode,
                   "pathname": pathname}


if __name__ == "__main__":
    from pprint import pprint
    from sys import argv
    for mem in ProcessMemory(argv[1]):
        pprint(mem)
