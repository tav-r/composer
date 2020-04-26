from sys import argv, stderr, exit as sys_exit
from composer.process import *


def main():
    pid = int(argv[1])
    searchstring = argv[2].encode()

    proc_mem = ProcessMemory(pid)
    for chunk in proc_mem:
        try:
            contents = chunk.read()
            if searchstring in contents:
                offset = contents.find(searchstring)
                print("Found in 0x{:x}-0x{:x} at offset 0x{:x}"
                      .format(chunk.start, chunk.end, offset))
                rest = contents
                while b"httpOnly" in rest:
                    off = rest.find(b"httpOnly")
                    print(rest[off-600:off+1000])
                    print(off)
                    rest = rest[off + len(b"httpOnly"):]

        except (OSError, ValueError):
            print("Could not read 0x{:x}-0x{:x}"
                  .format(chunk.start, chunk.end),
                  file=stderr)


if __name__ == "__main__":
    if len(argv) < 3:
        print("Usage: {} pid searchstring".format(argv[0]))
        sys_exit(1)

    main()
