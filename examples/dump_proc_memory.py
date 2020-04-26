from composer.process import *
from sys import argv, stdout, stderr, exit as sys_exit

def main():
    pid = int(argv[1])
    pm = ProcessMemory(pid)
    for chunk in pm:
        stdout.buffer.write(chunk.read())


if __name__ == "__main__":
    if len(argv) < 2:
        print("Usage: {} pid".format(argv[0]), file=stderr)
        sys_exit(1)
    main()

