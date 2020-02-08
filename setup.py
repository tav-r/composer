from distutils.core import setup, Extension

ELF_HANDLER = Extension('elf_handler',
              extra_compile_args = ['-Werror', '-Wpedantic'],
              sources = ['elf_handler.c'],
              include_dirs=["./"])

setup (name = 'elf_handler',
       version = '0.1',
       description = 'A package to make the manipulation of ELF files easier',
       ext_modules = [ELF_HANDLER])
