from distutils.core import setup, Extension

ELF_HANDLER = Extension('elf_handler',
              extra_compile_args = ['-Werror', '-Wpedantic'],
              sources = ['elf_handler.c'],
              include_dirs=["./"])

setup (name = 'elf_handler',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [ELF_HANDLER])
