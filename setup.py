from distutils.core import setup, Extension

ELF_HANDLER = Extension('elf_handler',
                        extra_compile_args=['-Werror', '-Wpedantic'],
                        sources=['elf/elf_handler.c'],
                        include_dirs=["elf"])

setup(name='elf_handler',
      version='0.1',
      description='A package to make the manipulation of ELF files easier',
      ext_modules=[ELF_HANDLER])
