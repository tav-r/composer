from distutils.core import setup, Extension

ELF_HANDLER = Extension('composer.extensions.elf_handler',
                        extra_compile_args=['-Werror', '-Wpedantic'],
                        sources=['composer/elf/elf_handler.c'])

PTRACE_WRAPPER = Extension('composer.extensions.ptrace_wrapper',
                           extra_compile_args=['-Werror', '-Wpedantic'],
                           sources=['composer/process/ptrace_wrapper.c'])

setup(name='composer',
      version='0.1',
      description='A package to make the manipulation of ELF files easier',
      packages=['composer', 'composer.elf', 'composer.process'],
      ext_modules=[ELF_HANDLER, PTRACE_WRAPPER])
