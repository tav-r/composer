from distutils.core import setup, Extension

ELF_HANDLER = Extension('elf_handler',
                        extra_compile_args=['-Werror', '-Wpedantic'],
                        sources=['composer/src/elf_handler.c'])

PTRACE_WRAPPER = Extension('ptrace_wrapper',
                           extra_compile_args=['-Werror', '-Wpedantic'],
                           sources=['composer/src/ptrace_wrapper.c'])

setup(name='composer',
      version='0.1',
      description='A package to make the manipulation of ELF files easier',
      packages=['composer', 'composer.process', 'composer.elf'],
      ext_package='composer_extensions',
      ext_modules=[ELF_HANDLER, PTRACE_WRAPPER])
