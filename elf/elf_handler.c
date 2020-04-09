/*TODO
 * - Handle relocs
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>

typedef enum {
    READONLY,
    READWRITE
} access_mode;

uint8_t*
map_file(int *const fd, const char *path, const access_mode MODE) {
    uint8_t *mmf;
    struct stat st;
    int OPENMODE, MAP_MODE;

    switch (MODE) {
        case READONLY:
            OPENMODE = O_RDONLY;
            MAP_MODE = PROT_READ;
            break;
        case READWRITE:
            OPENMODE = O_RDWR;
            MAP_MODE = PROT_READ | PROT_WRITE;
            break;
        default:
            return NULL;
    }

    if ((*fd = open(path, OPENMODE)) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    }
    if ((fstat(*fd, &st)) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto read_fail;
    }

    mmf = mmap(NULL, st.st_size, MAP_MODE, MAP_SHARED, *fd, 0);
    if (mmf == MAP_FAILED) goto read_fail;

    return mmf;

read_fail:
    close(*fd);
fail:
    return NULL;
}

static PyObject*
read_elf_header_e_ident(PyObject* self, PyObject *args)
{
    Elf64_Ehdr *hdr;
    char *path;
    int fd;
    access_mode mode = READONLY;

    if (!PyArg_ParseTuple(args, "s", &path)) goto fail;
    if ((hdr = (Elf64_Ehdr*) map_file(&fd, path, mode)) == NULL) goto fail;

    return PyByteArray_FromStringAndSize((char *) hdr->e_ident, EI_NIDENT);

fail:
    return NULL;
}

static PyObject*
write_elf_header_e_ident(PyObject* self, PyObject *args)
{
    Elf64_Ehdr *hdr;
    const char *path;
    PyObject* e_ident_bytearray;
    int fd;
    access_mode mode = READWRITE;

    if (!PyArg_ParseTuple(args, "sY", &path, &e_ident_bytearray)) goto fail;

    if ((hdr = (Elf64_Ehdr*) map_file(&fd, path, mode)) == NULL) goto fail;

    memcpy(hdr->e_ident, PyByteArray_AsString(e_ident_bytearray), EI_NIDENT);

    return Py_None;

fail:
    return NULL;
}

static PyObject*
read_elf_header(PyObject* self, PyObject *args) {
    Elf64_Ehdr *hdr;
    const char *path, *member;	
    long ret;
    int fd;
    access_mode mode = READONLY;

    if (!PyArg_ParseTuple(args, "ss", &path, &member)) return NULL;

    if ((hdr = (Elf64_Ehdr*) map_file(&fd, path, mode)) == NULL) goto fail;

    if (strcmp("e_type", member) == 0) {
        ret = hdr->e_type;
    } else if (strcmp("e_machine", member) == 0) {
        ret = hdr->e_machine;
    } else if (strcmp("e_version", member) == 0) {
        ret = hdr->e_version;
    } else if (strcmp("e_entry", member) == 0) {
        ret = hdr->e_entry;
    } else if (strcmp("e_phoff", member) == 0) {
        ret = hdr->e_phoff;
    } else if (strcmp("e_shoff", member) == 0) {
        ret = hdr->e_shoff;
    } else if (strcmp("e_flags", member) == 0) {
        ret = hdr->e_flags;
    } else if (strcmp("e_ehsize", member) == 0) {
        ret = hdr->e_ehsize;
    } else if (strcmp("e_phentsize", member) == 0) {
        ret = hdr->e_phentsize;
    } else if (strcmp("e_phnum", member) == 0) {
        ret = hdr->e_phnum;
    } else if (strcmp("e_shentsize", member) == 0) {
        ret = hdr->e_shentsize;
    } else if (strcmp("e_shnum", member) == 0) {
        ret = hdr->e_shnum;
    } else if (strcmp("e_shstrndx", member) == 0) {
        ret = hdr->e_shstrndx;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF header has no such member");
        goto parse_fail;
    }

    close(fd);

    return PyLong_FromLong(ret);

parse_fail:
    close(fd);
fail:
    return NULL;
}

static PyObject*
write_elf_header(PyObject* self, PyObject *args) {
    const char *path, *member;	
    const long data;
    Elf64_Ehdr *hdr;
    int fd;
    access_mode mode = READWRITE;

    if (!PyArg_ParseTuple(args, "ssl", &path, &member, &data)) return NULL;

    if ((hdr = (Elf64_Ehdr*) map_file(&fd, path, mode)) == NULL) goto fail;

    if (strcmp("e_type", member) == 0) {
        hdr->e_type = (uint16_t) data;
    } else if (strcmp("e_machine", member) == 0) {
        hdr->e_machine = (uint16_t) data;
    } else if (strcmp("e_version", member) == 0) {
        hdr->e_version = (uint16_t) data;
    } else if (strcmp("e_entry", member) == 0) {
        hdr->e_entry = (Elf64_Addr) data;
    } else if (strcmp("e_phoff", member) == 0) {
        hdr->e_phoff = (Elf64_Off) data;
    } else if (strcmp("e_shoff", member) == 0) {
        hdr->e_shoff = (Elf64_Off) data;
    } else if (strcmp("e_flags", member) == 0) {
        hdr->e_flags = (uint32_t) data;
    } else if (strcmp("e_ehsize", member) == 0) {
        hdr->e_ehsize = (uint16_t) data;
    } else if (strcmp("e_phentsize", member) == 0) {
        hdr->e_phentsize = (uint16_t) data;
    } else if (strcmp("e_phnum", member) == 0) {
        hdr->e_phnum = (uint16_t) data;
    } else if (strcmp("e_shentsize", member) == 0) {
        hdr->e_shentsize = (uint16_t) data;
    } else if (strcmp("e_shnum", member) == 0) {
        hdr->e_shnum = (uint16_t) data;
    } else if (strcmp("e_shstrndx", member) == 0) {
        hdr->e_shstrndx = (uint16_t) data;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF header has no such member");
        goto parse_fail;
    }

    close(fd);

    return Py_None;

parse_fail:
    close(fd);
fail:
    return NULL;

}

static PyObject*
read_section_header(PyObject* self, PyObject* args)
{
    long res;
    Elf64_Shdr* shdr;
    Elf64_Ehdr* hdr;
    uint8_t *mmf;
    char* path, * member;
    int index, fd;
    access_mode mode = READONLY;

    if (!PyArg_ParseTuple(args, "ssi", &path, &member, &index)) {
        return NULL;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    shdr = (Elf64_Shdr*) &mmf[hdr->e_shoff + index * hdr->e_shentsize];

    if (strcmp("sh_name", member) == 0) {
        res = shdr->sh_name;
    } else if (strcmp("sh_type", member) == 0) {
        res = shdr->sh_type;
    } else if (strcmp("sh_flags", member) == 0) {
        res = shdr->sh_flags;
    } else if (strcmp("sh_addr", member) == 0) {
        res = shdr->sh_addr;
    } else if (strcmp("sh_offset", member) == 0) {
        res = shdr->sh_offset;
    } else if (strcmp("sh_size", member) == 0) {
        res = shdr->sh_size;
    } else if (strcmp("sh_link", member) == 0) {
        res = shdr->sh_link;
    } else if (strcmp("sh_info", member) == 0) {
        res = shdr->sh_info;
    } else if (strcmp("sh_addralign", member) == 0) {
        res = shdr->sh_addralign;
    } else if (strcmp("sh_entsize", member) == 0) {
        res = shdr->sh_entsize;
    } else {
        PyErr_SetString(PyExc_AttributeError, "Section header has no such member");
        goto parse_fail;
    }

    close(fd);

    return PyLong_FromLong(res);

parse_fail:
    close(fd);
fail:
    return NULL;
}

static PyObject*
write_section_header(PyObject *self, PyObject *args)
{
    Elf64_Shdr *shdr;
    Elf64_Ehdr *hdr;
    uint8_t *mmf;
    char *path, *member;
    int index, fd;
    long data;
    access_mode mode = READWRITE;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
        goto fail;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    shdr = (Elf64_Shdr*) &mmf[hdr->e_shoff + index * hdr->e_shentsize];

    if (strcmp("sh_name", member) == 0) {
        shdr->sh_name = (uint32_t) data;
    } else if (strcmp("sh_type", member) == 0) {
        shdr->sh_type = (uint32_t) data;
    } else if (strcmp("sh_flags", member) == 0) {
        shdr->sh_flags = (uint64_t) data;
    } else if (strcmp("sh_addr", member) == 0) {
        shdr->sh_addr = (Elf64_Addr) data;
    } else if (strcmp("sh_offset", member) == 0) {
        shdr->sh_offset = (Elf64_Off) data;
    } else if (strcmp("sh_size", member) == 0) {
        shdr->sh_size = (uint64_t) data;
    } else if (strcmp("sh_link", member) == 0) {
        shdr->sh_link = (uint32_t) data;
    } else if (strcmp("sh_info", member) == 0) {
        shdr->sh_info = (uint32_t) data;
    } else if (strcmp("sh_addralign", member) == 0) {
        shdr->sh_addralign = (uint64_t) data;
    } else if (strcmp("sh_entsize", member) == 0) {
        shdr->sh_entsize = (uint64_t) data;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF section header does not have a member with this name");
        goto parse_fail;
    }

    close(fd);

    return Py_None;

parse_fail:
    close(fd);
fail:
    return NULL;
}

static PyObject*
read_program_header(PyObject* self, PyObject* args)
{
    long res;
    Elf64_Phdr *phdr;
    Elf64_Ehdr *hdr;
    uint8_t *mmf;
    char *path, *member;
    int index, fd;
    access_mode mode = READONLY;

    if (!PyArg_ParseTuple(args, "ssi", &path, &member, &index)) {
        return NULL;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    phdr = (Elf64_Phdr*) &mmf[hdr->e_phoff + index * hdr->e_phentsize];

    if (strcmp("p_type", member) == 0) {
        res = phdr->p_type;
    } else if (strcmp("p_flags", member) == 0) {
        res = phdr->p_flags;
    } else if (strcmp("p_offset", member) == 0) {
        res = phdr->p_offset;
    } else if (strcmp("p_vaddr", member) == 0) {
        res = phdr->p_vaddr;
    } else if (strcmp("p_paddr", member) == 0) {
        res = phdr->p_paddr;
    } else if (strcmp("p_filesz", member) == 0) {
        res = phdr->p_filesz;
    } else if (strcmp("p_memsz", member) == 0) {
        res = phdr->p_memsz;
    } else if (strcmp("sh_align", member) == 0) {
        res = phdr->p_align;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF program header does not have a member with this name");
        goto read_fail;
    }

    close(fd);

    return PyLong_FromLong(res);

read_fail:
    close(fd);
fail:
    return NULL;
}

static PyObject*
write_program_header(PyObject* self, PyObject* args)
{
    Elf64_Phdr *phdr;
    Elf64_Ehdr *hdr; 
    uint8_t *mmf;
    char* path, *member;
    int index, fd;
    long data;
    access_mode mode = READWRITE;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
        goto fail;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    phdr = (Elf64_Phdr*) &mmf[hdr->e_phoff + index * hdr->e_phentsize];

    if (strcmp("p_type", member) == 0) {
        phdr->p_type = (uint32_t) data;
    } else if (strcmp("p_flags", member) == 0) {
        phdr->p_flags = (uint32_t) data;
    } else if (strcmp("p_offset", member) == 0) {
        phdr->p_offset = (Elf64_Off) data;
    } else if (strcmp("p_vaddr", member) == 0) {
        phdr->p_vaddr = (Elf64_Addr) data;
    } else if (strcmp("p_paddr", member) == 0) {
        phdr->p_paddr = (Elf64_Addr) data;
    } else if (strcmp("p_filesz", member) == 0) {
        phdr->p_filesz = (uint64_t) data;
    } else if (strcmp("p_memsz", member) == 0) {
        phdr->p_memsz = (uint64_t) data;
    } else if (strcmp("p_align", member) == 0) {
        phdr->p_align = (uint64_t) data;;
    } else {
        goto parse_fail;
    }

    close(fd);
    return Py_None;

parse_fail:
    close(fd);
fail:
    return NULL;
}

PyObject*
read_elf_symbol(PyObject *self, PyObject *args)
{
    long res;
    Elf64_Sym *sym;
    Elf64_Ehdr *hdr;
    Elf64_Shdr *shdr;
    uint8_t *mmf;
    char *path, *member;
    int index, symnr, fd;
    access_mode mode = READONLY;

    if (!PyArg_ParseTuple(args, "ssii", &path, &member, &index, &symnr)) {
        return NULL;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    shdr = (Elf64_Shdr*) &mmf[hdr->e_shoff + index * hdr->e_shentsize];

    if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM) {
        PyErr_SetString(PyExc_OSError, "The given section does not contain symbols according to its type");
        goto read_fail;
    }

    sym = (Elf64_Sym*) &mmf[shdr->sh_offset + shdr->sh_entsize * symnr];

    if (strcmp("st_name", member) == 0) {
        res = sym->st_name;
    } else if (strcmp("st_info", member) == 0) {
        res = sym->st_info;
    } else if (strcmp("st_other", member) == 0) {
        res = sym->st_other;
    } else if (strcmp("st_shndx", member) == 0) {
        res = sym->st_shndx;
    } else if (strcmp("st_value", member) == 0) {
        res = sym->st_value;
    } else if (strcmp("st_size", member) == 0) {
        res = sym->st_size;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF program header does not have a member with this name");
        goto read_fail;
    }

    close(fd);

    return PyLong_FromLong(res);

read_fail:
    close(fd);
fail:
    return NULL;
}

PyObject*
write_elf_symbol(PyObject *self, PyObject *args)
{
    long new_val;
    Elf64_Sym *sym;
    Elf64_Ehdr *hdr;
    Elf64_Shdr *shdr;
    uint8_t *mmf;
    char *path, *member;
    int index, symnr, fd;
    access_mode mode = READWRITE;

    if (!PyArg_ParseTuple(args, "ssiil", &path, &member, &index, &symnr, &new_val)) {
        goto fail;
    }

    if ((mmf = map_file(&fd, path, mode)) == NULL) goto fail;
    hdr = (Elf64_Ehdr*) mmf;
    shdr = (Elf64_Shdr*) &mmf[hdr->e_shoff + index * hdr->e_shentsize];

    if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_SYMTAB) {
        PyErr_SetString(PyExc_OSError, "The given section does not contain symbols according to its type");
        goto read_fail;
    }

    sym = (Elf64_Sym*) &mmf[shdr->sh_offset + shdr->sh_entsize * symnr];

    if (strcmp("st_name", member) == 0) {
        sym->st_name = (uint32_t) new_val;
    } else if (strcmp("st_info", member) == 0) {
        sym->st_info = (unsigned char) new_val;
    } else if (strcmp("st_other", member) == 0) {
        sym->st_other = (unsigned char) new_val;
    } else if (strcmp("st_shndx", member) == 0) {
        sym->st_shndx = (uint16_t) new_val;
    } else if (strcmp("st_value", member) == 0) {
        sym->st_value = (Elf64_Addr) new_val;
    } else if (strcmp("st_size", member) == 0) {
        sym->st_size = (uint64_t) new_val;
    } else {
        PyErr_SetString(PyExc_AttributeError, "ELF program header does not have a member with this name");
        goto read_fail;
    }

    close(fd);

    return Py_None;

read_fail:
    close(fd);
fail:
    return NULL;
}

static PyMethodDef ElfHandlerMethods[] = {
    {"read_elf_header_e_ident", read_elf_header_e_ident, 
     METH_VARARGS,
            "Args:\n"
            "    file_path (string): path to ELF file\n"},
    {"write_elf_header_e_ident", write_elf_header_e_ident, 
     METH_VARARGS,
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    new_e_ident (bytearray): new e_ident data"},
    {"read_elf_header", read_elf_header, 
     METH_VARARGS,
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Ehdr member to read\n"},
    {"write_elf_header", write_elf_header, 
     METH_VARARGS,
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Ehdr member to overwrite\n"
            "    data (int): data to write (will not write more than the size of the member\n"},
    {"read_section_header", read_section_header, 
     METH_VARARGS,
    "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Shdr member to read\n"
            "    index (int): index of section header in section header table\n"},
    {"write_section_header", write_section_header, 
     METH_VARARGS,
    "Args:\n"\
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Shdr member to overwrite\n"
            "    index (int): index of section header in section header table\n"
            "    data (int): data to write (will not write more than the size of the member\n"},
    {"read_program_header", read_program_header, 
     METH_VARARGS, 
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Phdr member to read\n"
            "    index (int): index of program header in program header table\n"},
    {"read_elf_symbol", read_elf_symbol, 
     METH_VARARGS,
    "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Shdr member to read\n"
            "    sindex (int): index of section which hodls the symbol\n"
            "    symnr (int): number of symbol in the symbol table\n"},
    {"write_elf_symbol", write_elf_symbol, 
     METH_VARARGS,
    "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Shdr member to write\n"
            "    sindex (int): index of section which holds the symbol\n"
            "    symnr (int): number of symbol in the symbol table\n"
            "    new_val (int): new value to write\n"},
    {"write_program_header", write_program_header, 
     METH_VARARGS, 
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Phdr member to overwrite\n"
            "    index (int): index of program header in program header table\n"
            "    data (int): data to write (will not write more than the size of the member\n"},
};

static struct PyModuleDef elf_handler = {
    PyModuleDef_HEAD_INIT,
    "elf_handler",  // name
    NULL,           // documentation
    -1,             // do not reserve space for state
    ElfHandlerMethods
};

PyMODINIT_FUNC
PyInit_elf_handler(void)
{
    return PyModule_Create(&elf_handler);
}
