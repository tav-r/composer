/*TODO
 * - Check success on open, read and write
 * - Raise propper exceptions on fail
 * - Commenting/doc
 */


#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>


void*
read_n_at(const char *path, long at, size_t length) {
    FILE *elff;
    void *buf;
    size_t ret;

    if ((buf = malloc(length)) == NULL) goto fail;
    memset(buf, 0, length);

    if ((elff = fopen(path, "r")) == NULL) goto fail;
    if (fseek(elff, at, SEEK_SET) == -1) goto fail;
    if ((ret = fread(buf, 1, length, elff)) < length && !feof(elff)) goto fail;

    fclose(elff);

    return buf;

fail:
    fprintf(stderr, "error while reading file: %s\n", strerror(errno));
    return NULL;
    
}

Elf64_Ehdr*
get_ehdr_data(const char *path)
{
    Elf64_Ehdr *hdr;

    hdr = (Elf64_Ehdr*) read_n_at(path, 0, sizeof(Elf64_Ehdr));

    return hdr;
}

long
get_shdr_offset(char *path, int index) {
    long offset;

    Elf64_Ehdr* ehdr;
    ehdr = get_ehdr_data(path);
    offset = ehdr->e_shoff + ehdr->e_shentsize * index;
    free(ehdr);

    return offset;
}

/* Write to size bytes of data at offset in file. Returns bytes written or
 * -1 if fail.
 */
ssize_t
write_to_file(FILE *file, size_t offset, unsigned char *data, size_t size)
{
    ssize_t ret;

    // write given bytes to file
    if(fseek(file, offset, SEEK_SET) < 0) goto fail;
    if ((ret = fwrite(data, 1, size, file)) < 0) goto fail;
    return ret;

fail:
    fprintf(stderr, "could not write to file: %s", strerror(errno));
    return -1;
}

Elf64_Shdr*
get_shdr_data(char *path, int index) {
    Elf64_Shdr *shdr;
    long offset;

    offset = get_shdr_offset(path, index);

    // read shdr data from file
    shdr = (Elf64_Shdr*) read_n_at(path, offset, sizeof(Elf64_Shdr));

    return shdr;
}

long
get_phdr_offset(char *path, int index) {
    long offset;

    Elf64_Ehdr* ehdr;
    if ((ehdr = get_ehdr_data(path)) == NULL) goto fail;
    offset = ehdr->e_phoff + ehdr->e_phentsize * index;
    free(ehdr);

    return offset;

fail:
    fprintf(stderr, "could not get program header offset from file header: %s", strerror(errno));
    return -1;
}

Elf64_Phdr*
get_phdr_data(char *path, int index) {
    Elf64_Phdr* phdr;
    long offset;
	
    if ((offset = get_phdr_offset(path, index)) == -1) goto fail;

    // read shdr data from file
    phdr = read_n_at(path, offset, sizeof(Elf64_Phdr));
	
    return phdr;

fail:
    fprintf(stderr, "could not get program header data: %s", strerror(errno));
    return NULL;
}

static PyObject*
read_elf_header(PyObject* self, PyObject *args) {
    const char *path, *member;	
    Elf64_Ehdr *hdr;
    long ret;

    if (!PyArg_ParseTuple(args, "ss", &path, &member)) return NULL;
    if ((hdr = get_ehdr_data(path)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF file header");
        goto fail;
    }

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

    free(hdr);

    return PyLong_FromLong(ret);

parse_fail:
    free(hdr);
fail:
    return NULL;
}

static PyObject*
write_elf_header(PyObject* self, PyObject *args) {
    const char *path, *member;	
    const long data;
    FILE *elff;
    Elf64_Ehdr *hdr;

    if (!PyArg_ParseTuple(args, "ssl", &path, &member, &data)) return NULL;
    if ((hdr = get_ehdr_data(path)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF file header");
        goto fail;
    }

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

    if ((elff = fopen(path, "r+")) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not open file to write");
        goto read_fail;
    }

    fseek(elff, 0L, SEEK_SET);
    if ((fwrite(hdr, sizeof(Elf64_Ehdr), 1, elff)) < 0) {
        PyErr_SetString(PyExc_IOError, "Could not write to file");
        goto write_fail;
    }

    fclose(elff);

    free(hdr);

    return Py_None;

write_fail:
    fclose(elff);
parse_fail:
read_fail:
    free(hdr);
fail:
    return NULL;

}

static PyObject*
read_section_header(PyObject* self, PyObject* args)
{
    long res;
    Elf64_Shdr* shdr;
    char* path, * member;
    int index;

    if (!PyArg_ParseTuple(args, "ssi", &path, &member, &index)) {
        return NULL;
    }

    if ((shdr = get_shdr_data(path, index)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF file header");
        goto fail;
    }

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

    free(shdr);

    return PyLong_FromLong(res);

parse_fail:
    free(shdr);
fail:
    return NULL;
}

static PyObject*
insert_bytes(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *path;
    unsigned char *bytes, *filemem;
    size_t nbytes, offset, filesz;
    FILE *elff;
    int overwrite;

    static char *kwlist[] = {"", "", "", "overwrite", NULL};
    
    overwrite = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sly#p", kwlist,
                                     &path, &offset, &bytes, &nbytes,
                                     &overwrite)) {
            return NULL;
    }

    // open for reading and writing in binary mode, calculate filesize
    if((elff = fopen(path, "rb+")) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not open file");
        goto fail;
    }

    fseek(elff, 0L, SEEK_END);
    filesz = ftell(elff);

    if (offset > filesz) {
        PyErr_SetString(PyExc_IndexError, "Offset is bigger than filesize");
        goto pre_write_fail;
    }

    if (!overwrite) {
        // store part after insertion block
        filemem = malloc(filesz - offset);
        fseek(elff, offset, SEEK_SET);
        if (fread(filemem, 1, filesz - offset, elff) < filesz - offset) {
            PyErr_SetString(PyExc_IOError, "Could not read data");
            goto pre_write_fail;
        }

        if (write_to_file(elff, offset, bytes, nbytes) == -1) { 
            PyErr_SetString(PyExc_IOError, "Could not insert data");
            goto copy_fail;
        }

        // write stored data after inserted block
        fseek(elff, offset + nbytes, SEEK_SET);
        if (fwrite(filemem, 1, filesz - offset, elff) < filesz - offset) {
            PyErr_SetString(PyExc_IOError, "Could not move data");
            goto copy_fail;
        }

        free(filemem);
    } else {
        if (write_to_file(elff, offset, bytes, nbytes) < 0) {
            PyErr_SetString(PyExc_IOError, "Could not overwrite data");
            goto write_fail;
        }
    }

    fclose(elff);

    return Py_None;

copy_fail:
    free(filemem);
write_fail:
pre_write_fail:
    fclose(elff);
fail:
    return NULL;

}

static PyObject*
write_section_header(PyObject *self, PyObject *args)
{
    Elf64_Shdr* shdr;
    char* path, * member;
    int index, elf_fd;
    long offset, data;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
        return NULL;
    }

    if ((shdr = get_shdr_data(path, index)) == NULL) {
        goto fail;
    }

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
        return NULL;
    }

    offset = get_shdr_offset(path, index);
    elf_fd = open(path, O_WRONLY);
    lseek(elf_fd, offset, SEEK_SET);
    write(elf_fd, shdr, sizeof(Elf64_Shdr));
    close(elf_fd);

    free(shdr);

    return Py_None;

fail:
    return NULL;
}

static PyObject*
read_program_header(PyObject* self, PyObject* args)
{
    long res;
    Elf64_Phdr* phdr;
    char* path, * member;
    int index;

    if (!PyArg_ParseTuple(args, "ssi", &path, &member, &index)) {
        return NULL;
    }

    phdr = get_phdr_data(path, index);

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
        return NULL;
    }

    free(phdr);

    return PyLong_FromLong(res);
}


static PyObject*
write_program_header(PyObject* self, PyObject* args)
{
    Elf64_Phdr* phdr;
    char* path, * member;
    int index, elf_fd;
    long offset, data;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
            return NULL;
    }

    phdr = get_phdr_data(path, index);

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
            return NULL;
    }

    offset = get_phdr_offset(path, index);
    elf_fd = open(path, O_WRONLY);
    lseek(elf_fd, offset, SEEK_SET);
    write(elf_fd, phdr, sizeof(Elf64_Phdr));
    close(elf_fd);

    free(phdr);

    return Py_None;
}

static PyMethodDef ElfHandlerMethods[] = {
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
    {"write_program_header", write_program_header, 
     METH_VARARGS, 
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    member_name (string): Name of Elf64_Phdr member to overwrite\n"
            "    index (int): index of program header in program header table\n"
            "    data (int): data to write (will not write more than the size of the member\n"},
    {"insert_bytes", (PyCFunction) insert_bytes, 
     METH_VARARGS | METH_KEYWORDS,
            "Args:\n"
            "    file_path (string): path to ELF file\n"
            "    offset (int): offset to write at\n"
            "    data (bytes): bytes to insert into the file\n"
            "Keyword Args:\n"
            "    overwrite=False (bool): if True, the data at the given offset is overwritten instead of moved behind the inserted data"},
 	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef elf_handler = {
    PyModuleDef_HEAD_INIT,
    "elf_handler",  	// name
    NULL, 				// documentation
    -1,       			// do not reserve space for state
    ElfHandlerMethods
};

PyMODINIT_FUNC
PyInit_elf_handler(void)
{
    return PyModule_Create(&elf_handler);
}
