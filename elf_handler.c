/*TODO
 * - Handle symbols, string tables, relocs and so on
 */


#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>


/**
 * read 'length' bytes from file at 'path' at 'offset'. Returns NULL if an error occured.
 */
void*
read_n_at(const char *path, long offset, size_t length) {
    FILE *elff;
    void *buf;
    size_t ret;

    if ((buf = malloc(length)) == NULL) goto fail;
    memset(buf, 0, length);

    if ((elff = fopen(path, "r")) == NULL) goto fail;
    if (fseek(elff, offset, SEEK_SET) == -1) goto fail;
    if ((ret = fread(buf, 1, length, elff)) < length && !feof(elff)) goto fail;

    fclose(elff);

    return buf;

fail:
    PyErr_SetString(PyExc_IOError, strerror(errno));
    fprintf(stderr, "error while reading file: %s\n", strerror(errno));
    return NULL;
}

/**
 * Write 'length' bytes of 'data' at 'offset' in file at 'path'. Returns bytes written or
 * -1 if an error occured.
 */
ssize_t
write_to_file(const char *path, size_t offset, void *data, ssize_t length)
{
    FILE *file;
    ssize_t written;

    if ((file = fopen(path, "rb+")) == NULL) {
        fprintf(stderr, "%s\n", strerror(errno));
        PyErr_SetString(PyExc_IOError, "Could not open file for reading and writing");
        goto fail;
    }

    if (fseek(file, offset, SEEK_SET) == -1) {
        fprintf(stderr, "%s\n", strerror(errno));
        PyErr_SetString(PyExc_IOError, "Could set position in file");
        goto write_fail;
    }

    if ((written = fwrite(data, 1, length, file)) < length) {
        PyErr_SetString(PyExc_IOError, "Could not write section header data");
        goto write_fail;
    }

    fclose(file);
    return written;

write_fail:
    fclose(file);
fail:
    return -1;
}

/**
 * ELF file header of file at 'path'
 */
Elf64_Ehdr*
read_ehdr_data(const char *path)
{
    Elf64_Ehdr *hdr;

    hdr = (Elf64_Ehdr*) read_n_at(path, 0, sizeof(Elf64_Ehdr));

    return hdr;
}

/**
 * Section header offset of section header number 'index' for file at 'path'
 */
long
get_shdr_offset(char *path, int index) {
    long offset;

    Elf64_Ehdr* ehdr;
    ehdr = read_ehdr_data(path);
    offset = ehdr->e_shoff + ehdr->e_shentsize * index;
    free(ehdr);

    return offset;
}

/**
 * Section header of section header number 'index' for file at 'path'
 */
Elf64_Shdr*
read_shdr_data(char *path, int index) {
    Elf64_Shdr *shdr;
    long offset;

    offset = get_shdr_offset(path, index);

    // read shdr data from file
    shdr = (Elf64_Shdr*) read_n_at(path, offset, sizeof(Elf64_Shdr));

    return shdr;
}

/**
 * Section header of section header number 'index' for file at 'path'. In contrast to
 * 'read_shdr_data, this function checks for illegal 'index'.
 */
Elf64_Shdr*
checked_read_shdr_data(char *path, int index)
{
    Elf64_Shdr *shdr;
    Elf64_Ehdr *ehdr;

    if ((ehdr = read_ehdr_data(path)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF file header to check section header index");
        goto fail;
    }

    if (ehdr->e_shnum <= index || index < 0) {
        PyErr_SetString(PyExc_IndexError, "This ELF file does not have a sction header with this index");
        goto fail;
    }

    if ((shdr = read_shdr_data(path, index)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF section header");
        goto fail;
    }

    return shdr;

fail:
    return NULL;
}

/**
 * Program header offset of section header number 'index' for file at 'path'.
 */
long
get_phdr_offset(char *path, int index) {
    long offset;

    Elf64_Ehdr* ehdr;
    if ((ehdr = read_ehdr_data(path)) == NULL) goto fail;
    offset = ehdr->e_phoff + ehdr->e_phentsize * index;
    free(ehdr);

    return offset;

fail:
    return -1;
}

/**
 * Program header of section header number 'index' for file at 'path'.
 */
Elf64_Phdr*
read_phdr_data(char *path, int index) {
    Elf64_Phdr* phdr;
    long offset;
	
    if ((offset = get_phdr_offset(path, index)) == -1) goto fail;

    // read shdr data from file
    phdr = read_n_at(path, offset, sizeof(Elf64_Phdr));
	
    return phdr;
fail:
    return NULL;
}

/**
 * Program header of program header number 'index' for file at 'path'. In contrast to
 * 'read_phdr_data, this function checks for illegal 'index'.
 */
Elf64_Phdr*
checked_read_phdr_data(char *path, int index)
{
    Elf64_Phdr *phdr;
    Elf64_Ehdr *ehdr;

    if ((ehdr = read_ehdr_data(path)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF file header to check program header index");
        goto fail;
    }

    if (ehdr->e_phnum <= index || index < 0) {
        PyErr_SetString(PyExc_IndexError, "This ELF file does not have a program header with this index");
        goto fail;
    }

    if ((phdr = read_phdr_data(path, index)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF program header");
        goto fail;
    }

    return phdr;

fail:
    return NULL;
}

static PyObject*
read_elf_header(PyObject* self, PyObject *args) {
    const char *path, *member;	
    Elf64_Ehdr *hdr;
    long ret;

    if (!PyArg_ParseTuple(args, "ss", &path, &member)) return NULL;
    if ((hdr = read_ehdr_data(path)) == NULL) {
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
    Elf64_Ehdr *hdr;

    if (!PyArg_ParseTuple(args, "ssl", &path, &member, &data)) return NULL;
    if ((hdr = read_ehdr_data(path)) == NULL) {
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

    if (write_to_file(path, 0, hdr, sizeof(Elf64_Ehdr)) == -1) {
        goto parse_fail;
    };

    free(hdr);

    return Py_None;

parse_fail:
    free(hdr);
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
            goto fail;
    }

    // check that offset is not bigger than filesize
    if((elff = fopen(path, "rb")) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not open file to read");
        goto fail;
    }

    fseek(elff, 0L, SEEK_END);
    filesz = ftell(elff);
    fclose(elff);

    if (offset > filesz) {
        PyErr_SetString(PyExc_IndexError, "Offset is bigger than filesize");
        goto read_fail;
    }

    if (!overwrite) {
        // store part after insertion block
        if ((filemem = read_n_at(path, offset, filesz - offset)) == NULL);

        // insert new data
        if (write_to_file(path, offset, bytes, nbytes) == -1) goto copy_fail;

        // write stored data after inserted block
        if (write_to_file(path, offset + nbytes, bytes, filesz - offset) == -1) goto copy_fail;

        free(filemem);
    } else {
        // insert new data
        if (write_to_file(path, offset, bytes, nbytes) == -1) goto fail;
    }

    return Py_None;

copy_fail:
    free(filemem);
read_fail:
    fclose(elff);
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

    if ((shdr = checked_read_shdr_data(path, index)) == NULL) {
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
write_section_header(PyObject *self, PyObject *args)
{
    Elf64_Shdr* shdr;
    char *path, *member;
    int index;
    long offset, data;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
        goto fail;
    }

    if ((shdr = checked_read_shdr_data(path, index)) == NULL) {
        PyErr_SetString(PyExc_IOError, "Could not read ELF section header.");
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
        PyErr_SetString(PyExc_AttributeError, "ELF section header does not have a member with this name");
        goto parse_fail;
    }

    if ((offset = get_shdr_offset(path, index)) == -1) {
        goto parse_fail;
    }
    
    if ((write_to_file(path, offset, shdr, sizeof(Elf64_Shdr))) == -1) {
        goto parse_fail;
    }

    free(shdr);

    return Py_None;

parse_fail:
    free(shdr);
fail:
    return NULL;
}

static PyObject*
read_program_header(PyObject* self, PyObject* args)
{
    long res;
    Elf64_Phdr* phdr;
    char *path, *member;
    int index;

    if (!PyArg_ParseTuple(args, "ssi", &path, &member, &index)) {
        return NULL;
    }

    if ((phdr = checked_read_phdr_data(path, index)) == NULL) {
        goto fail;
    }

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

    free(phdr);

    return PyLong_FromLong(res);

read_fail:
    free(phdr);
fail:
    return NULL;
}


static PyObject*
write_program_header(PyObject* self, PyObject* args)
{
    Elf64_Phdr* phdr;
    char* path, * member;
    int index;
    long offset, data;

    if (!PyArg_ParseTuple(args, "ssil", &path, &member, &index, &data)) {
        goto fail;
    }

    if ((phdr = checked_read_phdr_data(path, index)) == NULL) {
        goto fail;
    }

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

    offset = get_phdr_offset(path, index);
    if (write_to_file(path, offset, (void *) phdr, sizeof(Elf64_Phdr)) == -1) goto write_fail;

    free(phdr);
    return Py_None;

write_fail:
parse_fail:
    free(phdr);
fail:
    return NULL;
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
