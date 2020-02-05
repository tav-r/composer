#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

Elf64_Ehdr*
get_ehdr_data(const char *path)
{
    int elf_fd;
    Elf64_Ehdr *hdr;

    elf_fd = open(path, O_RDONLY);
    hdr = malloc(sizeof(Elf64_Ehdr));
    read(elf_fd, hdr, sizeof(Elf64_Ehdr));

    close(elf_fd);
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

ssize_t
write_to_file(FILE *file, ssize_t offset, unsigned char *data, ssize_t size)
{
	ssize_t res;

	// write given bytes to file
	res = fseek(file, offset, SEEK_SET);
	if (fwrite(data, 1, size, file) < 0) {
		puts(strerror(errno));
	}
	return res;
}

Elf64_Shdr*
get_shdr_data(char *path, int index) {
	Elf64_Shdr* shdr;
	long offset;
	int elf_fd;
	
	offset = get_shdr_offset(path, index);

	// read shdr data from file
	elf_fd = open(path, O_RDONLY);
	lseek(elf_fd, offset, SEEK_SET);
	shdr = malloc(sizeof(Elf64_Shdr));
	read(elf_fd, shdr, sizeof(Elf64_Shdr));
	close(elf_fd);
	
	return shdr;
}

long
get_phdr_offset(char *path, int index) {
	long offset;

	Elf64_Ehdr* ehdr;
	ehdr = get_ehdr_data(path);
	offset = ehdr->e_phoff + ehdr->e_phentsize * index;
	free(ehdr);

	return offset;
}

Elf64_Phdr*
get_phdr_data(char *path, int index) {
	Elf64_Phdr* phdr;
	long offset;
	int elf_fd;
	
	offset = get_phdr_offset(path, index);

	// read shdr data from file
	elf_fd = open(path, O_RDONLY);
	lseek(elf_fd, offset, SEEK_SET);
	phdr = malloc(sizeof(Elf64_Shdr));
	read(elf_fd, phdr, sizeof(Elf64_Shdr));
	close(elf_fd);
	
	return phdr;
}
