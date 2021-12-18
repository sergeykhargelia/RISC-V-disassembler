#ifndef HW3_ELF_PARSER_H
#define HW3_ELF_PARSER_H

#include <cstdint>
#include <iosfwd>

namespace Parser {

#pragma pack(push, 1)

typedef struct {
    std::uint8_t e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint32_t e_entry;
    std::uint32_t e_phoff;
    std::uint32_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
} ELF32_header;

typedef struct {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint32_t sh_flags;
    std::uint32_t sh_addr;
    std::uint32_t sh_offset;
    std::uint32_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint32_t sh_addralign;
    std::uint32_t sh_entsize;
} Elf32_section_header;

typedef struct {
    std::uint32_t st_name;
    std::uint32_t st_value;
    std::uint32_t st_size;
    std::uint8_t st_info;
    std::uint8_t st_other;
    std::uint16_t st_shndx;
} Elf32_Sym;

#pragma pack(pop)

const int TEXT_TYPE = 1;
const int SYMTAB_TYPE = 2;
const int STRTAB_TYPE = 3;

void parse(std::ifstream& in, std::ofstream& out);

}

#endif
