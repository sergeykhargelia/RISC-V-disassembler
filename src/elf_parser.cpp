#include "elf_parser.h"
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <stdexcept>
#include <bitset>
#include <map>

namespace Parser {

static std::string get_type(std::uint32_t x) {
    auto type = x & 0xf;
    switch (type) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 5: return "COMMON";
        case 6: return "TLS";
        case 10: return "LOOS";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        case 15: return "HIPROC";
        default: throw std::invalid_argument("unknown type in symtab");
    }
}

static std::string get_bind(std::uint32_t x) {
    auto bind = x >> 4;
    switch (bind) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 10: return "LOOS";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        case 15: return "HIPROC";
        default: throw std::invalid_argument("unknown bind in symtab");
    }
}

static std::string get_visibility(std::uint8_t x) {
    auto visibility = x & 0x3;
    switch (visibility) {
        case 0: return "DEFAULT";
        case 1: return "INTERNAL";
        case 2: return "HIDDEN";
        default: return "PROTECTED";
    }
}

static std::string get_index(std::uint16_t x) {
    switch (x) {
        case 0: return "UNDEF";
        case 0xfff1: return "ABS";
        case 0xff00: return "LOPROC";
        case 0xff1f: return "HIPROC";
        case 0xff20: return "LOOS";
        case 0xff3f: return "HIOS";
        case 0xfff2: return "COMMON";
        case 0xffff: return "XINDEX";
        default: return std::to_string(x);
    }
}

static std::string get_name(std::ifstream& in, std::uint32_t offset_inside_strtab, std::uint32_t strtab_offset) {
    if (offset_inside_strtab == 0) {
        return "";
    }
    in.seekg(strtab_offset + offset_inside_strtab);
    std::string name;
    char c;
    in.read(reinterpret_cast<char *>(&c), sizeof(c));
    while (c != '\0') {
        name.push_back(c);
        in.read(reinterpret_cast<char *>(&c), sizeof(c));
    }
    return name;
}

static std::uint32_t find_section(const std::vector<Elf32_section_header>& section_headers, int section_type_id) {
    for (std::size_t i = 0; i < section_headers.size(); i++) {
        if (section_headers[i].sh_type == section_type_id) {
            return i;
        }
    }
    return 0;
}

static const int MAX_LENGTH = 10000;

static void parse_symtab (
        std::ifstream& in,
        std::ofstream& out,
        std::vector<Elf32_section_header>& section_headers
) {
    auto strtab_offset = section_headers[find_section(section_headers, STRTAB_TYPE)].sh_offset;

    static char buf[MAX_LENGTH];

    sprintf(buf, "%s %-15s %7s %-8s %-8s %-8s %6s %s\n",
            "Symbol", "Value", "Size", "Type", "Bind", "Vis", "Index", "Name");

    out.write(buf, static_cast<int>(std::string(buf).size()));

    for (auto s_header : section_headers) {
        if (s_header.sh_type == SYMTAB_TYPE) {
            for (std::size_t id_in_section = 0; id_in_section < s_header.sh_size / sizeof(Elf32_Sym); id_in_section++) {
                in.seekg(static_cast<int>(s_header.sh_offset + id_in_section * sizeof(Elf32_Sym)));

                Elf32_Sym sym;
                in.read(reinterpret_cast<char *>(&sym), sizeof(sym));

                sprintf(buf, "[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n",
                        id_in_section,
                        sym.st_value,
                        sym.st_size,
                        get_type(sym.st_info).c_str(),
                        get_bind(sym.st_info).c_str(),
                        get_visibility(sym.st_other).c_str(),
                        get_index(sym.st_shndx).c_str(),
                        get_name(in, sym.st_name, strtab_offset).c_str()
                );
                out.write(buf, static_cast<int>(std::string(buf).size()));
            }
        }
    }
}

static std::map<std::uint32_t, std::string> calc_tags (
        std::ifstream& in,
        std::vector<Elf32_section_header>& section_headers
) {
    std::map<std::uint32_t, std::string> tags;
    auto strtab_offset = section_headers[find_section(section_headers, STRTAB_TYPE)].sh_offset;

    for (auto s_header : section_headers) {
        if (s_header.sh_type == SYMTAB_TYPE) {
            for (std::size_t id_in_section = 0; id_in_section < s_header.sh_size / sizeof(Elf32_Sym); id_in_section++) {
                in.seekg(static_cast<int>(s_header.sh_offset + id_in_section * sizeof(Elf32_Sym)));

                Elf32_Sym sym;
                in.read(reinterpret_cast<char *>(&sym), sizeof(sym));

                auto name = get_name(in, sym.st_name, strtab_offset);
                if (!name.empty()) {
                    tags[sym.st_value] = name;
                }
            }
        }
    }
    return tags;
}

static std::string get_segment(std::uint16_t cmd, int l, int r) {
    return std::bitset<16>(cmd).to_string().substr(16 - r - 1, r - l + 1);
}

static std::string get_segment(std::uint32_t cmd, int l, int r) {
    return std::bitset<32>(cmd).to_string().substr(32 - r - 1, r - l + 1);
}

std::uint32_t get_cmd32(std::ifstream& in, std::uint16_t cmd16) {
    std::uint32_t cmd32 = cmd16;
    in.read(reinterpret_cast<char *>(&cmd16), sizeof(cmd16));
    cmd32 = (cmd16 << 16) | cmd32;
    return cmd32;
}

const char* print_format[2][4] = {{"%s\n", "%s %s\n", "%s %s, %s\n", "%s %s, %s, %s\n"},
                                  {"%s()\n", "%s(%s)\n", "%s %s(%s)\n", "%s %s, %s(%s)\n"}};

static void print_cmd (
        std::ofstream& out,
        std::uint32_t adr,
        const std::string& tag,
        const std::vector<std::string>& args,
        bool is_load_store = false
) {
    if (tag.empty()) {
        static char buf_title[25];
        sprintf(buf_title, "%08x", adr);
        out.write(buf_title, static_cast<int>(std::string(buf_title).size()));
        out.write(std::string(13, ' ').c_str(), 13);
    } else {
        static char buf_title[MAX_LENGTH];
        sprintf(buf_title, "%08x %10s: ", adr, tag.c_str());
        out.write(buf_title, static_cast<int>(std::string(buf_title).size()));
    }
    static char buf[4][MAX_LENGTH];
    switch (args.size()) {
        case 1: sprintf(buf[0], print_format[is_load_store][0], args[0].c_str());
                break;
        case 2: sprintf(buf[1], print_format[is_load_store][1], args[0].c_str(), args[1].c_str());
                break;
        case 3: sprintf(buf[2], print_format[is_load_store][2], args[0].c_str(), args[1].c_str(), args[2].c_str());
                break;
        case 4: sprintf(buf[3], print_format[is_load_store][3], args[0].c_str(), args[1].c_str(), args[2].c_str(), args[3].c_str());
                break;
        default: throw std::invalid_argument("wrong number of arguments for print_cmd function");
    }
    out.write(buf[args.size() - 1], static_cast<int>(std::string(buf[args.size() - 1]).size()));
}

static std::uint32_t get_unsigned(std::uint32_t value, int l, int r) {
    std::uint32_t result = 0;
    for (std::size_t i = l; i <= r; i++) {
        if ((value >> i) & 1) {
            result |= 1 << (i - l);
        }
    }
    return result;
}

static int get_signed(std::uint32_t value, int l, int r) {
    int result = 0;
    if ((value >> r) & 1) {
        for (int i = l; i < r; i++) {
            if (!((value >> i) & 1)) {
                result |= 1 << (i - l);
            }
        }
        return -result - 1;
    }
    return static_cast<int>(get_unsigned(value, l, r - 1));
}

static std::string get_reg(std::uint32_t id) {
    if (id == 0)
        return "zero";
    if (id == 1)
        return "ra";
    if (id == 2)
        return "sp";
    if (id == 3)
        return "gp";
    if (id == 4)
        return "tp";
    if (id >= 5 && id <= 7)
        return "t" + std::to_string(id - 5);
    if (id == 8 || id == 9)
        return "s" + std::to_string(id - 8);
    if (id >= 10 && id <= 17)
        return "a" + std::to_string(id - 10);
    if (id >= 18 && id <= 27)
        return "s" + std::to_string(id - 16);
    if (id >= 28 && id <= 31)
        return "t" + std::to_string(id - 25);
    throw std::invalid_argument("unknown register");
}

static void parse_text (
        std::ifstream& in,
        std::ofstream& out,
        std::vector<Elf32_section_header>& section_headers,
        std::map<std::uint32_t, std::string>& tags
) {
    std::size_t text_section_id = find_section(section_headers, TEXT_TYPE);
    std::uint32_t text_offset = section_headers[text_section_id].sh_offset,
    text_size = section_headers[text_section_id].sh_size;
    in.seekg(text_offset);

    while (static_cast<std::uint32_t>(in.tellg()) - text_offset < text_size) {
        bool is_load_store = false;
        auto adr = static_cast<std::uint32_t>(in.tellg()) - text_offset;
        auto tag = (tags.count(adr) ? tags[adr] : "");
        std::uint32_t cmd32;
        std::uint16_t cmd16;
        in.read(reinterpret_cast<char *>(&cmd16), sizeof(cmd16));
        std::vector<std::string> args;
        std::string cmd_name;
        if (get_segment(cmd16, 0, 1) == "00") {
            std::string type = get_segment(cmd16, 13, 15);
            if (type == "000") {
                cmd_name = "c.addi4spn";
                auto value = (get_unsigned(cmd16, 11, 12) << 4) +
                        (get_unsigned(cmd16, 7, 10) << 6) +
                        (get_unsigned(cmd16, 6, 6) << 2) +
                        (get_unsigned(cmd16, 5, 5) << 3);
                args = {
                    get_reg(get_unsigned(cmd16, 2, 4) + 8),
                    get_reg(2),
                    std::to_string(value)
                };
            } else if (type == "001" || type == "011" || type == "101") {
                is_load_store = true;
                if (type == "001") {
                    cmd_name = "c.fld";
                } else if (type == "011") {
                    cmd_name = "c.ld";
                } else {
                    cmd_name = "c.fsd";
                }
                auto value = (get_unsigned(cmd16, 10, 12) << 3) +
                        (get_unsigned(cmd16, 5, 6) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 2, 4) + 8),
                    std::to_string(value),
                    get_reg(get_unsigned(cmd16, 7, 9) + 8)
                };
            } else if (type == "010" || type == "011" || type == "110" || type == "111") {
                is_load_store = true;
                if (type == "010") {
                    cmd_name = "c.lw";
                } else if (type == "011") {
                    cmd_name = "c.flw";
                } else if (type == "110") {
                    cmd_name = "c.sw";
                } else {
                    cmd_name = "c.fsw";
                }
                auto value = (get_unsigned(cmd16, 10, 12) << 3) +
                        (get_unsigned(cmd16, 6, 6) << 2) +
                        (get_unsigned(cmd16, 5, 5) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 2, 4) + 8),
                    std::to_string(value),
                    get_reg(get_unsigned(cmd16, 7, 9) + 8)
                };
            }
        } else if (get_segment(cmd16, 0, 1) == "01") {
            if (get_segment(cmd16, 2, 15) == std::string(14, '0')) {
                cmd_name = "c.nop";
            } else {
                std::string type = get_segment(cmd16, 13, 15);
                if (type == "000") {
                    cmd_name = "c.addi";
                    args = {
                        get_reg(get_unsigned(cmd16, 7, 11)),
                        get_reg(get_unsigned(cmd16, 7, 11)),
                        std::to_string(get_signed((get_unsigned(cmd16, 12, 12) << 5) +
                        get_unsigned(cmd16, 2, 6), 0, 5))
                    };
                } else if (type == "001") {
                    cmd_name = "c.jal";
                    auto uvalue = (get_unsigned(cmd16, 12, 12) << 11) +
                            (get_unsigned(cmd16, 11, 11) << 4) +
                            (get_unsigned(cmd16, 9, 10) << 8) +
                            (get_unsigned(cmd16, 8, 8) << 10) +
                            (get_unsigned(cmd16, 7, 7) << 6) +
                            (get_unsigned(cmd16, 6, 6) << 7) +
                            (get_unsigned(cmd16, 3, 5) << 1) +
                            (get_unsigned(cmd16, 2, 2) << 5);
                    auto value = get_signed(uvalue, 0, 11);
                    if (tags.count(adr + value)) {
                        args = {tags[adr + value]};
                    } else {
                        args = {std::to_string(value)};
                    }
                } else if (type == "010") {
                    cmd_name = "c.li";
                    args = {
                        get_reg(get_unsigned(cmd16, 7, 11)),
                        std::to_string(get_signed((get_unsigned(cmd16, 12, 12) << 5) +
                        get_unsigned(cmd16, 2, 6), 0, 5))
                    };
                } else if (type == "011" && get_unsigned(cmd16, 7, 11) == 2) {
                    cmd_name = "c.addi16sp";
                    auto uvalue = (get_unsigned(cmd16, 12, 12) << 9)
                            + (get_unsigned(cmd16, 6, 6) << 4) +
                            (get_unsigned(cmd16, 5, 5) << 6) +
                            (get_unsigned(cmd16, 3, 4) << 7) +
                            (get_unsigned(cmd16, 2, 2) << 5);
                    auto value = get_signed(uvalue, 0, 9);
                    args = {
                        get_reg(2),
                        get_reg(2),
                        std::to_string(value)
                    };
                } else if (type == "011") {
                    cmd_name = "c.lui";
                    auto value = get_signed((get_unsigned(cmd16, 12, 12) << 17) +
                                                    (get_unsigned(cmd16, 2, 6) << 12), 0, 17);
                    args = {
                        get_reg(get_unsigned(cmd16, 7, 11)),
                        std::to_string(value)
                    };
                } else if (type == "100") {
                    if (get_segment(cmd16, 10, 11) == "00") {
                        cmd_name = "c.srli";
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            std::to_string((get_unsigned(cmd16, 12, 12) << 5) +
                            get_unsigned(cmd16, 2, 6))
                        };
                    } else if (get_segment(cmd16, 10, 11) == "01") {
                        cmd_name = "c.srai";
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            std::to_string((get_unsigned(cmd16, 12, 12) << 5) + get_unsigned(cmd16, 2, 6))
                        };
                    } else if (get_segment(cmd16, 10, 11) == "10") {
                        cmd_name = "c.andi";
                        auto value = get_signed((get_unsigned(cmd16, 12, 12) << 5) +
                                get_unsigned(cmd16, 2, 6), 0, 5);
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            std::to_string(value)
                        };
                    } else if (get_segment(cmd16, 10, 11) == "11") {
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            get_reg(get_unsigned(cmd16, 7, 9) + 8),
                            get_reg(get_unsigned(cmd16, 2, 4) + 8)
                        };
                        std::string type2 = get_segment(cmd16, 12, 12) + get_segment(cmd16, 5, 6);
                        if (type2 == "000") {
                            cmd_name = "c.sub";
                        } else if (type2 == "001") {
                            cmd_name = "c.xor";
                        } else if (type2 == "010") {
                            cmd_name = "c.or";
                        } else if (type2 == "011") {
                            cmd_name = "c.and";
                        } else if (type2 == "100") {
                            cmd_name = "c.subw";
                        } else if (type2 == "101") {
                            cmd_name = "c.addw";
                        }
                    }
                } else if (type == "101") {
                    cmd_name = "c.j";
                    auto uvalue = (get_unsigned(cmd16, 12, 12) << 11) +
                            (get_unsigned(cmd16, 11, 11) << 4) +
                            (get_unsigned(cmd16, 9, 10) << 8) +
                            (get_unsigned(cmd16, 8, 8) << 10) +
                            (get_unsigned(cmd16, 7, 7) << 6) +
                            (get_unsigned(cmd16, 6, 6) << 7) +
                            (get_unsigned(cmd16, 3, 5) << 1) +
                            (get_unsigned(cmd16, 2, 2) << 5);
                    auto value = get_signed(uvalue, 0, 11);
                    if (tags.count(adr + value)) {
                        args = {tags[adr + value]};
                    } else {
                        args = {std::to_string(value)};
                    }
                } else if (type == "110" || type == "111") {
                    if (type == "110") {
                        cmd_name = "c.beqz";
                    } else {
                        cmd_name = "c.bnez";
                    }
                    args = {get_reg(get_unsigned(cmd16, 7, 9) + 8)};
                    auto uvalue = (get_unsigned(cmd16, 12, 12) << 8) +
                            (get_unsigned(cmd16, 10, 11) << 3) +
                            (get_unsigned(cmd16, 5, 6) << 6) +
                            (get_unsigned(cmd16, 3, 4) << 1) +
                            (get_unsigned(cmd16, 2, 2) << 5);
                    auto value = get_signed(uvalue, 0, 8);
                    if (tags.count(adr + value)) {
                        args.push_back(tags[adr + value]);
                    } else {
                        args.push_back(std::to_string(value));
                    }
                }
            }
        } else if (get_segment(cmd16, 0, 1) == "10") {
            std::string type = get_segment(cmd16, 13, 15);
            if (type == "000") {
                cmd_name = "c.slli";
                auto uvalue = (get_unsigned(cmd16, 12, 12) << 5) +
                        get_unsigned(cmd16, 2, 6);
                args = {
                    get_reg(get_unsigned(cmd16, 7, 11)),
                    get_reg(get_unsigned(cmd16, 7, 11)),
                    std::to_string(uvalue)
                };
            } else if (type == "001") {
                is_load_store = true;
                cmd_name = "c.fldsp";
                auto uvalue = (get_unsigned(cmd16, 12, 12) << 5) +
                        (get_unsigned(cmd16, 5, 6) << 3) +
                        (get_unsigned(cmd16, 2, 4) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 7, 11)),
                    std::to_string(uvalue),
                    get_reg(2)
                };
            } else if (type == "010") {
                is_load_store = true;
                cmd_name = "c.lwsp";
                auto uvalue = (get_unsigned(cmd16, 12, 12) << 5) +
                              (get_unsigned(cmd16, 4, 6) << 2) +
                              (get_unsigned(cmd16, 2, 3) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 7, 11)),
                    std::to_string(uvalue),
                    get_reg(2)
                };
            } else if (type == "011") {
                is_load_store = true;
                cmd_name = "c.flwsp";
                auto uvalue = (get_unsigned(cmd16, 12, 12) << 5) +
                              (get_unsigned(cmd16, 4, 6) << 2) +
                              (get_unsigned(cmd16, 2, 3) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 7, 11)),
                    std::to_string(uvalue),
                    get_reg(2)
                };
            } else if (type == "100") {
                if (get_segment(cmd16, 2, 6) != "00000") {
                    if (get_segment(cmd16, 12, 12) == "1") {
                        cmd_name = "c.add";
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 11)),
                            get_reg(get_unsigned(cmd16, 7, 11)),
                            get_reg(get_unsigned(cmd16, 2, 6))
                        };
                    } else {
                        cmd_name = "c.mv";
                        args = {
                            get_reg(get_unsigned(cmd16, 7, 11)),
                            get_reg(get_unsigned(cmd16, 2, 6))
                        };
                    }
                } else {
                    if (get_segment(cmd16, 7, 15) == "100100000") {
                        cmd_name = "c.ebreak";
                    } else {
                        args = {get_reg(get_unsigned(cmd16, 7, 11))};
                        if (get_segment(cmd16, 12, 12) == "0") {
                            cmd_name = "c.jr";
                        } else {
                            cmd_name = "c.jalr";
                        }
                    }
                }
            } else if (type == "101") {
                is_load_store = true;
                cmd_name = "c.fsdsp";
                auto uvalue = (get_unsigned(cmd16, 10, 12) << 3) +
                        (get_unsigned(cmd16, 7, 9) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 2, 6)),
                    std::to_string(uvalue),
                    get_reg(2)
                };
            } else {
                is_load_store = true;
                if (type == "110") {
                    cmd_name = "c.swsp";
                } else {
                    cmd_name = "c.fswsp";
                }
                auto uvalue = (get_unsigned(cmd16, 9, 12) << 2) +
                              (get_unsigned(cmd16, 7, 8) << 6);
                args = {
                    get_reg(get_unsigned(cmd16, 2, 6)),
                    std::to_string(uvalue),
                    get_reg(2)
                };
            }
        }
        else if (get_segment(cmd16, 0, 6) == "0110111") {
            cmd32 = get_cmd32(in, cmd16);
            args = std::vector<std::string>({
                get_reg(get_unsigned(cmd32, 7, 11)),
                std::to_string(get_signed((get_unsigned(cmd32, 12, 31) << 12), 0, 31))
            });
            cmd_name = "lui";
        } else if (get_segment(cmd16, 0, 6) == "0010111") {
            cmd32 = get_cmd32(in, cmd16);
            auto value = get_signed((get_unsigned(cmd32, 12, 31) << 12), 0, 31);
            args = std::vector<std::string>({
                get_reg(get_unsigned(cmd32, 7, 11)),
                std::to_string(value)
            });
            cmd_name = "auipc";
        } else if (get_segment(cmd16, 0, 6) == "0010011") {
            cmd32 = get_cmd32(in, cmd16);
            std::string type = get_segment(cmd32, 12, 14);
            if (type != "001" && type != "101") {
                if (type == "000") {
                    cmd_name = "addi";
                } else if (type == "010") {
                    cmd_name = "slti";
                } else if (type == "011") {
                    cmd_name = "sltiu";
                } else if (type == "100") {
                    cmd_name = "xori";
                } else if (type == "110") {
                    cmd_name = "ori";
                } else if (type == "111") {
                    cmd_name = "andi";
                }
                args = std::vector<std::string>({
                     get_reg(get_unsigned(cmd32, 7, 11)),
                     get_reg(get_unsigned(cmd32, 15, 19)),
                     std::to_string(get_signed((get_unsigned(cmd32, 20, 31)), 0, 11))
                });
            } else {
                args = std::vector<std::string>({
                    get_reg(get_unsigned(cmd32, 7, 11)),
                    get_reg(get_unsigned(cmd32, 15, 19)),
                    std::to_string((get_unsigned(cmd32, 20, 24)))
                });
                if (type == "001") {
                    cmd_name = "slli";
                } else {
                    if (get_segment(cmd32, 30, 30) == "0") {
                        cmd_name = "srli";
                    } else {
                        cmd_name = "srai";
                    }
                }
            }
        } else if (get_segment(cmd16, 0, 6) == "0110011") {
            cmd32 = get_cmd32(in, cmd16);
            if (get_segment(cmd32, 25, 26) == "00") {
                std::string type = get_segment(cmd32, 27, 31) + get_segment(cmd32, 12, 14);
                args = {
                    get_reg(get_unsigned(cmd32, 7, 11)),
                    get_reg(get_unsigned(cmd32, 15, 19)),
                    get_reg(get_unsigned(cmd32, 20, 24))
                };
                if (type == "00000000") {
                    cmd_name = "add";
                } else if (type == "01000000") {
                    cmd_name = "sub";
                } else if (type == "00000001") {
                    cmd_name = "sll";
                } else if (type == "00000010") {
                    cmd_name = "slt";
                } else if (type == "00000011") {
                    cmd_name = "sltu";
                } else if (type == "00000100") {
                    cmd_name = "xor";
                } else if (type == "00000101") {
                    cmd_name = "srl";
                } else if (type == "01000101") {
                    cmd_name = "sra";
                } else if (type == "00000110") {
                    cmd_name = "or";
                } else if (type == "00000111") {
                    cmd_name = "and";
                }
            } else if (get_segment(cmd32, 25, 26) == "01") {
                std::string type = get_segment(cmd32, 12, 14);
                args = {
                    get_reg(get_unsigned(cmd32, 7, 11)),
                    get_reg(get_unsigned(cmd32, 15, 19)),
                    get_reg(get_unsigned(cmd32, 20, 24))
                };
                if (type == "000") {
                    cmd_name = "mul";
                } else if (type == "001") {
                    cmd_name = "mulh";
                } else if (type == "010") {
                    cmd_name = "mulhsu";
                } else if (type == "011") {
                    cmd_name = "mulhu";
                } else if (type == "100") {
                    cmd_name = "div";
                } else if (type == "101") {
                    cmd_name = "divu";
                } else if (type == "110") {
                    cmd_name = "rem";
                } else if (type == "111") {
                    cmd_name = "remu";
                }
            }
        } else if (get_segment(cmd16, 0, 6) == "0000011") {
            is_load_store = true;
            cmd32 = get_cmd32(in, cmd16);
            std::string type = get_segment(cmd32, 12, 14);
            args = {
                get_reg(get_unsigned(cmd32, 7, 11)),
                std::to_string(get_signed(cmd32, 20, 31)),
                get_reg(get_unsigned(cmd32, 15, 19))
            };
            if (type == "000") {
                cmd_name = "lb";
            } else if (type == "001") {
                cmd_name = "lh";
            } else if (type == "010") {
                cmd_name = "lw";
            } else if (type == "100") {
                cmd_name = "lbu";
            } else if (type == "101") {
                cmd_name = "lhu";
            }
        } else if (get_segment(cmd16, 0, 6) == "0100011") {
            cmd32 = get_cmd32(in, cmd16);
            std::string type = get_segment(cmd32, 12, 14);
            args = {
                get_reg(get_unsigned(cmd32, 20, 24)),
                std::to_string(get_signed((get_unsigned(cmd32, 25, 31) << 5) + get_unsigned(cmd32, 7, 11), 0, 11)),
                get_reg(get_unsigned(cmd32, 15, 19))
            };
            is_load_store = true;
            if (type == "000") {
                cmd_name = "sb";
            } else if (type == "001") {
                cmd_name = "sh";
            } else if (type == "010") {
                cmd_name = "sw";
            }
        } else if (get_segment(cmd16, 0, 6) == "1101111") {
            cmd32 = get_cmd32(in, cmd16);
            cmd_name = "jal";
            args = {get_reg(get_signed(cmd32, 7, 11))};
            auto uvalue = (get_unsigned(cmd32, 31, 31) << 20) +
                    (get_unsigned(cmd32, 21, 30) << 1) +
                    (get_unsigned(cmd32, 20, 20) << 11) +
                    (get_unsigned(cmd32, 12, 19) << 12);
            auto value = get_signed(uvalue, 0, 20);
            if (tags.count(adr + value)) {
                args.push_back(tags[adr + value]);
            } else {
                args.push_back(std::to_string(value));
            }
        } else if (get_segment(cmd16, 0, 6) == "1100111") {
            cmd32 = get_cmd32(in, cmd16);
            cmd_name = "jalr";
            args = {
                get_reg(get_unsigned(cmd32, 7, 11)),
                get_reg(get_unsigned(cmd32, 15, 19)),
            };
            auto value = get_signed(get_unsigned(cmd32, 20, 31), 0, 11);
            args.push_back(std::to_string(value));
        } else if (get_segment(cmd16, 0, 6) == "1100011") {
            cmd32 = get_cmd32(in, cmd16);
            args = {
                get_reg(get_unsigned(cmd32, 15, 19)),
                get_reg(get_unsigned(cmd32, 20, 24))
            };
            std::string type = get_segment(cmd32, 12, 14);
            if (type == "000") {
                cmd_name = "beq";
            } else if (type == "001") {
                cmd_name = "bne";
            } else if (type == "100") {
                cmd_name = "blt";
            } else if (type == "101") {
                cmd_name = "bge";
            } else if (type == "110") {
                cmd_name = "bltu";
            } else if (type == "111") {
                cmd_name = "bgeu";
            }
            auto uvalue = (get_unsigned(cmd32, 31, 31) << 12) +
                    (get_unsigned(cmd32, 25, 30) << 5) +
                    (get_unsigned(cmd32, 8, 11) << 1) +
                    (get_unsigned(cmd32, 7, 7) << 11);
            auto value = get_signed(uvalue, 0, 12);
            if (tags.count(adr + value)) {
                args.push_back(tags[adr + value]);
            } else {
                args.push_back(std::to_string(value));
            }
        }

        if (cmd_name.empty()) {
            std::string s = "unknown_command\n";
            out.write(s.c_str(), static_cast<int>(s.size()));
        } else {
            args.insert(args.begin(), cmd_name);
            print_cmd(out, adr, tag, args, is_load_store);
        }
    }
}

void parse(std::ifstream& in, std::ofstream& out) {
    ELF32_header file_header;
    in.read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
    if (file_header.e_ident[1] != 'E' || file_header.e_ident[2] != 'L' || file_header.e_ident[3] != 'F') {
        throw std::invalid_argument("this is not a ELF file");
    }
    std::vector<Elf32_section_header> section_headers(file_header.e_shnum);
    in.seekg(file_header.e_shoff);
    for (auto& s_header : section_headers) {
        in.read(reinterpret_cast<char *>(&s_header), sizeof(s_header));
    }
    auto tags = calc_tags(in, section_headers);
    out.write(".text\n", 6);
    parse_text(in, out, section_headers, tags);
    out.write("\n.symtab\n", 9);
    parse_symtab(in, out, section_headers);
}

}