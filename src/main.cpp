#include "elf_parser.h"
#include <iostream>
#include <stdexcept>
#include <fstream>

const int ARGUMENTS_COUNT = 3;

int main(int argc, char * argv[]) {
    try {
        if (argc < ARGUMENTS_COUNT) {
            throw std::invalid_argument("wrong number of arguments.");
        }
        std::string input_file_name = std::string(argv[1]),
                    output_file_name = std::string(argv[2]);

        std::ifstream in(input_file_name, std::ios::binary);
        in.exceptions(std::ifstream::failbit | std::ifstream::eofbit);

        std::ofstream out(output_file_name);

        Parser::parse(in, out);
    } catch (const std::invalid_argument& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::ios_base::failure& e) {
        std::cout << "Failed to read input file: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
