#include "printer.h"

using namespace std;

void printBlock(const Block& block) {
    std::cout << "hash: " << block.hash << std::endl;
    std::cout << "height: " << block.height << std::endl;
    std::cout << "total: " << block.total << std::endl;
    std::cout << "time: " << block.time << std::endl;
    std::cout << "relayed_by: " << block.relayed_by << std::endl;
    std::cout << "previous_block: " << block.previous_block << std::endl;
}

void print_output(const std::string& message) {
    std::cout << message;
}

void print_error(const std::string& message) {
    std::cerr << message;
}


void printNotFoundMessage(const std::string& field, const std::string& value) {
    std::cout << "No matching block found for " << field << ": " << value << std::endl;
}

void PrintMenu()
{
    cout << "Choose an option:" << endl;
    cout << "1. Print db" << endl;
    cout << "2. Print block by hash" << endl;
    cout << "3. Print block by height" << endl;
    cout << "4. Export data to csv" << endl;
    cout << "5. Refresh data" << endl;
    cout << "Enter your choice: ";
}