#include "utils.h"
#include "printer.h"
#include <iostream>
#include <fstream>

using namespace std;


int main(int argc, char* argv[]) {

    if (argc != 3) {
        print_error("Usage: " + string(argv[0]) + " --hash <value> OR --height <value>\n");
        return 1;
    }

    string option = argv[1];
    string value = argv[2];
    vector<Block> blocks = load_db();

    if (option == "--hash") {
        findAndPrintBlockByField("hash", value, blocks);
    } else if (option == "--height") {
        findAndPrintBlockByField("height", value, blocks);
    } else {
        print_output("Invalid option: " + option + "\nUse --hash or --height\n");
        return 1;
    }

    return 0;
}
