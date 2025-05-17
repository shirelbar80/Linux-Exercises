#include "utils.h"
#include "printer.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

int main() {

    vector<Block> blocks = load_db();
    printBlocks(blocks);
    return 0;
}

