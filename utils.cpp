#include "utils.h"
#include "printer.h" 


vector<Block> load_db() {
    ifstream file("blocks.txt");
    vector<Block> blocks;

    if (!file) {
        print_error("Failed to open file: blocks.txt\n");
        return blocks;
    }

    string line;
    Block current;

    while (getline(file, line)) {
        if (line.rfind("hash: ", 0) == 0)
            current.hash = line.substr(6);
        else if (line.rfind("height: ", 0) == 0)
            current.height = stoi(line.substr(8));
        else if (line.rfind("total: ", 0) == 0)
            current.total = stoll(line.substr(7));
        else if (line.rfind("time: ", 0) == 0)
            current.time = line.substr(6);
        else if (line.rfind("relayed_by: ", 0) == 0)
            current.relayed_by = line.substr(12);
        else if (line.rfind("previous_block: ", 0) == 0) {
            current.previous_block = line.substr(16);
            blocks.push_back(current);  // Only push after full block is read
        }
    }

    return blocks;
}

//print the db
void printBlocks(const vector<Block>& blocks) {
    for (size_t i = 0; i < blocks.size(); ++i) {
        printBlock(blocks[i]);
        if (i != blocks.size() - 1) {
            print_output("|\n|\n|\nV\n");
        }
    }
}

// Prints block matching given hash or height.
void findAndPrintBlockByField(const string& field, const string& value, vector<Block>& blocks) {

    for (const Block& block : blocks) {
        if ((field == "hash" && block.hash == value) ||
            (field == "height" && to_string(block.height) == value)) {
            printBlock(block);
            return;
        }
    }

    printNotFoundMessage(field, value);
}

// Converts blocks.txt to a.csv
void ExportTxtToCSV() {
    std::ifstream inputFile("blocks.txt");
    std::ofstream outputFile("blocks.csv");  // <-- writes to blocks.csv automatically

    if (!inputFile.is_open() || !outputFile.is_open()) {
        print_error("Error opening input or output file!\n");
        return;
    }

    std::vector<Block> blocks;
    std::string line;
    Block current;

    while (std::getline(inputFile, line)) {
        if (line.rfind("hash: ", 0) == 0)
            current.hash = extractValue(line);
        else if (line.rfind("height: ", 0) == 0)
            current.height = std::stoi(extractValue(line));
        else if (line.rfind("total: ", 0) == 0)
            current.total = std::stoll(extractValue(line));
        else if (line.rfind("time: ", 0) == 0)
            current.time = extractValue(line);
        else if (line.rfind("relayed_by: ", 0) == 0)
            current.relayed_by = extractValue(line);
        else if (line.rfind("previous_block: ", 0) == 0) {
            current.previous_block = extractValue(line);
            blocks.push_back(current);
        }
    }

    inputFile.close();

    outputFile << "hash,height,total,time,relayed_by,previous_block\n";
    for (const Block& block : blocks) {
        outputFile << block.hash << ","
                   << block.height << ","
                   << block.total << ","
                   << block.time << ","
                   << block.relayed_by << ","
                   << block.previous_block << "\n";
    }

    outputFile.close();
}

// Extracts the value part from a "key: value" line
 string extractValue(const std::string& rawLine) {
    size_t delimiterPos = rawLine.find(':');
    if (delimiterPos == std::string::npos) return "";

    std::string value = rawLine.substr(delimiterPos + 1);
    size_t firstNonSpace = value.find_first_not_of(' ');
    return (firstNonSpace != std::string::npos) ? value.substr(firstNonSpace) : "";
}

void refreshData(int numBlocks) 
{
    string command = "./get_blocks.sh " + to_string(numBlocks);
    system(command.c_str());
}