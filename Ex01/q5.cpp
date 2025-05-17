#include "printer.h"
#include "utils.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

void RunQ5();
void ExecuteChoice(int choiceNum, vector<Block> blocks);

int main() {
    
    while(true){
        RunQ5();
    }

    return 0;
}

void RunQ5() {

    vector<Block> blocks = load_db();
    PrintMenu();
    int choice;
    cin >> choice;
    ExecuteChoice(choice, blocks);
}

void ExecuteChoice (int choiceNum, vector<Block> blocks)
{
    if (choiceNum == 1)
    {
        printBlocks(blocks);
    }
    else if (choiceNum == 2)
    {
        string hashNumber;
        print_output("Enter block hash: \n");
        cin >> hashNumber;
        findAndPrintBlockByField("hash", hashNumber, blocks);
    }
    else if (choiceNum == 3)
    {
        string heightNumber;
        print_output("Enter block height: \n");
        cin >> heightNumber;
        findAndPrintBlockByField("height", heightNumber, blocks);
    }
    else if (choiceNum == 4)
    {
        ExportTxtToCSV();
    }
    else if (choiceNum == 5) 
    {
    int numOfNewBlocks;
    print_output("Enter number of blocks to fetch: ");
    cin >> numOfNewBlocks;
    refreshData(numOfNewBlocks);
    }
}