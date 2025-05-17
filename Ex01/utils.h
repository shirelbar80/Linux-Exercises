#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>


using namespace std;

struct Block {
    string hash;
    int height;
    long long total;
    string time;
    string relayed_by;
    string previous_block;
};

vector<Block> load_db();
//void printBlock(const Block& block);
void printBlocks(const std::vector<Block>& blocks);
void findAndPrintBlockByField(const string& field, const string& value, vector<Block>& blocks);
 string extractValue(const string& rawLine);
void ExportTxtToCSV();
void refreshData(int numBlocks);