#include <iostream>
#include <cstdlib> // for system()
#include <string>
#include "printer.h"

using namespace std;


int main(int argc, char* argv[]) {
  if (argc != 2) {
      print_error("Usage: " + string(argv[0]) + " <number_of_blocks>\n");
      return 1;
  }

  int numBlocks = stoi(argv[1]); // Convert input string to int
  refreshData(numBlocks);

  return 0;
}
