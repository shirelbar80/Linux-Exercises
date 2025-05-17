# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -fPIC -std=c++17

# Find all .cpp files
SRCS := $(wildcard *.cpp)

# Object files: replace .cpp with .o
OBJS := $(SRCS:.cpp=.o)

# The shared library
SHARED_LIB = libutils.so

# List of source files that belong to the library
LIB_SRCS := utils.cpp printer.cpp
LIB_OBJS := $(LIB_SRCS:.cpp=.o)

# All .cpp files excluding library sources = main programs
MAIN_SRCS := $(filter-out $(LIB_SRCS), $(SRCS))
MAIN_PROGS := $(MAIN_SRCS:.cpp=.out)

.PHONY: all clean

# Default rule
all: $(SHARED_LIB) $(MAIN_PROGS)

# Rule to build the shared library
$(SHARED_LIB): $(LIB_OBJS)
	$(CXX) -shared -o $@ $^

# Rule to build each .out program (linking with the .so)
%.out: %.o $(SHARED_LIB)
	$(CXX) -o $@ $< -L. -lutils

# Generic rule to compile .cpp to .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f *.o *.out *.so
