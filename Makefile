CXX=g++
CXXFLAGS=-std=c++11 -g -pedantic -Wall -Wextra -Werror
LDFLAGS=-lpcap -lncurses
TARGET=dhcp-stats
FILES=dhcp-stats.cpp prefix.cpp input_check.cpp
OBJFILES=$(FILES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJFILES)