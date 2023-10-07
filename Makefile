CXX=g++
CXXFLAGS=-std=c++11 -g -pedantic -Wall -Wextra -Werror
LDFLAGS=-lpcap
TARGET=dhcp-stats
FILES=dhcp-stats.cpp prefix.cpp
OBJFILES=$(FILES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJFILES)