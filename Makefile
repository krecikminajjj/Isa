CXX=g++
CXXFLAGS=-std=c++11 -g -pedantic -Wall -Wextra -Werror
LDFLAGS=-lpcap

dhcp-stats: dhcp-stats.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f dhcp-stats