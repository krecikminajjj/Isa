#pragma once

#include <string>
#include <vector>
#include <getopt.h>
#include <regex>

int check_args(int argc, char **argv, std::string &pcap_file, std::string &interface, std::vector<std::string> &ip_prefixes);
bool valid_prefix(std::string ip_prefix);