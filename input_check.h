/**
 * @file input_check.h
 * @author Patrik Potancok xpotan00
 * @date 2023-10-19
 */
#pragma once

#include <string>
#include <vector>
#include <getopt.h>
#include <regex>

/**
 * @brief function for checking if the input argumets are correct
 *
 * @param argc number of arguments
 * @param argv arguments from terminal
 * @param pcap_file name of the pcap file will be returned here, if any was on input
 * @param interface name of the interface will be returned here, if any was on input
 * @param ip_prefixes ip prefixes from input will be stored here
 * @return int 0 if correct 1 if incorrect
 */
int check_args(int argc, char **argv, std::string &pcap_file, std::string &interface, std::vector<std::string> &ip_prefixes);
/**
 * @brief checks if the prefix has the right regex
 *
 * @param ip_prefix IP prefix
 * @return true
 * @return false
 */
bool valid_prefix(std::string ip_prefix);