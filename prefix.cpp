#include "prefix.h"

Prefix::Prefix(const std::string &prefix_str)
{
    size_t slash_pos = prefix_str.find('/');
    ip_address = prefix_str.substr(0, slash_pos);
    prefix_length = std::stoi(prefix_str.substr(slash_pos + 1));

    max_hosts = (1 << (32 - prefix_length)) - 2; // Subtracting network and broadcast addresses
    current_hosts = 0;
}

uint32_t Prefix::ip_to_int(const std::string &ip)
{
    uint32_t byte1, byte2, byte3, byte4;
    sscanf(ip.c_str(), "%u.%u.%u.%u", &byte1, &byte2, &byte3, &byte4);
    return (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
}

bool Prefix::ip_belongs(const std::string &ip)
{
    uint32_t ip_num = ip_to_int(ip);
    uint32_t prefix_num = ip_to_int(ip_address);
    uint32_t mask = ~((1 << (32 - prefix_length)) - 1); // Calculate netmask

    return (ip_num & mask) == (prefix_num & mask); // Check if IPs match in the prefix
}
