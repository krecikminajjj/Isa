/**
 * @file prefix.cpp
 * @author Patrik Potancok xpotan00
 * @date 2023-10-19
 */
#include "prefix.h"

Prefix::Prefix(const std::string ip_address, const int prefix_length)
    : ip_address(std::move(ip_address)), prefix_length(prefix_length),
      current_hosts(0), usage_flag(false)
{
    this->max_hosts = (1 << (32 - this->prefix_length)) - 2; // Subtracting network and broadcast addresses
    if (this->max_hosts < 0)
    {
        this->max_hosts = 0;
    }
}

Prefix::~Prefix() = default;

float Prefix::usage() const
{
    if (this->max_hosts > 0)
    {
        return static_cast<float>(this->current_hosts) / this->max_hosts;
    }
    return 0.0f;
}

uint32_t Prefix::ip_to_int(const std::string ip)
{
    uint32_t byte1, byte2, byte3, byte4;
    sscanf(ip.c_str(), "%u.%u.%u.%u", &byte1, &byte2, &byte3, &byte4);
    return (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
}

bool Prefix::ip_belongs(const std::string ip)
{
    uint32_t ip_num = Prefix::ip_to_int(ip);
    uint32_t prefix_num = Prefix::ip_to_int(this->ip_address);
    uint32_t mask = ~((1 << (32 - this->prefix_length)) - 1); // Calculate netmask
    uint32_t network_address = prefix_num & mask;
    uint32_t broadcast_address = network_address | ~mask;

    if (ip_num == network_address || ip_num == broadcast_address)
    {
        return false; // The IP is either the network or broadcast address
    }

    return (ip_num & mask) == (prefix_num & mask) ? true : false; // Check if IPs match in the prefix
}

void Prefix::increment_host_count()
{
    this->current_hosts++;
}

int Prefix::get_max_hosts() const
{
    return this->max_hosts;
}

std::string Prefix::get_ip_address() const
{
    return this->ip_address;
}

int Prefix::get_prefix_length() const
{
    return this->prefix_length;
}

int Prefix::get_current_hosts() const
{
    return this->current_hosts;
}

bool Prefix::get_usage_flag() const
{
    return this->usage_flag;
}

void Prefix::set_max_hosts(const int value)
{
    this->max_hosts = value;
}

void Prefix::set_usage_flag(const bool value)
{
    this->usage_flag = value;
}

std::string Prefix::to_string() const
{
    return this->ip_address + "/" + std::to_string(this->prefix_length);
}