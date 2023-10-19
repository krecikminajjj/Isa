/**
 * @file prefix.h
 * @author Patrik Potancok xpotan00
 * @date 2023-10-19
 */
#pragma once
#include <string>

class Prefix
{
private:
    std::string ip_address; // Base IP of the prefix
    int prefix_length;      // Length of the prefix
    int max_hosts;          // Max hosts of the prefix
    int current_hosts;      // Number of current hosts
    bool usage_flag;        // % of usage

public:
    Prefix(const std::string ip_address, const int prefix_length); // Constructor will need to parse the prefix string

    ~Prefix();

    // Increase the current host count by one
    void increment_host_count();

    // Check if a given IP belongs to the prefix
    bool ip_belongs(const std::string ip);

    // Usage percentage
    float usage() const;

    // Convert IP address string to a numeric representation
    static uint32_t ip_to_int(const std::string ip);

    // Getters and setters as needed
    int get_max_hosts() const;
    void set_max_hosts(const int value);
    std::string get_ip_address() const;
    int get_prefix_length() const;
    int get_current_hosts() const;
    bool get_usage_flag() const;
    void set_usage_flag(const bool value);
    std::string to_string() const;
};
