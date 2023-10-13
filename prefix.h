#include <string>

class Prefix
{
private:
    std::string ip_address; // Base IP of the prefix
    int prefix_length;      // Length of the prefix
    int max_hosts;
    int current_hosts = 0;
    int usage_flag = 0;

    // Convert IP address string to a numeric representation
    uint32_t ip_to_int(const std::string &ip);

public:
    Prefix(const std::string prefix_str); // Constructor will need to parse the prefix string

    ~Prefix();

    // Increase the current host count by one
    void increment_host_count() { current_hosts++; }

    // Check if a given IP belongs to the prefix
    bool ip_belongs(const std::string &ip);

    // Usage percentage
    float usage() const;

    // Getters and setters as needed
    int get_max_hosts() const { return max_hosts; }
    void set_max_hosts(int value) { max_hosts = value; }
    std::string get_ip_address() const { return ip_address; }
    int get_prefix_length() const { return prefix_length; }
    int get_current_hosts() const { return current_hosts; }
    int get_usage_flag() const { return usage_flag; }
    void set_usage_flag(int value) { usage_flag = value; }
    std::string to_string() const { return ip_address + "/" + std::to_string(prefix_length); }
};
