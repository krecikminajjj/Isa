#include "input_check.h"
#include <iostream>

int check_args(int argc, char **argv, std::string &pcap_file, std::string &interface, std::vector<std::string> &ip_prefixes)
{
    int opt;
    bool i_flag = false;
    bool r_flag = false;

    if (argc < 1)
    {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(1);
    }

    while ((opt = getopt(argc, argv, "r:i:h")) != -1)
    {
        switch (opt)
        {
        case 'r':
            r_flag = true;
            if (optarg)
            {
                pcap_file = std::string(optarg);
                while (optind < argc && argv[optind][0] != '-')
                {
                    ip_prefixes.push_back(std::string(argv[optind]));
                    optind++;
                    if (optind >= argc)
                    {
                        break;
                    }
                }
                if (ip_prefixes.empty())
                {
                    std::cerr << "Error: IP addresses must follow the interface argument." << std::endl;
                    return 1;
                }
            }
            else
            {
                return 1;
            }
            break;
        case 'i':
            i_flag = true;
            if (optarg)
            {
                interface = std::string(optarg);
                while (optind < argc && argv[optind][0] != '-')
                {
                    ip_prefixes.push_back(std::string(argv[optind]));
                    optind++;
                    if (optind >= argc)
                    {
                        break;
                    }
                }
                if (ip_prefixes.empty())
                {
                    std::cerr << "Error: IP addresses must follow the interface argument." << std::endl;
                    return 1;
                }
            }
            else
            {
                return 1;
            }
            break;
        case 'h':
            std::cout << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
            std::cout << "-r <filename>   : Parse pcap file for DHCP packets." << std::endl;
            std::cout << "-i <interface>  : Listen on the given interface for DHCP packets." << std::endl;
            std::cout << "-h              : Show this help message." << std::endl;
            exit(0); // Exit the program after showing help
        default:
            std::cerr << "Error: Arguments not used correctly type './dhcp-stats -h for help." << std::endl;
            return 1;
        }
    }

    // Check if neither -r nor -i were provided
    if (!r_flag && !i_flag)
    {
        std::cerr << "Error: Either -r or -i must be provided. Type './dhcp-stats -h' for help." << std::endl;
        return 1;
    }
    else if (r_flag && i_flag)
    {
        std::cerr << "Error: Either -r or -i must be provided not both. Type './dhcp-stats -h' for help." << std::endl;
    }

    return 0;
}

bool valid_prefix(std::string ip)
{
    std::regex ip_prefix{
        "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/([0-9]|[1-2][0-9]|3[0-2]))?$"};

    return std::regex_match(ip, ip_prefix);
}