#include <pcap.h>
#include <syslog.h>
#include <vector>
#include <string>
#include <iostream>
#include <signal.h>
#include <getopt.h>

//testing commit

int check_args(int argc, char **argv, std::string& pcapFile, std::vector<std::string>& interfaces) {
    int opt;
    
    while ((opt = getopt(argc, argv, "r:i:h")) != -1) {  
        switch (opt) {
            case 'r':
                if (optarg) {
                    pcapFile = std::string(optarg);
                } else {
                    return -1;  
                }
                break;
            case 'i':
                if (optarg) {
                    while (optind < argc && argv[optind][0] != '-') {
                        interfaces.push_back(std::string(argv[optind]));
                        optind++;
                    }
                } else {
                    return -1;  
                }
                break;
            case 'h':
                 std::cout << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
                std::cout << "-r <filename>   : Parse pcap file for DHCP packets." << std::endl;
                std::cout << "-i <interface>  : Listen on the given interface for DHCP packets." << std::endl;
                std::cout << "-h              : Show this help message." << std::endl;
                exit(0);  // Exit the program after showing help
            default:
                std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
                return -1;  
        }
    }
    return 0;
}


int main (int argc, char ** argv) {
    std::string pcapFile;
    std::vector<std::string> interfaces;

    int arguments = check_args(argc, argv, pcapFile, interfaces);

    if (arguments != 0){
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        return 0;
    }
     

    for (const auto& interface : interfaces) {
    std::cout << interface << std::endl;
    }
 //commit check
}