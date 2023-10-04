#include <pcap.h>
#include <syslog.h>
#include <vector>
#include <string>
#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <signal.h>

// Handling CTRL + C
void signal_handler(int signum){
    (void)signum;
    printf("Closing... \n");
    //pcap_close(descr);
    exit(0);
}

//testing commit

int check_args(int argc, char **argv, std::string& pcapFile, std::string& interface, std::vector<std::string>& ip_prefixes) {
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
                    interface = std::string(optarg);
                    while (optind < argc && argv[optind][0] != '-') {
                        ip_prefixes.push_back(std::string(argv[optind]));
                        optind++;
                    }
                    if(ip_prefixes.empty()) {
                        std::cerr << "Error: IP addresses must follow the interface argument." << std::endl;
                        return -1;
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
                std::cerr << "Error: IP addresses must follow the interface argument." << std::endl;
                return -1; 
        }
    }
    return 0;
}


int main (int argc, char ** argv) {
    std::string pcapFile;
    std::string interface;
    std::vector<std::string> ip_prefixes;
    pcap_if_t *alldevs, *device;
    pcap_if_t *interface_select = NULL; 
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;
    //struct bpf_program fp;
    pcap_t *descr;
    //int count = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int arguments = 0;

    if (argc > 1) {  
        arguments = check_args(argc, argv, pcapFile, interface, ip_prefixes);
    } else {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(0);
    }
    

    if (arguments != 0) {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(0);
    }
     
    std::cout << "Interface: " << interface << std::endl;
    
    for(const auto& ip : ip_prefixes) {
        std::cout << ip << std::endl;
    }

    // Handling CTRL + C
    signal(SIGINT, signal_handler);

    //this part is inspired by https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error finding interface: %s\n", errbuf);
        exit(1);
    }
    
    //check if user selected a valid interface
    bool isInterfaceValid = false;
    for (device = alldevs; device; device = device->next) {
        if (interface == device->name) {
            isInterfaceValid = true;
            break;
        }
    }
    
    //if no selected interface was valid print a list of all avaible interfaces
    if (!isInterfaceValid) {
        std::cerr << "Invalid interface: " << interface << std::endl;
        std::cerr << "Available interfaces are: " << std::endl;

        for (device = alldevs; device; device = device->next) {
            std::cerr << device->name << std::endl;
            }
            pcap_freealldevs(alldevs);
            return 1;
    }


    if (pcap_lookupnet(interface_select->name, &pNet, &pMask, errbuf) == PCAP_ERROR) {
        pMask = 0;
        pNet = 0;
    }

    descr = pcap_open_live(interface_select->name, BUFSIZ, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);

    if (descr == NULL) {
        pcap_close(descr);
        fprintf(stderr, "pcap_open_live() failed due to [%s]\n", errbuf);
        exit(1);
    }

    if (pcap_datalink(descr) != DLT_EN10MB) {
        pcap_close(descr);
        fprintf(stderr, "Device does not have ethernet headers\n");
        exit(1);
    }

    pcap_freealldevs(alldevs);
}