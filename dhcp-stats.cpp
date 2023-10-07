#include <pcap.h>
#include <syslog.h>
#include <vector>
#include <string>
#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <ncurses.h>
#include <algorithm>
#include <string.h>

#include "prefix.h"

pcap_t *descr;
std::vector<Prefix> ip_prefixes;
std::vector<std::string> seen_ips;

// Handling CTRL + C
void signal_handler(int signum)
{
    (void)signum;
    printf("Closing... \n");
    pcap_close(descr);
    exit(0);
}

int check_args(int argc, char **argv, std::string &pcap_file, std::string &interface, std::vector<std::string> &ip_prefixes)
{
    int opt;

    while ((opt = getopt(argc, argv, "r:i:h")) != -1)
    {
        switch (opt)
        {
        case 'r':
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
                    return -1;
                }
            }
            else
            {
                return -1;
            }
            break;
        case 'i':
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
                    return -1;
                }
            }
            else
            {
                return -1;
            }
            break;
        case 'h':
            std::cout << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
            std::cout << "-r <filename>   : Parse pcap file for DHCP packets." << std::endl;
            std::cout << "-i <interface>  : Listen on the given interface for DHCP packets." << std::endl;
            std::cout << "-h              : Show this help message." << std::endl;
            exit(0); // Exit the program after showing help
        default:
            std::cerr << "Error: IP addresses must follow the interface argument." << std::endl;
            return -1;
        }
    }
    return 0;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;
    
    // Skip the Ethernet, IP, and UDP headers to get to DHCP
    const uint8_t *dhcp_data = packet + 14 + 20 + 8;

    // Now extract yiaddr
    const uint8_t *yiaddr_ptr = dhcp_data + 16;
    
    std::string yiaddr_str;
    for (int i = 0; i < 4; ++i) {
        yiaddr_str += std::to_string(yiaddr_ptr[i]);  // Convert the byte to a string
        if (i < 3) {
            yiaddr_str += ".";  // Insert dot between octets
        }
    }

    std::cout << yiaddr_str << std::endl;

    if (std::find(seen_ips.begin(),seen_ips.end(), yiaddr_str) == seen_ips.end()) {
        seen_ips.push_back(yiaddr_str);
        for (auto& prefix : ip_prefixes) {
            if (prefix.ip_belongs(yiaddr_str)) {
                prefix.increment_host_count();
                std::cout << "IP " << yiaddr_str << " belongs to prefix " << prefix.get_ip_address() << "/" << prefix.get_prefix_length() << std::endl;
                std::cout << "Usage for this prefix: " << prefix.usage() * 100 << "%" << std::endl;
                break; // Exit loop once we find the matching prefix
            }
        }
    } 
    
}

int main(int argc, char **argv)
{
    std::string pcap_file;
    std::string interface;
    std::vector<std::string> ip_prefixes_vec;
    pcap_if_t *alldevs, *device;
    pcap_if_t *interface_select = NULL;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;
    struct bpf_program fp;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    int arguments = 0;    

    if (argc > 1)
    {
        arguments = check_args(argc, argv, pcap_file, interface, ip_prefixes_vec);
    }
    else
    {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(0);
    }

    if (arguments != 0)
    {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(0);
    }

    for (const auto &ip : ip_prefixes_vec)
    {
        ip_prefixes.emplace_back(ip);
    }

    // Handling CTRL + C
    signal(SIGINT, signal_handler);

   
    if (strcmp(argv[1], "-i") == 0) {
        // this part is inspired by https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
        {
            fprintf(stderr, "Error finding interface: %s\n", errbuf);
            exit(1);
        }

        // check if user selected a valid interface
        bool is_interface_valid = false;
        for (device = alldevs; device; device = device->next)
        {
            if (interface == device->name)
            {
                is_interface_valid = true;
                interface_select = device;
                break;
            }
        }

        // if no selected interface was valid print a list of all avaible interfaces
        if (!is_interface_valid)
        {
            std::cerr << "Invalid interface: " << interface << std::endl;
            std::cerr << "Available interfaces are: " << std::endl;

            for (device = alldevs; device; device = device->next)
            {
                std::cerr << device->name << std::endl;
            }
            pcap_freealldevs(alldevs);
            return 1;
        }
        
        if (pcap_lookupnet(interface_select->name, &pNet, &pMask, errbuf) == PCAP_ERROR)
        {
            pMask = 0;
            pNet = 0;
        }
        descr = pcap_open_live(interface_select->name, BUFSIZ, 1, 1000, errbuf);

        pcap_freealldevs(alldevs);

        if (descr == NULL)
        {
            pcap_close(descr);
            fprintf(stderr, "pcap_open_live() failed due to [%s]\n", errbuf);
            exit(1);
        }
    }
    else {
        pcap_file = argv[2];

        if (!pcap_file.empty()){
            descr = pcap_open_offline(pcap_file.c_str(),errbuf);
        } else {
            std::cerr << "Empty pcap file" << errbuf << std::endl;
            return -1;
        }

        if (descr == NULL) 
        {
            std::cerr << "Error opening device: " << errbuf << std::endl;
            return -1;
        }
        
    }
    
    
    if (pcap_datalink(descr) != DLT_EN10MB)
    {
        pcap_close(descr);
        fprintf(stderr, "Device does not have ethernet headers\n");
        exit(1);
    }

    std::string filter_str = "udp and port 67 or port 68";

    if (pcap_compile(descr, &fp, filter_str.c_str(), 0, pNet) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        fprintf(stderr, "pcap_compile() failed\n");
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        fprintf(stderr, "pcap_setfilter() failed\n");
        exit(1);
    }
    
    if (pcap_loop(descr, 0, callback, NULL) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        fprintf(stderr, "pcap_loop() failed\n");
        exit(1);
    }

    pcap_freecode(&fp);
    pcap_close(descr);

    return 0;
}