/**
 * @file dhcp-stats.cpp
 * @author Patrik Potancok xpotan00
 * @date 2023-10-19
 */

#include <pcap.h>
#include <syslog.h>
#include <vector>
#include <string>
#include <iostream>
#include <signal.h>
#include <ncurses.h>
#include <algorithm>
#include <string.h>
#include <syslog.h>
#include <map>

#include "prefix.h"
#include "input_check.h"

pcap_t *descr;
std::vector<Prefix> ip_prefixes;
std::vector<std::string> seen_ips;

// Handling CTRL + C
void signal_handler(int signum)
{
    (void)signum;
    std::cout << "Closing..." << std::endl;
    pcap_close(descr);
    endwin();
    exit(0);
}

/**
 * @brief Function for packet sniffing and printing stats
 * 
 * @param args 
 * @param header 
 * @param packet 
 */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;
    std::map<std::string, int> prefix_lines;
    int current_line = 1;
    
    // Skip the Ethernet, IP, and UDP headers to get to DHCP
    const uint8_t *dhcp_data = packet + 14 + 20 + 8;

    // Get to DHCP options
    const uint8_t *dhcp_options = dhcp_data + 240;
    bool is_ack = false;

    // Look for DHCP ack in options
    while (*dhcp_options != 255)
    {
        uint8_t option_code = *dhcp_options++;
        uint8_t option_length = *dhcp_options++;

        if (option_code == 53 && *dhcp_options == 5) // Check for DHCP ACK
        {
            is_ack = true;
            break;
        }
        dhcp_options += option_length; // Skip over this option's data
    }

    // If it's not a DHCP ACK, skip the rest of this iteration and await next callback
    if (!is_ack)
    {
        return;
    }

    // Extract yiaddr
    const uint8_t *yiaddr_ptr = dhcp_data + 16;

    // Converting yiaddr to string
    std::string yiaddr_str;
    for (int i = 0; i < 4; ++i)
    {
        yiaddr_str += std::to_string(yiaddr_ptr[i]); // Convert the byte to a string
        if (i < 3)
        {
            yiaddr_str += "."; // Insert dot between octets
        }
    }

    // Sort by prefix length (not max hosts) - smaller lengths first
    std::sort(ip_prefixes.begin(), ip_prefixes.end(), [](const Prefix &a, const Prefix &b)
              { return a.get_prefix_length() < b.get_prefix_length(); });

    // Skip 0.0.0.0 address
    if (yiaddr_str != "0.0.0.0")
    {
        // If IP was not seen yet it will be added to seen_ips
        if (std::find(seen_ips.begin(), seen_ips.end(), yiaddr_str) == seen_ips.end())
        {
            seen_ips.push_back(yiaddr_str);
            // Check if the IP belongs in any prefix
            for (Prefix &prefix : ip_prefixes)
            {
                // If it belongs the host count will be incemented 
                if (prefix.ip_belongs(yiaddr_str))
                {
                    prefix.increment_host_count();

                    // If usage is more than 50% error will be printed to syslog
                    if (prefix.usage() > 0.5 && prefix.get_usage_flag() == false)
                    {
                        prefix.set_usage_flag(true);
                        openlog("dhcp-stats", LOG_PID | LOG_CONS, LOG_USER);
                        syslog(LOG_ERR, "prefix %s exceeded 50%% of allocations.", prefix.to_string().c_str());
                        closelog();
                    }
                }
            }
        }
    }

    //Printing stats
    move(0, 0);
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");

    for (Prefix &prefix : ip_prefixes)
    {
        // Finding line in which the desired prefix is and changing just that one line
        std::string prefix_str = prefix.to_string();
        if (prefix_lines.find(prefix_str) == prefix_lines.end())
        {
            prefix_lines[prefix_str] = current_line++;
        }
        move(prefix_lines[prefix_str], 0);
        printw("%s %d %d %.2f%%\n", prefix_str.c_str(), prefix.get_max_hosts(), prefix.get_current_hosts(), prefix.usage() * 100);
    }
    refresh();
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

    arguments = check_args(argc, argv, pcap_file, interface, ip_prefixes_vec);

    if (arguments != 0)
    {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(1);
    }
    
    // Creating instances of class prefix
    for (std::string ip_prefix : ip_prefixes_vec)
    {
        std::string ip = ip_prefix.substr(0, ip_prefix.find('/'));
        int prefix_length = std::stoi(ip_prefix.substr(ip_prefix.find('/') + 1));
        ip_prefixes.emplace_back(ip, prefix_length);
    }

    // Checking if the prefix has correct syntax
    for (std::string prefix : ip_prefixes_vec)
    {
        if (!valid_prefix(prefix))
        {
            std::cerr << "Invalid prefix " << prefix << std::endl;
            exit(1);
        }
    }

    // Handling CTRL + C
    signal(SIGINT, signal_handler);

    // If we are sniffing an interface
    if (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interface") == 0)
    {
        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
        {
            std::cerr << "Error finding interface: " << errbuf << std::endl;
            exit(1);
        }

        // Check if user selected a valid interface
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

        // If no selected interface was valid print a list of all avaible interfaces
        if (!is_interface_valid)
        {
            std::cerr << "Invalid interface: " << interface << std::endl;
            std::cerr << "Available interfaces are: " << std::endl;

            for (device = alldevs; device; device = device->next)
            {
                std::cerr << device->name << std::endl;
            }
            pcap_freealldevs(alldevs);
            exit(1);
        }

        // Initializing ncurses field
        initscr();

        // Attempt to retrieve the network address and mask of the selected interface.
        if (pcap_lookupnet(interface_select->name, &pNet, &pMask, errbuf) == PCAP_ERROR)
        {
            // If lookup fails, default the network address and mask to 0.
            pMask = 0;
            pNet = 0;
        }

        // Open the selected interface for live capturing. Set buffer size and read timeout.
        descr = pcap_open_live(interface_select->name, BUFSIZ, 1, 1000, errbuf);

        // Free the list of available devices.
        pcap_freealldevs(alldevs);

        // Check if the descriptor was initialized correctly.
        if (descr == NULL)
        {
            std::cerr << "pcap_open_live() failed due to " << errbuf << std::endl;
            endwin();
            exit(1);
        }

        // Check if the opened device supports Ethernet headers.
        if (pcap_datalink(descr) != DLT_EN10MB)
        {
            pcap_close(descr);
            std::cerr << "Device does not have ethernet headers" << std::endl;
            endwin();
            exit(1);
        }
    }
    else if (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "--read") == 0)
    {
        //initializing ncurses field
        initscr();
        
        // Check if the pcap file is not empty.
        if (!pcap_file.empty())
        {
            // Open pcap file for offline analysis.
            descr = pcap_open_offline(pcap_file.c_str(), errbuf);
        }
        else
        {
            std::cerr << "Empty pcap file" << errbuf << std::endl;
            endwin();
            exit(1);
        }

        // Check if the descriptor was initialized correctly.
        if (descr == NULL)
        {
            std::cerr << "Error opening device: " << errbuf << std::endl;
            endwin();
            exit(1);
        }
    }
    else 
    {
        std::cerr << "Invalid argument" << std::endl;
    }

    // Set filter to capture only UDP packets on ports 67 or 68.
    std::string filter_str = "udp and port 67 or port 68";

    // Compile the filter.
    if (pcap_compile(descr, &fp, filter_str.c_str(), 0, pNet) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_compile() failed" << std::endl;
        endwin();
        exit(1);
    }

    // Set the compiled filter for the capture.
    if (pcap_setfilter(descr, &fp) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_setfilter() failed" << std::endl;
        endwin();
        exit(1);
    }
    
    // Start capturing packets. Callback function will be invoked for each captured packet.
    if (pcap_loop(descr, 0, callback, NULL) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_loop() failed" << std::endl;
        endwin();
        exit(1);
    }

    // Free the compiled filter.
    pcap_freecode(&fp);

    // Notify user to press any key to terminate the program.
    printw("Press any key to exit...");
    getch();

    // Clean up: Close the descriptor and the ncurses window.
    pcap_close(descr);
    endwin();
    return 0;
}