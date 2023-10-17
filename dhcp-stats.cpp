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

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;
    std::map<std::string, int> prefix_lines;
    int current_line = 1;

    // Skip the Ethernet, IP, and UDP headers to get to DHCP
    const uint8_t *dhcp_data = packet + 14 + 20 + 8;

    / Skip the Ethernet, IP, and UDP headers to get to DHCP
    const uint8_t *dhcp_data = packet + 14 + 20 + 8;

    const uint8_t *dhcp_options = dhcp_data + 240;
    bool is_ack = false;

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
    
    // Now extract yiaddr
    const uint8_t *yiaddr_ptr = dhcp_data + 16;

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

    if (yiaddr_str != "0.0.0.0")
    {

        if (std::find(seen_ips.begin(), seen_ips.end(), yiaddr_str) == seen_ips.end())
        {
            seen_ips.push_back(yiaddr_str);

            for (auto &prefix : ip_prefixes)
            {

                if (prefix.ip_belongs(yiaddr_str))
                {
                    prefix.increment_host_count();

                    std::string prefix_str = prefix.to_string();
                    if (prefix_lines.find(prefix_str) == prefix_lines.end())
                    {
                        prefix_lines[prefix_str] = current_line++;
                    }

                    if (prefix.usage() > 0.5 && prefix.get_usage_flag() == 0)
                    {
                        prefix.set_usage_flag(1);
                        openlog("dhcp-stats", LOG_PID | LOG_CONS, LOG_USER);
                        syslog(LOG_ERR, "Prefix %s exceeded 50%% of allocations.", prefix.to_string().c_str());
                        closelog();
                    }
                }
            }
        }
    }

    move(0, 0);
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");

    for (const auto &prefix : ip_prefixes)
    {
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
    bool prefix_regex = false;

    arguments = check_args(argc, argv, pcap_file, interface, ip_prefixes_vec);

    if (arguments != 0)
    {
        std::cerr << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name> ...] <ip-prefix> [<ip-prefix> ... ]" << std::endl;
        exit(1);
    }

    for (const auto &ip : ip_prefixes_vec)
    {
        ip_prefixes.emplace_back(ip);
    }

    for (const auto &prefix : ip_prefixes_vec)
    {
        prefix_regex = valid_prefix(prefix);

        if (prefix_regex == false)
        {
            std::cerr << "Invalid prefix" << prefix << std::endl;
            exit(1);
        }
    }

    initscr();

    // Handling CTRL + C
    signal(SIGINT, signal_handler);

    if (strcmp(argv[1], "-i") == 0)
    {
        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
        {
            std::cerr << "Error finding interface: " << errbuf << std::endl;
            endwin();
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
            endwin();
            exit(1);
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
            std::cerr << "pcap_open_live() failed due to " << errbuf << std::endl;
            endwin();
            exit(1);
        }

        if (pcap_datalink(descr) != DLT_EN10MB)
        {
            pcap_close(descr);
            std::cerr << "Device does not have ethernet headers" << std::endl;
            endwin();
            exit(1);
        }
    }
    else
    {
        pcap_file = argv[2];

        if (!pcap_file.empty())
        {
            descr = pcap_open_offline(pcap_file.c_str(), errbuf);
        }
        else
        {
            std::cerr << "Empty pcap file" << errbuf << std::endl;
            endwin();
            exit(1);
        }

        if (descr == NULL)
        {
            std::cerr << "Error opening device: " << errbuf << std::endl;
            endwin();
            exit(1);
        }
    }

    std::string filter_str = "udp and port 67 or port 68";

    if (pcap_compile(descr, &fp, filter_str.c_str(), 0, pNet) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_compile() failed" << std::endl;
        endwin();
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_setfilter() failed" << std::endl;
        endwin();
        exit(1);
    }

    if (pcap_loop(descr, 0, callback, NULL) == -1)
    {
        pcap_freecode(&fp);
        pcap_close(descr);
        std::cerr << "pcap_loop() failed" << std::endl;
        endwin();
        exit(1);
    }

    pcap_freecode(&fp);
    printw("Press any key to exit...");
    getch();
    pcap_close(descr);
    endwin();
    return 0;
}
