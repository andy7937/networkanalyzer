#pragma once
class packet_sniffer
{
};

#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H
#include "IPv4.h" // Include IPv4 header
#include "IPv6.h" // Include IPv6 header
#include <pcap.h>
#include <winsock2.h> 

// Define the Ethernet header structure
// example Ethernet frame
// | Destination MAC | Source MAC | EtherType | Payload | CRC |
// |       6B        |     6B     |    2B     |   nB    | 4B  |
// destination MAC: 6 bytes
// source MAC: 6 bytes
// ethertype: 2 bytes
// payload: data length
// CRC: 4 bytes
struct etherHeader {
    u_char ether_dhost[6]; // Destination host address
    u_char ether_shost[6]; // Source host address
    u_short ether_type;    // Ethernet type
};

class PacketSniffer {
public:
    PacketSniffer(const char* device);
    ~PacketSniffer();
    void startSniffing();
    void packetEtherHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

private:
    pcap_t* handle; // handle for opened device
    char errbuf[PCAP_ERRBUF_SIZE]; // buffer for any error messages
    IPv4 ipv4Processor; // Instance of IPv4 processor
    IPv6 ipv6Processor; // Instance of IPv6 processor
};

#endif // PACKET_SNIFFER_H  