#ifndef IPV4_H
#define IPV4_H
#include "Logger.h"
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // Include this for IPv6 related definitions

// Define the IPv4 header structure
struct IPv4Header {
    u_char      ip_vhl;         // Version (4 bits) + Header Length (4 bits)
    u_char      ip_tos;         // Type of Service (8 bits)
    u_short     ip_len;         // Total Length (16 bits)
    u_short     ip_id;          // Identification (16 bits)
    u_short     ip_off;         // Fragment Offset (13 bits) + Flags (3 bits)
    u_char      ip_ttl;         // Time to Live (8 bits)
    u_char      ip_p;           // Protocol (8 bits)
    u_short     ip_sum;         // Header Checksum (16 bits)
    struct in_addr ip_src;      // Source IPv4 address (32 bits)
    struct in_addr ip_dst;      // Destination IPv4 address (32 bits)
};

class IPv4 {
public:
    void handleIPv4Packet(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    void handleIPv4UDPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void handleIPv4TCPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void handleIPv4ICMPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void handleIPv4UnknownProtocol(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    Logger logger; // Reference to Logger object
};

#endif // IPV4_H