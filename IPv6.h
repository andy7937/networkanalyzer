#ifndef IPV6_H
#define IPV6_H

#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // Include this for IPv6 related definitions

// Define the IPv6 header structure
struct IPv6Header {
    u_char      ip_vtcflow;     // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    u_short     ip_payloadlen;  // Payload Length (16 bits)
    u_char      ip_nexthdr;     // Next Header (8 bits)
    u_char      ip_hoplimit;    // Hop Limit (8 bits)
    struct in6_addr ip_src;     // Source IPv6 address (128 bits)
    struct in6_addr ip_dst;     // Destination IPv6 address (128 bits)
};

// Function declarations for handling IPv6 packets

class IPv6 {
public:
    void handleIPv6Packet(const u_char* packet);

private:
    void handleIPv6UDPPacket(const struct IPv6Header* IPv6Header);
    void handleIPv6TCPPacket(const struct IPv6Header* IPv6Header);
    void handleIPv6ICMPPacket(const struct IPv6Header* IPv6Header);
    void handleIPv6UnknownIPvProtocol(uint8_t protocol);
};

#endif // IPV4_H