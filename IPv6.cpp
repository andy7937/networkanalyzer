#include "IPv6.h"
#include "packet_sniffer.h"
#include <iostream>

void IPv6::handleIPv6Packet(const u_char* packet) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv6Header* IPv6Header = (const struct IPv6Header*)packet;

    // Determine protocol inside packet
    switch (IPv6Header->ip_nexthdr) {
    case IPPROTO_UDP:
        std::cout << "Protocol is UDP" << std::endl;
        handleIPv6UDPPacket(IPv6Header);
        break;
    case IPPROTO_TCP:
        std::cout << "Protocol is TCP" << std::endl;        
        handleIPv6TCPPacket(IPv6Header);
        break;
    case IPPROTO_ICMP:
        std::cout << "Protocol is ICMP" << std::endl;
        handleIPv6ICMPPacket(IPv6Header);
        break;
        // Add cases for other protocols as needed
    default:
        std::cout << "Protocol is Unknown" << std::endl;
        handleIPv6UnknownProtocol(IPv6Header);
        // unknown cases
        break;
    }
}

void IPv6::handleIPv6UDPPacket(const struct IPv6Header* IPv6Header) {

}

void IPv6::handleIPv6TCPPacket(const struct IPv6Header* IPv6Header) {

}

void IPv6::handleIPv6ICMPPacket(const struct IPv6Header* IPv6Header) {

}

void IPv6::handleIPv6UnknownProtocol(const struct IPv6Header* IPv6Header) {

}