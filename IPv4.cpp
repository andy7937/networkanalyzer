#include "IPv4.h"
#include "packet_sniffer.h"
#include <iostream>

void IPv4::handleIPv4Packet(const u_char* packet) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv4Header* IPv4Header = (const struct IPv4Header*)(packet + sizeof(struct etherHeader));

    // Determine protocol inside packet
    switch (IPv4Header->ip_p) {
    case IPPROTO_UDP:
        std::cout << "Protocol is UDP" << std::endl;
        handleIPv4UDPPacket(IPv4Header);
        break;
    case IPPROTO_TCP:
        std::cout << "Protocol is TCP" << std::endl;
        handleIPv4TCPPacket(IPv4Header);
        break;
    case IPPROTO_ICMP:
        std::cout << "Protocol is ICMP" << std::endl;
        handleIPv4ICMPPacket(IPv4Header);
        break;
        // Add cases for other protocols as needed
    default:
        std::cout << "Protocol is Unknown" << std::endl;
        handleIPv4UnknownProtocol(IPv4Header);
        // unknown cases
        break;
    }
}

void IPv4::handleIPv4UDPPacket(const struct IPv4Header* IPv4Header) {

}

void IPv4::handleIPv4TCPPacket(const struct IPv4Header* IPv4Header) {

}

void IPv4::handleIPv4ICMPPacket(const struct IPv4Header* IPv4Header) {

}

void IPv4::handleIPv4UnknownProtocol(const IPv4Header* IPv4Header){

}
