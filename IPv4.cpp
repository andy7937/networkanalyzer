#include "IPv4.h"
#include "packet_sniffer.h"

void IPv4::handleIPv4Packet(const u_char* packet) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv4Header* IPv4Header = (const struct IPv4Header*)(packet + sizeof(struct etherHeader));

    // Determine protocol inside packet
    switch (IPv4Header->ip_p) {
    case IPPROTO_UDP:
        handleIPv4UDPPacket(IPv4Header);
        break;
    case IPPROTO_TCP:
        handleIPv4TCPPacket(IPv4Header);
        break;
    case IPPROTO_ICMP:
        handleIPv4ICMPPacket(IPv4Header);
        break;
        // Add cases for other protocols as needed
    default:
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

