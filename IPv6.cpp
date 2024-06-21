#include "IPv6.h"
#include "packet_sniffer.h"

void IPv6::handleIPv6Packet(const u_char* packet) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv6Header* IPv6Header = (const struct IPv6Header*)packet;

    // Determine protocol inside packet
    switch (IPv6Header->ip_nexthdr) {
    case IPPROTO_UDP:
        handleIPv6UDPPacket(IPv6Header);
        break;
    case IPPROTO_TCP:
        handleIPv6TCPPacket(IPv6Header);
        break;
    case IPPROTO_ICMP:
        handleIPv6ICMPPacket(IPv6Header);
        break;
        // Add cases for other protocols as needed
    default:
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

