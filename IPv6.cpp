#include "IPv6.h"
#include "packet_sniffer.h"
#include <iostream>

void IPv6::handleIPv6Packet(const u_char* packet, const struct pcap_pkthdr* pkthdr) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv6Header* IPv6Header = (const struct IPv6Header*)packet;

    // Determine protocol inside packet
    switch (IPv6Header->ip_nexthdr) {
    case IPPROTO_UDP:
        std::cout << "Protocol is UDP" << std::endl;
        handleIPv6UDPPacket(packet, pkthdr);
        break;
    case IPPROTO_TCP:
        std::cout << "Protocol is TCP" << std::endl;        
        handleIPv6TCPPacket(packet, pkthdr);
        break;
    case IPPROTO_ICMP:
        std::cout << "Protocol is ICMP" << std::endl;
        handleIPv6ICMPPacket(packet, pkthdr);
        break;
        // Add cases for other protocols as needed
    default:
        std::cout << "Protocol is Unknown" << std::endl;
        handleIPv6UnknownProtocol(packet, pkthdr);
        // unknown cases
        break;
    }
}

void IPv6::handleIPv6UDPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}

void IPv6::handleIPv6TCPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}

void IPv6::handleIPv6ICMPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}

void IPv6::handleIPv6UnknownProtocol(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}