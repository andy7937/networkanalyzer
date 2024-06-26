#include "IPv4.h"
#include "packet_sniffer.h"
#include "Logger.h"

#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <ws2tcpip.h> 
#include <iphlpapi.h> 
#include <pcap.h>       

// List of common ports
std::unordered_map<u_short, std::string> commonUDPPorts = {
    {53, "DNS"},
    {67, "DHCP (Server)"},
    {68, "DHCP (Client)"},
    {80, "HTTP"},
    {123, "NTP"},
    {161, "SNMP"},
    {162, "SNMP Trap"},
    {443, "HTTPS"},
    {500, "IKE (IPsec)"},
    {520, "RIP"},
    {1900, "SSDP"},
    {2095, "Webmail"},
    {2096, "Webmail SSL"},
    {3306, "MySQL"},
    {4500, "IPsec NAT Traversal"}
};

// List of common IP addresses
std::unordered_set<u_short> commonIPaddrs = {
};



void IPv4::handleIPv4Packet(const u_char* packet, const struct pcap_pkthdr* pkthdr) {
    // Parse the protocol by adding length of the etherHead
    const struct IPv4Header* IPv4Header = (const struct IPv4Header*)(packet + sizeof(struct etherHeader));
    logger.appendTimeStamp();

    // Determine protocol inside packet
    switch (IPv4Header->ip_p) {
    case IPPROTO_UDP:
        std::cout << "Protocol is UDP" << std::endl;
        handleIPv4UDPPacket(packet, pkthdr);
        break;
    case IPPROTO_TCP:
        std::cout << "Protocol is TCP" << std::endl;
        handleIPv4TCPPacket(packet, pkthdr);
        break;
    case IPPROTO_ICMP:
        std::cout << "Protocol is ICMP" << std::endl;
        handleIPv4ICMPPacket(packet, pkthdr);
        break;
        // Add cases for other protocols as needed
    default:
        std::cout << "Protocol is Unknown" << std::endl;
        handleIPv4UnknownProtocol(packet, pkthdr);
        // unknown cases
        break;
    }
}

// most common
void IPv4::handleIPv4UDPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {
    struct etherHeader* ethHeader = (struct etherHeader*)packet;
    const struct IPv4Header* IPv4Header = (const struct IPv4Header*)(packet + sizeof(struct etherHeader));

    // checking for unusually large Packets
    if (pkthdr->len > 512) {
        std::cout << "Unusally large Packet length: " << pkthdr->len << " bytes" << std::endl;
    }

    // checking for fragmented Packets
    u_short fragment_offset = ntohs(IPv4Header->ip_off) & 0x1FFF;
    bool more_fragments = ntohs(IPv4Header->ip_off) & 0x2000;

    if (fragment_offset != 0 || more_fragments) {
        std::cout << "Fragmented packet detected." << std::endl;
        std::cout << "Fragment Offset: " << fragment_offset << std::endl;
        std::cout << "More Fragments: " << (more_fragments ? "Yes" : "No") << std::endl;
    }


    // checking for unknown IP addresses
    char sourceIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(IPv4Header->ip_src.s_addr), sourceIP, INET_ADDRSTRLEN);
    std::cout << "Source IP Address: " << sourceIP << std::endl;

    // get domain name
    // Calculate UDP header offset (assuming UDP and DNS processing)
    int ipHeaderLength = (IPv4Header->ip_vhl & 0x0F) * 4; // Calculate IP header length
    int udpHeaderOffset = 14 + ipHeaderLength; // 14 is the Ethernet header length

    // Extract UDP header fields
    u_short udpSrcPort = ntohs(*(u_short*)&packet[udpHeaderOffset]);
    u_short udpDstPort = ntohs(*(u_short*)&packet[udpHeaderOffset + 2]);

    // Assuming payload starts right after UDP header
    int payloadOffset = udpHeaderOffset + 8; // UDP header is 8 bytes

    // Print payload (assuming it contains domain-like data)
    std::string payload;
    for (int i = payloadOffset; i < pkthdr->len; ++i) {
        if (isprint(packet[i])) {
            payload += packet[i];
        }
        else {
            payload += '.';
        }
    }

    std::cout << "Payload: " << payload << std::endl;



    // checking for spoofed IP addresses

    // checking for uncommon src ports
    if (commonUDPPorts.find(udpSrcPort) != commonUDPPorts.end()) {
        std::cout << "Src Port " << udpSrcPort << " is commonly used for " << commonUDPPorts[udpSrcPort] << std::endl;
    }
    else {
        std::cout << "Uncommon src Port Detected: " << udpSrcPort << std::endl;
    }

    // checking for uncommon dst ports
    if (commonUDPPorts.find(udpDstPort) != commonUDPPorts.end()) {
        std::cout << "Dst Port " << udpDstPort << " is commonly used for " << commonUDPPorts[udpDstPort] << std::endl;
    }
    else {
        std::cout << "Uncommon dst Port Detected: " << udpDstPort << std::endl;
    }


    // checking for known attack signatures (would need to decrypt the payload based on the protocol used


    // checking for suspicious strings

    // log these packets, and do an overall security check, as this only checks for individual packets. There may be patterns on the overall packet signatures depending on where it is being sent and how many is coming through
    logger.appendLog("Source IP: " + std::string(sourceIP) + " - Transport Protocol: UDP" + " - Packet Length: " + std::to_string(pkthdr->len) + " - Src Port: " + std::to_string(udpSrcPort) + " - Dst Port: " + std::to_string(udpDstPort));
    logger.newLog();
}

void IPv4::handleIPv4TCPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}

void IPv4::handleIPv4ICMPPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}

void IPv4::handleIPv4UnknownProtocol(const u_char* packet, const struct pcap_pkthdr* pkthdr) {

}