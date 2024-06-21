#include "packet_sniffer.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <cstdint>

// Link with Ws2_32.lib
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// open specified device for capturing packets
PacketSniffer::PacketSniffer(const char* device) {
    // second parameter - size of the buffer in which packets will be stored temporarily
    // third parameter - 1 turns on promiscuous mode capturing all packets on the network
    //                 - 0 turns off promiscuous mode only capturing device packets
    // fourth parameter - read timeout in ms
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << device << ": " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }
}

// close the device handle if it is open
PacketSniffer::~PacketSniffer() {
    if (handle) {
        pcap_close(handle);
    }
}

// start capturing packets
void PacketSniffer::startSniffing() {
    const u_char* packet;
    struct pcap_pkthdr header;

    // enter loop reading packets in the buffer
    // if buffer is overflown, then older packets will be overwritten by newer packets
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        std::cout << "Captured a packet with length of [" << header.len << "]" << std::endl;
        packetEtherHandler(nullptr, &header, packet);
    } // Register packetEtherHandler as callback

}

// handles packages by first finding the type of package
// userData is a parameter to pass user defined data to the callback function
// pkthdr is a pointer that contains the metadata about the captured packet. include 'ts' - timestamp of packet capture, 'caplen' - length of the packet, 'len' - length of the original packet on the wire
// packet is a pointer to the packet data
void PacketSniffer::packetEtherHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Parse Ethernet header to get EtherType
    struct etherHeader* ethHeader = (struct etherHeader*)packet;
    u_short ether_type = ntohs(ethHeader->ether_type);

    switch (ether_type) {
    case 0x0800: // IPv4
        std::cout << "Packet is IPv4" << std::endl;
        ipv4Processor.handleIPv4Packet(packet);
        break;
    case 0x86DD: // IPv6
        std::cout << "Packet is IPv6" << std::endl;
        ipv6Processor.handleIPv6Packet(packet);
        break;
    case 0x0806: // ARP
        std::cout << "Packet is ARP" << std::endl;
        // handle ARP case
        break;
    case 0x8100: // VLAN-tagged frame
        std::cout << "Packet is VLAN" << std::endl;
        // handle VLAN case
        break;
        // Add cases for other EtherTypes as needed
    default:
        // handle default case
        std::cout << "Packet is Unknown" << std::endl;
        break;
    }
}

