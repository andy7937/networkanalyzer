#include <pcap.h>
#include <iostream>
#include "packet_sniffer.h"
#include "Logger.h"

// printing device list
void printDeviceList() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL /* auth is not needed */,
        &alldevs, errbuf) == -1)
    {
        fprintf(stderr,
            "Error in pcap_findalldevs_ex: %s\n",
            errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    char device[256];

    printDeviceList();

    printf("\nEnter device name to capture from: ");
    std::cin.getline(device, sizeof(device));


    // Specify the network device to capture packets from
    // example - const char* device = "\Device\\NPF_{00247F45-FDC6-49D8-930B-5983567D12D8}";
    const char* device_name = (device); // Replace with your actual network device name

    try {
        // Create a PacketSniffer object
        PacketSniffer sniffer(device_name);
        Logger logger;

        logger.initLog();
        // Start capturing packets
        sniffer.startSniffing();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Cleanup Winsock
    WSACleanup();

    return EXIT_SUCCESS;
}

