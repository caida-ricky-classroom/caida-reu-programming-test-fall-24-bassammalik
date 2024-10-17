#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>  // Since I use macOS, I had to change the header instead of <linux/if_ether.h>
#include <arpa/inet.h>      // Include inet_ntoa to convert IP address to a readable format

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    int packet_count = 0;

    // Checks to see if the pcap file is an argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\\n", argv[0]);
        return 1;
    }

    // Opens the pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\\n", errbuf);
        return 1;
    }

    // Loops through the packets in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Ensures that it contains both an Ethernet and IP header
        
        if (header.caplen < sizeof(struct ether_header) + sizeof(struct ip)) { // Used `struct ether_header`for macOS
            // Skips the packet if it's not long enough
            continue;
        }
        
        // Offsets the IP header based on the Ethernet header size
        ip_header = (struct ip*)(packet + sizeof(struct ether_header)); // Used struct ether_header` and `struct ip` for macOS 

        // Prints the destination IP address from the IP header
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst)); // Used `ip_header->ip_dst` for destination IP and inet_ntoa to print it
    }
    pcap_close(handle);
    return 0;
}
