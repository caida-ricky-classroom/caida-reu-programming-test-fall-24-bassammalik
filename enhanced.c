#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>  
#include <arpa/inet.h>      
#include <string.h>         

#define MAX_OCTET 256  

// struct to pass the octet count array to the pcap_loop callback
struct octet_counter {
    int octet_count[MAX_OCTET];
    int packet_count;
};

// function for pcap_loop to process each packet
void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct octet_counter *counter = (struct octet_counter*)user;
    struct ip *ip_header;

    // checks to see if it contains an Ethernet and IP header
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        return;
    }

    // offset the IP header after the Ethernet header
    ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    // extract IP address
    struct in_addr dest_ip = ip_header->ip_dst;

    // convert IP from network order to host order
    uint32_t ip_in_host_order = ntohl(dest_ip.s_addr);

    // gets the last octet from the IP address
    unsigned char last_octet = ip_in_host_order & 0xFF;

    // increments the count 
    counter->octet_count[last_octet]++;

    // prints destination IP 
    printf("Packet %d: IP destination address: %s\n", ++counter->packet_count, inet_ntoa(dest_ip));
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct octet_counter counter;

    // initializes the octet count array and packet count
    memset(counter.octet_count, 0, sizeof(counter.octet_count));
    counter.packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\\n", argv[0]);
        return 1;
    }

    // opens the pcap file 
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\\n", errbuf);
        return 1;
    }

    // uses pcap_loop to process the packets
    pcap_loop(handle, 0, process_packet, (u_char*)&counter);

    pcap_close(handle);

    // print the counts
    for (int i = 0; i < MAX_OCTET; i++) {
        if (counter.octet_count[i] > 0) {
            printf("Last octet %d: %d occurrences\n", i, counter.octet_count[i]);
        }
    }

    return 0;
}
