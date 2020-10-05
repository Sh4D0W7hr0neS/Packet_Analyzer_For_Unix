#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


//global variable to keep track of number of packets.
int packet_no = 0;

//Callback subroutine and other functions definitions.
void callback(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
    );
void print_capture_info(const struct pcap_pkthdr *packet_header);    
void handle_ethernet(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet);
void handle_IP(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);
void handle_TCP(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet, int ethernet_header_length, int ip_header_length);


int main(){
   //---------------------------------------------------------------------------Variable Declarions-------------------------------------------------------//
    
    char *device; // Name of device
    char error_buffer[PCAP_ERRBUF_SIZE]; // error buffer, size predefined in pcap.h 

    
    //bpf_u_int32 is 32-bit unsigned integer type
    bpf_u_int32 ip_raw; // IP address as integer
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer
    struct in_addr address; //Contains members for both ip & subnet
    struct pcap_pkthdr packet_header;   
    
    pcap_t *handle; //pcap_t is the device handle we want to capture packets form
    
    //---------------------------------------------------------------------------Finding device name-------------------------------------------------------//
    device = pcap_lookupdev(error_buffer);
    printf("Device found: %s\n", device);
    
    //---------------------------------------------------------------------------Finding IP address-------------------------------------------------------//
    
    // Get device info
    pcap_lookupnet(device, &ip_raw, &subnet_mask_raw,error_buffer);
    
    
    //set address.s_address as ip_raw and use inet_ntoa to convert the host address in ip_raw from network byte order to a string in IPv4 dotted-decimal notation and print.
    address.s_addr = ip_raw;
    printf("IP address: %s\n", inet_ntoa(address));
    
    //set address.s_address as subnet_mask_raw and use inet_ntoa to convert the host address in subnet_mask_raw from network byte order to a string in IPv4 dotted-decimal notation and print.
    address.s_addr = subnet_mask_raw;
    printf("Subnet mask: %s\n\n", inet_ntoa(address));
    
    //---------------------------------------------------------------------------Live Packet Capture-------------------------------------------------------//
    //create a live capture handle  
    handle = pcap_create(device,error_buffer);
    //activate capture handle  
    pcap_activate(handle);
    
    //capture packets from handle and execute callback subroutine for each subpacket.   
    pcap_loop(handle, 0, callback, NULL);
    
    return 0;
}
    
//callback implementation.
void callback(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet
)
{
    print_capture_info(packet_header);
    handle_ethernet(args,packet_header,packet);
    return;
}

//Function to print Basic Info about the Packer.
void print_capture_info(const struct pcap_pkthdr *packet_header){
    
    printf("Caught Packet %d\n\n", ++packet_no);
    printf("Packet total length %d\n", packet_header->len);
    printf("Packet capture length: %d\n", packet_header->caplen);  
    return;
}

//Function to handle Ethernetnet Header.
void handle_ethernet(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet){
    
    //Defined in netinet/ether.h
    struct ether_header *etherhead;
    etherhead = (struct ether_header *)packet;
    
    //Print source and destination, using ether_ntoa tp covert data into readable form.
    printf("Packet Source: %s\n", ether_ntoa((const struct ether_addr *)&etherhead->ether_shost));
    printf("Packet Destination: %s\n\n", ether_ntoa((const struct ether_addr *)&etherhead->ether_shost));
    
    //Find packet Type and handle if IP.
    printf("Packet Type: ");
    if (ntohs (etherhead->ether_type) == ETHERTYPE_IP)
    {
        printf("IP\n");
        handle_IP(args,packet_header,packet);
    }
    else  if (ntohs (etherhead->ether_type) == ETHERTYPE_ARP)
    {
        printf("ARP\n\n");
    }
    else  if (ntohs (etherhead->ether_type) == ETHERTYPE_REVARP)
    {
        printf("RARP\n\n");
    }
    else {
        printf("Unknown\n\n");
    }
}

//Function to handle IP header.
void handle_IP(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet){
    
    int ethernet_header_length = 14;//Standard.
    const u_char *ip_header; 
    int ip_header_length;
    
    ip_header = packet + ethernet_header_length;//IP header start after ethernet header.
    
    //Create ip structure, defined netinet/ip.h.
    struct ip* ip;
    ip =( struct ip*) ip_header;
    
    //Print IP header data.
    printf("IP Packet found, Sniffing...\n\n");
    printf("IP header length:       %d\n", ip->ip_hl);
    printf("IP Version:             %d\n", ip->ip_v);
    printf("Type of service:        %d\n", ip->ip_tos);
    printf("Total length:           %d\n", ip->ip_len);
    printf("Identification:         %d\n", ip->ip_id);
    printf("Fragment offset:        %d\n", ip->ip_off);
    printf("Time to live:           %d\n", ip->ip_ttl);
    printf("Protocol:               %d\n", ip->ip_p);
    printf("Checksum :              %d\n\n", ip->ip_sum);
    
    ip_header_length = ip->ip_hl;
    
    //check if protocol is tcp, if so handle it, if not return.
    if (ip->ip_p == 6)
        handle_TCP(args,packet_header,packet,ethernet_header_length,ip_header_length);
    else{
        printf("Protocol not TCP. Skipping...\n\n");
        printf("\n\n#############################################################################################################\n\n");
        return;
    }
    
}
    
//Function to handle TCP.
void handle_TCP(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet, int ethernet_header_length, int ip_header_length){
    
    //Pointers to tcp header and payload
    const u_char *tcp_header;
    const u_char *payload;
    
    //Lenght of tcp header and payload
    int tcp_header_length;
    int payload_length;
    
    //Variables used to print paylaod.
    int i;
    const u_char *temp;
    int tempno;
    
    tcp_header = packet + ethernet_header_length + ip_header_length;//TCP header starts after IP header.
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;// TCP header length is stored in the second half of the 12th byte, hence add 12 and apply bitwise operator of 15.
    tcp_header_length = tcp_header_length * 4;// Header Length is stored in 32 bit increments, ie, 2^5, multiply by 2^2 to get byte value.
    
    //Structure of TCP defined in netinet/tcp.h
    struct tcphdr *tcp;
    tcp = ( struct tcphdr*)tcp_header;
    
    printf("Protocol TCP.\n\n");
    printf("TCP Packet found, Sniffing...\n\n");
    
    //Print Tcp Header info
    printf("Source Port:                  %d\n", tcp->th_sport);
    printf("Destination Port:             %d\n", tcp->th_dport);
    printf("Sequence Number:              %d\n", tcp->th_seq);
    printf("Acknowledgement Number:       %d\n", tcp->th_ack);
    printf("Data Offset:                  %d\n", tcp->th_off);
    printf("Window:                       %d\n", tcp->th_win);
    printf("Checksum:                     %d\n", tcp->th_sum);
    printf("Urgenet Pointer:              %d\n\n", tcp->th_urp);
    
    
    //Payload is after TCP header, ie after all headers..
    payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;
    //Payload length is total length of packet - total length  of all headers.
    payload_length =  packet_header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload pointer at: %p, Payload length: %d\n", payload, payload_length);
    
    //Print payload in Hexdecimal form.
    if(payload_length>0){
        printf("Now reading Payload.....\n");
        temp = payload;
        for(i=0; i<=payload_length;i++){
            if(i%16 == 0)
                printf("\n     ");
            printf("%x ", *temp);
            temp++;
        }        
    }
    printf("\n\n#############################################################################################################\n\n");
}

