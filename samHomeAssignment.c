#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>

#define ROK 0
#define RFAILED -1
#define FALSE 0
#define TRUE 1

#define DNS_PORT 53
#define DNS_MSG_SIZE 4096 /* DNS packet is usually 512 bytes but if EDNS is supported need max of 4096 */
#define ETHERNET_HEADER_SIZE 14
#define LINUX_CAP_SIZE 2
#define LINUX_ETHERNET_HDR ETHERNET_HEADER_SIZE + LINUX_CAP_SIZE /* Linux Cooked Capture Header */
#define DNS_HDR_SIZE 12
#define DNS_TYPE_A_IPV4 1
#define DNS_TYPE_AAAA_IPV6 28
#define DNS_TYPE_CNAME 5
#define BUFFER_SIZE 256
#define IP_HEADER_WORD_SIZE 4
#define SLL_V1_HDR_SIZE 16
#define SLL_V2_HDR_SIZE 20


#ifdef DEBUG_PRINT
void print_dns_header_offset(const uint8_t* packet, uint32_t link_layer_offset)
{
    uint16_t ethertype = ntohs(*(uint16_t*)(packet + link_layer_offset - 2));
    uint32_t ip_header_len;
    uint32_t udp_header_offset;
    uint32_t dns_header_offset;

    if (ethertype == 0x0800)
    {
        struct ip* ip_header = (struct ip*)(packet + link_layer_offset);
        ip_header_len = ip_header->ip_hl * 4;
        udp_header_offset = link_layer_offset + ip_header_len;
        dns_header_offset = udp_header_offset + sizeof(struct udphdr);

        printf("[AHDEBUG] IPv4 detected:\n");
        printf("[AHDEBUG] - IP header length: %u bytes\n", ip_header_len);
        printf("[AHDEBUG] - UDP header offset: %u\n", udp_header_offset);
        printf("[AHDEBUG] - DNS header offset: %u\n", dns_header_offset);
        printf("[AHDEBUG] - Expected QR Bit location: udp[%u]\n", dns_header_offset - udp_header_offset + 10);
    }
    else if (ethertype == 0x86DD) {  // IPv6
        struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + link_layer_offset);
        ip_header_len = 40;  // IPv6 fixed header size (לא כולל Extension Headers)
        udp_header_offset = link_layer_offset + ip_header_len;
        dns_header_offset = udp_header_offset + sizeof(struct udphdr);

        printf("[AHDEBUG] IPv6 detected:\n");
        printf("[AHDEBUG] - IP header length: %u bytes (לא כולל Extension Headers)\n", ip_header_len);
        printf("[AHDEBUG] - UDP header offset: %u\n", udp_header_offset);
        printf("[AHDEBUG] - DNS header offset: %u\n", dns_header_offset);
        printf("[AHDEBUG] - Expected QR Bit location: udp[%u]\n", dns_header_offset - udp_header_offset + 10);
    }
    else {
        printf("[AHDEBUG] Unknown Ethertype: 0x%X\n", ethertype);
    }
    uint32_t dns_header_offset2 = udp_header_offset + sizeof(struct udphdr);
    uint8_t flags = packet[dns_header_offset2 + 2];
    printf("[AHDEBUG] !!!!!!!!!!! DNS Flags Byte: 0x%02X (QR Bit: %d)\n", flags, (flags & 0x80) >> 7);
}
#endif

/**
 * Prints the extracted DNS results, including the domain name,
 * IPv4 addresses, IPv6 addresses, and CNAME records.
 *
 * @param domain The extracted domain name.
 * @param listIpv4 List of IPv4 addresses resolved.
 * @param listIpv6 List of IPv6 addresses resolved.
 * @param listCname List of CNAME records resolved.
 */
void print_dns_results(const char* domain, const char* listIpv4, const char* listIpv6, const char* listCname)
{
    printf("\nDomain: %s\n", domain);
    if (strlen(listIpv4) > 0)
        printf("<List of IPv4 Addresses>:\n%s", listIpv4);
    if (strlen(listIpv6) > 0)
        printf("<List of IPv6 Addresses>:\n%s", listIpv6);
    if (strlen(listCname) > 0)
        printf("<List of CNAME Records>:\n%s", listCname);
}

/**
 * This function extracts the domain name from a DNS response payload. 
 * It handles also domain name compression.
 *
 * @param dns_data The DNS response payload.
 * @param offset The starting position to extract the domain name.
 * @param domain pointer to a buffer where the domain name will be stored.
 * @param domain_size The size of the domain buffer.
 *
 * @return The new offset after extracting the domain name.
 */
int extract_domain_name(const uint8_t* dns_data, int offset, char* domain, size_t domain_size)
{
    int pos = 0;
    while (dns_data[offset] != 0)
    {
        if ((dns_data[offset] & 0xC0) == 0xC0) // Compression case
        {
            int new_offset = ((dns_data[offset] & 0x3F) << 8) | dns_data[offset + 1];
            extract_domain_name(dns_data, new_offset, domain + pos, domain_size - pos);
            return offset + 2;
        }
        int len = dns_data[offset];
        memcpy(domain + pos, dns_data + offset + 1, len);
        pos += len;
        domain[pos++] = '.';
        offset += len + 1;
    }
    domain[pos - 1] = '\0';
    return offset + 1;
}

/**
 * This function handles the DNS response packet captured extract the domain name and stores 
 *  domain names, IPv4/IPv6/CNAME. 
 *
 * @param packet The raw DNS packet.
 * @param size The size of the packet captured.
 */
void process_dns_response(const uint8_t* packet, uint32_t size)
{
    uint32_t link_layer_offset;
    char listIpv4[BUFFER_SIZE] = "";
    char listIpv6[BUFFER_SIZE] = "";
    char listCname[BUFFER_SIZE] = "";
    const uint8_t* dns_data = NULL;
    uint32_t ip_header_len;

    uint16_t ethertype_v1 = ntohs(*(uint16_t*)(packet + SLL_V1_HDR_SIZE - 2));
    uint16_t ethertype_v2 = ntohs(*(uint16_t*)(packet + SLL_V2_HDR_SIZE - 2));
    if (ethertype_v1 == 0x0800 || ethertype_v1 == 0x86DD)
    {
        link_layer_offset = SLL_V1_HDR_SIZE;
    }
    else if (ethertype_v2 == 0x0800 || ethertype_v2 == 0x86DD)
    {
        link_layer_offset = SLL_V2_HDR_SIZE;
    }
    else 
    {
        link_layer_offset = ETHERNET_HEADER_SIZE;
    }

    uint16_t ethertype = ntohs(*(uint16_t*)(packet + link_layer_offset - 2));
    
    struct ip* ip_header = (struct ip*)(packet + link_layer_offset);
    if (ethertype == 0x0800)   // IPv4
    {
        ip_header_len = ip_header->ip_hl * IP_HEADER_WORD_SIZE;
    }
    else if (ethertype == 0x86DD)  // IPv6
    {
        ip_header_len = 40;  // Fixed IPv6 header size
    }

#ifdef DEBUG_PRINT
    print_dns_header_offset(packet, link_layer_offset);
#endif
    struct udphdr* udp_header = (struct udphdr*)(packet + link_layer_offset + ip_header_len);
    dns_data = (uint8_t*)(udp_header + 1);
    uint32_t dns_msg_size = size - (link_layer_offset + ip_header_len + sizeof(struct udphdr));

    //it should be only port 53, as we filtered port 53 only but no harm in verifying it here also. 
    // chekcing the size to make sure we dont handle empty response
    if (ntohs(udp_header->uh_sport) == DNS_PORT && dns_msg_size > DNS_HDR_SIZE)
    {
        char domain[256];
        uint8_t nonEmptyRsp = FALSE;
        int offset = extract_domain_name(dns_data, DNS_HDR_SIZE, domain, sizeof(domain));

        int answer_count = ntohs(*(uint16_t*)(dns_data + 6));
        offset += 4; //skip QTYPE + QCLASS
        for (int i = 0; i < answer_count && offset < dns_msg_size; i++)
        {
            offset = extract_domain_name(dns_data, offset, domain, sizeof(domain));
            uint16_t type = ntohs(*(uint16_t*)(dns_data + offset));
            uint16_t rdlength = ntohs(*(uint16_t*)(dns_data + offset + 8));
            offset += 10; // Skip TYPE, CLASS, TTL, RDLENGTH

            if (type == DNS_TYPE_A_IPV4 && rdlength == 4)
            {
                char ipv4[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, dns_data + offset, ipv4, INET_ADDRSTRLEN);
                strcat(listIpv4, ipv4);
                strcat(listIpv4, "\n");
                nonEmptyRsp = TRUE;
            }
            else if (type == DNS_TYPE_AAAA_IPV6 && rdlength == 16)
            {
                char ipv6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, dns_data + offset, ipv6, INET6_ADDRSTRLEN);
                strcat(listIpv6, ipv6);
                strcat(listIpv6, "\n");
                nonEmptyRsp = TRUE;
            }
            else if (type == DNS_TYPE_CNAME)
            {
                char cname[256];
                extract_domain_name(dns_data, offset, cname, sizeof(cname));
                strcat(listCname, cname);
                strcat(listCname, "\n");
                nonEmptyRsp = TRUE;
            }
            else
            {
                printf("unsupported TYPE: %d\n", type);
            }
            offset += rdlength;
        }
        if (nonEmptyRsp)
        {
            print_dns_results(domain, listIpv4, listIpv6, listCname);
        }
    }
}

/**
 * This function is called by pcap_dispatch to process each packet captured from
 * the network. It calls the `process_dns_response` function to extract and process
 * DNS response data.
 *
 * @param args not used, mandatory due to pcap_dispatch usage
 * @param header The pcap header containing metadata about the packet.
 * @param packet The packet captured.
 */
void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    process_dns_response(packet, header->len);
}
/**
 * This function initializes the packet capture, applies the filter for DNS responses,
 * and continuously captures packets. exits only if there is a failure.
 */
int main()
{
    printf("Starting application for sniffing DNS packets, please wait.\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("any", DNS_MSG_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "ERROR:pcap_open_live() Failed to open %s\n", errbuf);
        return RFAILED;
    }

    struct bpf_program filter;
    char filter_exp[] = "(udp src port 53 and ip and udp[10] & 0x80 != 0) or (udp src port 53 and ip6)";
    //char filter_exp[] = "(udp src port 53)";// making sure we are capture DNR response only and not request. so check the QR flag set to 1. 
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "ERROR:pcap_compile() Could not parse filter: %s\n", pcap_geterr(handle));
        return RFAILED;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "ERROR:pcap_setfilter() Could not set filter: %s\n", pcap_geterr(handle));
        return RFAILED;
    }

    while (1)
    {
        if (pcap_dispatch(handle, -1, packet_handler, NULL) == -1)
        {
            fprintf(stderr, "ERROR:pcap_dispatch() Failed to capture packets: %s\n", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
    return ROK;
}


