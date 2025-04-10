#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

// TCP checksum calculation
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_syn(int sock, struct sockaddr_in *server_addr) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1"); // spoofed client IP
    ip->daddr = server_addr->sin_addr.s_addr;

    // Fill TCP header
    tcp->source = htons(54321);  // arbitrary client port
    tcp->dest = htons(SERVER_PORT);
    tcp->seq = htonl(200);       // as expected by server
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(8192);
    tcp->check = 0;

    // Calculate TCP checksum
    struct {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    } pseudo_header;

    pseudo_header.src_addr = ip->saddr;
    pseudo_header.dst_addr = ip->daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcp, sizeof(struct tcphdr));

    tcp->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));

    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("sendto() failed");
    } else {
        std::cout << "[+] Sent SYN" << std::endl;
    }
}

void receive_syn_ack_and_send_ack(int sock, struct sockaddr_in *server_addr) {
    char buffer[65536];
    socklen_t addr_len = sizeof(*server_addr);

    while (true) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)server_addr, &addr_len);
        if (data_size < 0) {
            perror("recvfrom() failed");
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));

        if (ntohs(tcp->source) != SERVER_PORT || ntohs(tcp->dest) != 54321) continue;

        if (tcp->syn == 1 && tcp->ack == 1 && ntohl(tcp->seq) == 400 && ntohl(tcp->ack_seq) == 201) {
            std::cout << "[+] Received SYN-ACK" << std::endl;

            // Send final ACK
            char packet[4096];
            memset(packet, 0, sizeof(packet));

            struct iphdr *ip_resp = (struct iphdr *)packet;
            struct tcphdr *tcp_resp = (struct tcphdr *)(packet + sizeof(struct iphdr));

            ip_resp->ihl = 5;
            ip_resp->version = 4;
            ip_resp->tos = 0;
            ip_resp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip_resp->id = htons(12345);
            ip_resp->frag_off = 0;
            ip_resp->ttl = 64;
            ip_resp->protocol = IPPROTO_TCP;
            ip_resp->saddr = inet_addr("127.0.0.1");
            ip_resp->daddr = server_addr->sin_addr.s_addr;

            tcp_resp->source = htons(54321);
            tcp_resp->dest = htons(SERVER_PORT);
            tcp_resp->seq = htonl(600);       // as expected by server
            tcp_resp->ack_seq = htonl(401);   // server seq + 1
            tcp_resp->doff = 5;
            tcp_resp->ack = 1;
            tcp_resp->window = htons(8192);
            tcp_resp->check = 0;

            struct {
                unsigned int src_addr;
                unsigned int dst_addr;
                unsigned char placeholder;
                unsigned char protocol;
                unsigned short tcp_length;
                struct tcphdr tcp;
            } pseudo_hdr;

            pseudo_hdr.src_addr = ip_resp->saddr;
            pseudo_hdr.dst_addr = ip_resp->daddr;
            pseudo_hdr.placeholder = 0;
            pseudo_hdr.protocol = IPPROTO_TCP;
            pseudo_hdr.tcp_length = htons(sizeof(struct tcphdr));
            memcpy(&pseudo_hdr.tcp, tcp_resp, sizeof(struct tcphdr));

            tcp_resp->check = checksum((unsigned short *)&pseudo_hdr, sizeof(pseudo_hdr));

            if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                       (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
                perror("sendto() failed");
            } else {
                std::cout << "[+] Sent final ACK. Handshake complete!" << std::endl;
            }

            break;
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Raw socket creation failed");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    send_syn(sock, &server_addr);
    receive_syn_ack_and_send_ack(sock, &server_addr);

    close(sock);
    return 0;
}