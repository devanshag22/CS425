#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1" // Server IP address (localhost)
#define SERVER_PORT 12345     // Server port defined in server.cpp
#define CLIENT_SEQ_SYN 200    // Initial sequence number for SYN packet [cite: 6, server.cpp]
#define SERVER_EXPECTED_SEQ_SYN_ACK 400 // Expected sequence number in SYN-ACK from server [cite: 7, server.cpp]
#define CLIENT_EXPECTED_ACK_SYN_ACK 201 // Expected acknowledgment number in SYN-ACK (CLIENT_SEQ_SYN + 1) [cite: 7, server.cpp]
#define CLIENT_SEQ_ACK 600    // Sequence number for the final ACK packet [cite: 8, server.cpp]


/*
 * Pseudoheader struct for TCP checksum calculation.
 * The TCP checksum includes parts of the IP header (addresses, protocol)
 * and the TCP segment length.
 */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/*
 * Function to calculate the TCP checksum.
 * Uses a pseudo-header along with the TCP header and data.
 * Checksum algorithm: Sum 16-bit words, add carries, take one's complement.
 */
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

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
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}


/*
 * Prints TCP flags and sequence/ack numbers for debugging.
 */
void print_tcp_flags_client(struct tcphdr *tcp) {
    std::cout << "[+] TCP Flags Received: "
              << " SYN: " << tcp->syn
              << " ACK: " << tcp->ack
              << " FIN: " << tcp->fin
              << " RST: " << tcp->rst
              << " PSH: " << tcp->psh
              << " SEQ: " << ntohl(tcp->seq)
              << " ACK_SEQ: " << ntohl(tcp->ack_seq) << std::endl;
}


int main() {
    int sock;
    struct sockaddr_in server_addr;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)]; // Buffer for outgoing packet
    char buffer[65536]; // Buffer for incoming packet

    // --- Step 1: Create Raw Socket ---
    // SOCK_RAW: Specifies a raw socket.
    // IPPROTO_TCP: Specifies that we are interested in TCP packets at the IP level.
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] Raw socket created." << std::endl;


    // Enable IP_HDRINCL option - we will build the IP header ourselves. [cite: 4]
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] IP_HDRINCL option set." << std::endl;


    // Configure server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // --- Step 2: Construct and Send SYN Packet --- [cite: 6]
    memset(packet, 0, sizeof(packet)); // Zero out the packet buffer

    // Pointers to IP and TCP headers within the packet buffer
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill IP Header
    ip_header->ihl = 5;         // Internet Header Length (5 * 32 bits = 20 bytes)
    ip_header->version = 4;     // IPv4
    ip_header->tos = 0;         // Type of Service (usually 0)
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // Total length of IP packet
    ip_header->id = htons(rand() % 65535); // Identification field (random value)
    ip_header->frag_off = 0;    // Fragment offset (no fragmentation)
    ip_header->ttl = 64;        // Time To Live
    ip_header->protocol = IPPROTO_TCP; // Protocol (TCP)
    ip_header->check = 0;       // Checksum (will be filled by kernel or calculated later if needed, kernel handles for HDRINCL)
    ip_header->saddr = inet_addr("127.0.0.1"); // Source IP address (can be refined, using localhost for simplicity)
    ip_header->daddr = server_addr.sin_addr.s_addr; // Destination IP address


    // Fill TCP Header for SYN
    tcp_header->source = htons(rand() % 60000 + 1024); // Source Port (random ephemeral port)
    tcp_header->dest = htons(SERVER_PORT);       // Destination Port [server.cpp]
    tcp_header->seq = htonl(CLIENT_SEQ_SYN);     // Sequence Number (initial SYN sequence number) [cite: 6, 10, server.cpp]
    tcp_header->ack_seq = htonl(0);              // Acknowledgment Number (0 for initial SYN)
    tcp_header->doff = 5;                        // Data Offset (TCP header size in 32-bit words, 5 * 4 = 20 bytes)
    tcp_header->fin = 0;                         // FIN flag
    tcp_header->syn = 1;                         // SYN flag (Set for SYN packet)
    tcp_header->rst = 0;                         // RST flag
    tcp_header->psh = 0;                         // PSH flag
    tcp_header->ack = 0;                         // ACK flag (Not set for initial SYN)
    tcp_header->urg = 0;                         // URG flag
    tcp_header->window = htons(5840);            // Window size
    tcp_header->check = 0;                       // Checksum (Set to 0 initially)
    tcp_header->urg_ptr = 0;                     // Urgent Pointer


    // Calculate TCP Checksum
    struct pseudo_header psh;
    psh.source_address = ip_header->saddr;
    psh.dest_address = ip_header->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);


    // Send the SYN packet
    std::cout << "[+] Sending SYN packet (SEQ=" << CLIENT_SEQ_SYN << ") to " << SERVER_IP << ":" << SERVER_PORT << std::endl;
    if (sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto() SYN failed");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // --- Step 3: Receive and Parse SYN-ACK --- [cite: 7]
    std::cout << "[+] Waiting for SYN-ACK..." << std::endl;
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);
    int received_size = -1;

    while(true) {
        received_size = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
        if (received_size <= 0) {
            perror("recvfrom() failed or connection closed");
            close(sock);
            exit(EXIT_FAILURE);
        }

        // Extract IP and TCP headers from the received buffer
        struct iphdr *received_ip = (struct iphdr *)buffer;
        struct tcphdr *received_tcp = (struct tcphdr *)(buffer + (received_ip->ihl * 4));

        // Check if the packet is from the server and intended for our ephemeral port
        if (received_ip->saddr == server_addr.sin_addr.s_addr &&
            ntohs(received_tcp->dest) == ntohs(tcp_header->source)) // Check if dest port matches our source port
        {
             print_tcp_flags_client(received_tcp);

            // Validate SYN-ACK: Check flags, sequence number, and acknowledgment number [cite: 7, server.cpp]
            if (received_tcp->syn == 1 && received_tcp->ack == 1 &&
                ntohl(received_tcp->seq) == SERVER_EXPECTED_SEQ_SYN_ACK &&
                ntohl(received_tcp->ack_seq) == CLIENT_EXPECTED_ACK_SYN_ACK)
            {
                std::cout << "[+] Received valid SYN-ACK from server." << std::endl;
                std::cout << "    Server SEQ: " << ntohl(received_tcp->seq) << ", Server ACK_SEQ: " << ntohl(received_tcp->ack_seq) << std::endl;
                break; // Exit loop after receiving the correct SYN-ACK
            } else {
                 std::cout << "[!] Received TCP packet, but not the expected SYN-ACK. Ignoring." << std::endl;
                 // Continue listening
            }
        }
        // else: Packet not from the expected server or not for our port, ignore.
    }


    // --- Step 4: Construct and Send ACK Packet --- [cite: 8]
    memset(packet, 0, sizeof(packet)); // Zero out the packet buffer again

    // Update IP header (length, ID potentially) - most fields remain the same
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header->id = htons(rand() % 65535); // New ID for this packet

    // Update TCP Header for ACK
    tcp_header->source = tcp_header->source; // Keep the same source port used in SYN
    tcp_header->dest = htons(SERVER_PORT);   // Destination port remains the server port
    tcp_header->seq = htonl(CLIENT_SEQ_ACK); // Sequence Number for ACK packet [cite: 8, 10, server.cpp]
    tcp_header->ack_seq = htonl(ntohl(received_tcp->seq) + 1); // Acknowledge server's SYN sequence number + 1
    tcp_header->doff = 5;        // Data Offset (header size)
    tcp_header->fin = 0;
    tcp_header->syn = 0;         // SYN flag is OFF
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 1;         // ACK flag is ON
    tcp_header->urg = 0;
    tcp_header->window = htons(5840); // Window size
    tcp_header->check = 0;       // Reset checksum before recalculation
    tcp_header->urg_ptr = 0;


    // Recalculate TCP Checksum for the ACK packet
    psh.source_address = ip_header->saddr;
    psh.dest_address = ip_header->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = (char *)malloc(psize); // Reallocate or reuse buffer safely
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);


    // Send the final ACK packet
    std::cout << "[+] Sending ACK packet (SEQ=" << CLIENT_SEQ_ACK << ", ACK_SEQ=" << ntohl(tcp_header->ack_seq) << ") to " << SERVER_IP << ":" << SERVER_PORT << std::endl;
    if (sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto() ACK failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    std::cout << "[+] TCP Handshake Completed Successfully!" << std::endl;


    // --- Step 5: Cleanup ---
    close(sock); // Close the socket
    std::cout << "[+] Socket closed." << std::endl;

    return 0;
}