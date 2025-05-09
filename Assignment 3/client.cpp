#include <iostream>         
#include <cstring>          
#include <arpa/inet.h>      // For network address conversion functions 
#include <netinet/ip.h>     // Defines the iphdr structure for IPv4 headers
#include <netinet/tcp.h>    // Defines the tcphdr structure for TCP headers
#include <sys/socket.h>     // For socket-related functions and constants 
#include <unistd.h>         // For close() function to release socket resources
#include <netdb.h>          // For network database operations (though not heavily used here)
#include <errno.h>          // For error number definitions and strerror()

// Pseudo-header for TCP checksum calculation.
// This is needed because the TCP checksum covers parts of the IP header as well.
struct pseudo_header {
    uint32_t source_address; // Source IP address (32 bits)
    uint32_t dest_address;   // Destination IP address (32 bits)
    uint8_t placeholder;     // Placeholder (set to 0, reserved for future use)
    uint8_t protocol;        // Protocol type (6 for TCP)
    uint16_t tcp_length;     // Length of the TCP header (and data, if any)
};

// Function to compute the TCP checksum
// This implements a simplified 1's complement sum as required by TCP

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    // Step 1: Create a raw socket for TCP packets
    // AF_INET specifies IPv4, SOCK_RAW allows manual packet construction,
    // IPPROTO_TCP filters for TCP packets

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
        return 1;
    }

    // Enable manual IP header construction
    // IP_HDRINCL tells the kernel to let the application set the IP header

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Error setting IP_HDRINCL: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }

    // Server address (localhost:12345 as per server.cpp)
    // Using localhost (127.0.0.1) for local testing

    const char *server_ip = "127.0.0.1";
    const int server_port = 12345;
    const int client_port = 54321; // Arbitrary client port

   
    // Set up destination address structure
    // sockaddr_in is used for IPv4 socket addresses

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &dest_addr.sin_addr);

    // Buffer for constructing the packet
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    // IP header setup (minimal, as we focus on TCP)
    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;           // Header length (5 words = 20 bytes)
    iph->version = 4;       // IPv4
    iph->tos = 0;           // Type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321); // Arbitrary packet ID
    iph->frag_off = 0;      // No fragmentation
    iph->ttl = 255;         // Time to live
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;         // Kernel fills this
    iph->saddr = inet_addr("127.0.0.1"); // Client IP
    iph->daddr = dest_addr.sin_addr.s_addr; // Server IP

    // TCP header setup for SYN packet
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    tcph->source = htons(client_port);
    tcph->dest = htons(server_port);
    tcph->seq = htonl(200); // Initial sequence number as per server expectation
    tcph->ack_seq = 0;       // No ACK yet (SYN only)
    tcph->doff = 5;         // Data offset (5 words = 20 bytes)
    tcph->fin = 0;          // Finish flag (not set)
    tcph->syn = 1;          // SYN flag set for handshake initiation
    tcph->rst = 0;          // Reset flag (not set)
    tcph->psh = 0;          // Push flag (not set)
    tcph->ack = 0;          // ACK flag (not set)
    tcph->urg = 0;          // Urgent flag (not set)
    tcph->window = htons(5840); // Receive window size (arbitrary value)
    tcph->check = 0;        // To be computed
    tcph->urg_ptr = 0;      // Urgent pointer (not used)

    // Pseudo-header for TCP checksum
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Compute TCP checksum
    char checksum_buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(checksum_buf, &psh, sizeof(struct pseudo_header));
    memcpy(checksum_buf + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(checksum_buf, sizeof(checksum_buf));

    // Send SYN packet to server
    std::cout << "Sending SYN packet (seq=200)..." << std::endl;
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        std::cerr << "Error sending SYN: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }

    // Step 2: Receive SYN-ACK from server

    char recv_buf[4096];                 // Buffer for received packet
    struct sockaddr_in src_addr;         // Source address of received packet
    socklen_t addr_len = sizeof(src_addr);   // Length of source address structure
    std::cout << "Waiting for SYN-ACK..." << std::endl;
    while (true) {
        int len = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&src_addr, &addr_len);
        if (len < 0) {
            std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
            close(sock);
            return 1;
        }

        // Parse received packet
        struct iphdr *recv_iph = (struct iphdr *)recv_buf;
        struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buf + (recv_iph->ihl * 4));
        if (recv_tcph->dest == htons(client_port) && recv_tcph->syn == 1 && recv_tcph->ack == 1) {
            uint32_t server_seq = ntohl(recv_tcph->seq);
            uint32_t expected_ack = ntohl(recv_tcph->ack_seq);
            std::cout << "Received SYN-ACK: server_seq=" << server_seq << ", ack_seq=" << expected_ack << std::endl;
            if (server_seq == 400 && expected_ack == 201) { // Server’s expected response
                // Step 3: Send ACK packet
                tcph->seq = htonl(600); // Client's next sequence (from log)
                tcph->ack_seq = htonl(server_seq + 1); // Acknowledge server_seq + 1 = 401
                tcph->syn = 0;      // Clear SYN flag
                tcph->ack = 1;      // ACK flag set
                tcph->check = 0;    // Reset checksum for recalculation

                // Recalculate checksum for ACK packet
                memcpy(checksum_buf, &psh, sizeof(struct pseudo_header));
                memcpy(checksum_buf + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
                tcph->check = checksum(checksum_buf, sizeof(checksum_buf));

                iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
                std::cout << "Sending ACK packet (seq=600, ack_seq=401)..." << std::endl;
                if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                    std::cerr << "Error sending ACK: " << strerror(errno) << std::endl;
                    close(sock);
                    return 1;
                }
                std::cout << "TCP handshake completed!" << std::endl;
                break;
            }
        }
    }

    close(sock);      // Close the socket 
    return 0;
}