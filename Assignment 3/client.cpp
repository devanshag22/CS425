#include <iostream>     // For standard input/output operations (like cout)
#include <cstring>      // For memory manipulation functions (like memset, memcpy)
#include <cstdlib>      // For general utilities (like exit)
#include <sys/socket.h> // For socket programming functions (socket, setsockopt, sendto, recvfrom)
#include <netinet/ip.h> // Defines structures for IP header (struct iphdr)
#include <netinet/tcp.h> // Defines structures for TCP header (struct tcphdr)
#include <arpa/inet.h>  // For functions converting internet addresses (inet_pton, inet_addr, htons, ntohl)
#include <unistd.h>     // For POSIX operating system API (like close)

// Define the server's IP address (loopback address for local testing)
#define SERVER_IP "127.0.0.1"
// Define the server's port number the client will connect to
#define SERVER_PORT 12345

// Structure for TCP pseudo-header, used for checksum calculation.
// The TCP checksum calculation involves parts of the IP header.
struct pseudo_header {
    unsigned int src_addr;   // Source IP address
    unsigned int dst_addr;   // Destination IP address
    unsigned char placeholder; // Reserved, must be 0
    unsigned char protocol;    // Protocol (IPPROTO_TCP)
    unsigned short tcp_length;  // Length of the TCP segment (header + data)
};

/**
 * @brief Calculates the Internet Checksum (RFC 1071).
 *
 * This function computes the 16-bit one's complement of the one's complement sum
 * of the data. It's used for both IP and TCP checksums, though TCP also requires
 * a pseudo-header.
 *
 * @param ptr Pointer to the data buffer over which to calculate the checksum.
 * @param nbytes The number of bytes in the data buffer.
 * @return The calculated 16-bit checksum.
 */
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;              // Use long to avoid overflow during summation
    unsigned short oddbyte;    // Holds the byte if nbytes is odd

    // Sum 16-bit words
    while (nbytes > 1) {
        sum += *ptr++;          // Add the current 16-bit word and move pointer
        nbytes -= 2;          // Decrement byte count by 2
    }

    // If there's an odd byte left at the end
    if (nbytes == 1) {
        oddbyte = 0;            // Initialize oddbyte
        // Copy the last byte into the low-order byte of oddbyte (endian-neutral)
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;         // Add the last byte
    }

    // Fold the 32-bit sum into 16 bits by adding the upper 16 bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    // Add any carry that might have resulted from the folding
    sum += (sum >> 16);
    // Take the one's complement of the final sum
    return (unsigned short)(~sum);
}

/**
 * @brief Constructs and sends the initial SYN packet to the server.
 *
 * @param sock The raw socket file descriptor.
 * @param server_addr Pointer to the sockaddr_in structure containing the server's address.
 */
void send_syn(int sock, struct sockaddr_in *server_addr) {
    // Buffer to hold the entire packet (IP header + TCP header)
    // Size 4096 is large enough, actual packet is smaller.
    char packet[4096];
    // Zero out the packet buffer to ensure no garbage data
    memset(packet, 0, sizeof(packet));

    // Pointer to the beginning of the buffer, cast to IP header structure
    struct iphdr *ip = (struct iphdr *)packet;
    // Pointer to the position right after the IP header, cast to TCP header structure
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // --- Fill in the IP Header ---
    ip->ihl = 5;          // Internet Header Length (in 32-bit words, 5 * 4 = 20 bytes)
    ip->version = 4;      // IPv4
    ip->tos = 0;          // Type of Service (usually 0)
    // Total Length of the packet (IP header + TCP header) in bytes. Use htons to convert to network byte order.
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321); // Identification field (can be arbitrary, here fixed for simplicity)
    ip->frag_off = 0;     // Fragment Offset (no fragmentation)
    ip->ttl = 64;         // Time To Live (common default)
    ip->protocol = IPPROTO_TCP; // Protocol is TCP
    // Source IP address (using loopback for client)
    ip->saddr = inet_addr("127.0.0.1");
    // Destination IP address (from server_addr structure)
    ip->daddr = server_addr->sin_addr.s_addr;
    // IP Checksum: Set to 0. When IP_HDRINCL is set, the kernel computes this if set to 0.
    ip->check = 0;

    // --- Fill in the TCP Header (for SYN packet) ---
    tcp->source = htons(54321);  // Source port (arbitrary ephemeral port, fixed here)
    tcp->dest = htons(SERVER_PORT); // Destination port (server's listening port)
    // Sequence Number: Initial Sequence Number (ISN) required by assignment [cite: 6, 10, server.cpp]
    tcp->seq = htonl(200);
    tcp->ack_seq = 0;      // Acknowledgment Number (0 in the first SYN packet)
    tcp->doff = 5;         // Data Offset (TCP header length in 32-bit words, 5 * 4 = 20 bytes)
    tcp->syn = 1;          // SYN flag set to 1 to initiate connection
    tcp->ack = 0;          // ACK flag is 0
    tcp->fin = 0;          // FIN flag is 0
    tcp->rst = 0;          // RST flag is 0
    tcp->psh = 0;          // PSH flag is 0
    tcp->urg = 0;          // URG flag is 0
    tcp->window = htons(8192); // TCP window size (advertised window)
    tcp->check = 0;        // Checksum: Set to 0 initially, will be calculated next.
    tcp->urg_ptr = 0;      // Urgent pointer (not used)

    // --- Calculate TCP Checksum ---
    // Create the pseudo-header needed for TCP checksum calculation
    struct pseudo_header psh;
    psh.src_addr = ip->saddr;       // Source IP from IP header
    psh.dst_addr = ip->daddr;       // Destination IP from IP header
    psh.placeholder = 0;            // Reserved field
    psh.protocol = IPPROTO_TCP;     // Protocol (TCP)
    // TCP Length (header size only, as there's no data)
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Create a temporary buffer to hold the pseudo-header and TCP header for checksumming
    char checksum_buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    // Copy pseudo-header into the buffer
    memcpy(checksum_buf, &psh, sizeof(struct pseudo_header));
    // Copy the actual TCP header into the buffer, right after the pseudo-header
    memcpy(checksum_buf + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    // Calculate the checksum over the combined pseudo-header and TCP header
    // The size is the sum of their sizes.
    tcp->check = checksum((unsigned short *)checksum_buf, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

    // --- Send the packet ---
    // Use sendto() for raw sockets, providing destination address details.
    // The packet size is the IP header size + TCP header size.
    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        // Error handling if sendto fails
        perror("sendto() failed for SYN");
    } else {
        // Confirmation message
        std::cout << "[+] Sent SYN (Seq=200)" << std::endl;
    }
}

/**
 * @brief Waits to receive the server's SYN-ACK, validates it, and sends the final ACK.
 *
 * @param sock The raw socket file descriptor.
 * @param server_addr Pointer to the sockaddr_in structure containing the server's address (used for sending ACK).
 */
void receive_syn_ack_and_send_ack(int sock, struct sockaddr_in *server_addr) {
    // Buffer to receive incoming packets (large enough for typical MTU)
    char buffer[65536];
    // Structure to hold the source address of the received packet
    struct sockaddr_in source_addr;
    // Length of the source address structure
    socklen_t addr_len = sizeof(source_addr);

    // Loop indefinitely until the correct SYN-ACK is received
    while (true) {
        // Receive a packet from the raw socket
        // Note: recvfrom on raw sockets receives the full IP packet including the IP header.
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&source_addr, &addr_len);
        // Check for errors during reception
        if (data_size < 0) {
            perror("recvfrom() failed");
            continue; // Try receiving again
        }

        // --- Parse the received packet ---
        // Pointer to the IP header at the beginning of the buffer
        struct iphdr *ip = (struct iphdr *)buffer;
        // Calculate the start of the TCP header: buffer start + IP header length (ip->ihl * 4 bytes)
        struct tcphdr *tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));

        // --- Filter the packet ---
        // Check if the packet came from the expected server port and is destined for our client port
        // ntohs converts network byte order (used in packet) to host byte order for comparison.
        if (ntohs(tcp->source) != SERVER_PORT || ntohs(tcp->dest) != 54321) {
            // If ports don't match, ignore the packet and wait for the next one
            continue;
        }

        // --- Validate SYN-ACK ---
        // Check for the expected flags (SYN=1, ACK=1) and sequence/acknowledgment numbers [cite: 7, server.cpp]
        // ntohl converts 32-bit network byte order to host byte order.
        if (tcp->syn == 1 && tcp->ack == 1 && ntohl(tcp->seq) == 400 && ntohl(tcp->ack_seq) == 201) {
            // If it's the expected SYN-ACK, print confirmation
            std::cout << "[+] Received SYN-ACK (Seq=400, Ack=201)" << std::endl;

            // --- Prepare and send the final ACK ---
            // Buffer for the outgoing ACK packet
            char packet[4096];
            memset(packet, 0, sizeof(packet)); // Zero out the buffer

            // Pointers for IP and TCP headers in the outgoing packet buffer
            struct iphdr *ip_resp = (struct iphdr *)packet;
            struct tcphdr *tcp_resp = (struct tcphdr *)(packet + sizeof(struct iphdr));

            // --- Fill IP Header for ACK ---
            ip_resp->ihl = 5;
            ip_resp->version = 4;
            ip_resp->tos = 0;
            ip_resp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip_resp->id = htons(12345); // Different ID for this packet
            ip_resp->frag_off = 0;
            ip_resp->ttl = 64;
            ip_resp->protocol = IPPROTO_TCP;
            ip_resp->saddr = inet_addr("127.0.0.1"); // Client's IP
            ip_resp->daddr = server_addr->sin_addr.s_addr; // Server's IP
            ip_resp->check = 0; // Kernel will calculate

            // --- Fill TCP Header for ACK ---
            tcp_resp->source = htons(54321); // Client's port
            tcp_resp->dest = htons(SERVER_PORT); // Server's port
            // Sequence number for this ACK packet as required by assignment [cite: 8, 10, server.cpp]
            tcp_resp->seq = htonl(600);
            // Acknowledgment number: Received server sequence number (400) + 1
            tcp_resp->ack_seq = htonl(ntohl(tcp->seq) + 1); // Should be 401
            tcp_resp->doff = 5; // Header length
            tcp_resp->ack = 1;  // ACK flag is set
            tcp_resp->syn = 0;  // SYN is not set
            tcp_resp->fin = 0;
            tcp_resp->rst = 0;
            tcp_resp->psh = 0;
            tcp_resp->urg = 0;
            tcp_resp->window = htons(8192); // Window size
            tcp_resp->check = 0; // Checksum to be calculated
            tcp_resp->urg_ptr = 0;

            // --- Calculate TCP Checksum for ACK ---
            struct pseudo_header psh_ack;
            psh_ack.src_addr = ip_resp->saddr;
            psh_ack.dst_addr = ip_resp->daddr;
            psh_ack.placeholder = 0;
            psh_ack.protocol = IPPROTO_TCP;
            psh_ack.tcp_length = htons(sizeof(struct tcphdr));

            char checksum_buf_ack[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
            memcpy(checksum_buf_ack, &psh_ack, sizeof(struct pseudo_header));
            memcpy(checksum_buf_ack + sizeof(struct pseudo_header), tcp_resp, sizeof(struct tcphdr));

            tcp_resp->check = checksum((unsigned short *)checksum_buf_ack, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

            // --- Send the final ACK ---
            if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                       (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
                perror("sendto() failed for ACK");
            } else {
                std::cout << "[+] Sent final ACK (Seq=600, Ack=401). Handshake complete!" << std::endl;
            }

            // Handshake complete, break out of the receive loop
            break;
        }
        // If the packet wasn't the expected SYN-ACK, the loop continues to receive the next packet.
    }
}

/**
 * @brief Main function: Sets up the raw socket and orchestrates the handshake.
 */
int main() {
    int sock; // File descriptor for the raw socket

    // --- Create Raw Socket ---
    // AF_INET: Address family IPv4
    // SOCK_RAW: Raw socket type
    // IPPROTO_TCP: Only receive TCP packets (at the IP layer)
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        // Error handling if socket creation fails (requires root privileges)
        perror("Raw socket creation failed (requires root privileges)");
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] Raw socket created." << std::endl;


    // --- Set IP_HDRINCL Socket Option ---
    // This option tells the kernel that we will provide the IP header ourselves.
    int one = 1; // Value '1' enables the option
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        // Error handling if setting the option fails
        perror("setsockopt(IP_HDRINCL) failed");
        close(sock); // Close the socket before exiting
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] IP_HDRINCL option set." << std::endl;


    // --- Configure Server Address ---
    struct sockaddr_in server_addr; // Structure to hold server address info
    server_addr.sin_family = AF_INET; // Address family IPv4
    // Set server port, converting to network byte order
    server_addr.sin_port = htons(SERVER_PORT);
    // Convert the server IP string to binary network format
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // --- Execute Handshake Steps ---
    // 1. Send the initial SYN packet
    send_syn(sock, &server_addr);
    // 2. Wait for SYN-ACK and send the final ACK
    receive_syn_ack_and_send_ack(sock, &server_addr);

    // --- Cleanup ---
    // Close the socket file descriptor
    close(sock);
    std::cout << "[+] Socket closed." << std::endl;

    return 0; // Indicate successful execution
}