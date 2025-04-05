# CS425 - Assignment 3: TCP Handshake Client

This assignment implements the client-side of a simplified TCP three-way handshake using raw sockets in C++.


## Objective: ##

The goal was to manually construct and send TCP packets (SYN, ACK) and receive/parse the server's SYN-ACK response to establish a connection according to the sequence numbers specified in the assignment description and implied by the provided `server.cpp`[cite: 2, 5].

## Files: ##

* `client.cpp`: The C++ source code for the TCP handshake client[cite: 14].
* `server.cpp`: The provided server code (for reference and testing)[cite: 3].
* `Makefile`: Makefile to compile both client and server[cite: 21].
* `README.md`: This file[cite: 15].

### How to Compile: ###

1.  Make sure you have a C++ compiler (like g++) installed.
2.  Navigate to the directory containing the `Makefile`, `client.cpp`, and `server.cpp`.
3.  Run the following command in the terminal:
    ```bash
    make -f Makefile.txt
    ```
    This will compile both `client.cpp` and `server.cpp` using the provided `Makefile`, creating executables named `client` and `server`[cite: 21].

### How to Run: ###

1.  **Start the Server:** Open a terminal window, navigate to the assignment directory, and run:
    ```bash
    sudo ./server
    ```
    The server will start listening on port 12345 [cite: server.cpp].

2.  **Run the Client:** Open another terminal window, navigate to the assignment directory, and run:
    ```bash
    sudo ./client
    ```
   **Note:** Running the server and client typically requires `sudo` or root privileges because creating raw sockets is a privileged operation on most systems.

3.  **Observe Output:**
    * The server terminal will show messages when it receives the SYN, sends the SYN-ACK, and receives the final ACK.
    * The client terminal will show messages indicating it's sending SYN, receiving SYN-ACK, and sending the final ACK, ultimately confirming the handshake completion.

## Code Explanation: ##

The `client.cpp` program implements the client-side logic for a simplified TCP three-way handshake using raw sockets, adhering to the specific sequence numbers required by the assignment [cite: 10] and interacting with the provided `server.cpp`.

1. ### Headers and Constants: ###
* Includes necessary C++ standard library headers (`iostream`, `cstring`, `cstdlib`, `random`) and network-specific headers (`sys/socket.h`, `netinet/ip.h`, `netinet/tcp.h`, `arpa/inet.h`, `unistd.h`).
* Defines constants for the server's IP address (`127.0.0.1`), port (`12345` [cite: server.cpp]), and the specific sequence/acknowledgment numbers required for the handshake steps: `CLIENT_SEQ_SYN=200` [cite: 6, 10, server.cpp], `SERVER_EXPECTED_SEQ_SYN_ACK=400` [cite: 7, server.cpp], `CLIENT_EXPECTED_ACK_SYN_ACK=201` [cite: 7, server.cpp], and `CLIENT_SEQ_ACK=600` [cite: 8, 10, server.cpp].

2.   ### Checksum Calculation: ### 
* Includes a `struct pseudo_header` definition. This structure is essential for calculating the TCP checksum, as TCP's checksum computation includes fields from the IP header (source/destination addresses, protocol) and the TCP segment length, not just the TCP header itself.
* Implements the `csum` function, a standard internet checksum algorithm. It calculates the 16-bit one's complement of the one's complement sum of the data (including the pseudo-header and TCP header).

3.   ## Raw Socket Creation: ###
* `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` creates an IPv4 raw socket that operates directly at the IP layer but filters for TCP protocol packets when receiving. This allows manual construction of IP and TCP headers[cite: 4].
* Error handling checks if socket creation was successful.

4.   ### `IP_HDRINCL` Socket Option: ###
* `setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))` sets the `IP_HDRINCL` option on the socket. This crucial step informs the kernel that the application will provide the complete IP header for outgoing packets, rather than having the kernel construct it[cite: 4].

5.   ### Server Address Configuration: ### 
* A `struct sockaddr_in` named `server_addr` is populated with the server's address family (`AF_INET`), IP address (`SERVER_IP`), and port (`SERVER_PORT`).

6.   ### Packet Buffer: ###
* A character array `packet` is allocated to hold the raw bytes of the outgoing IP and TCP headers. Its size is calculated as `sizeof(struct iphdr) + sizeof(struct tcphdr)`.
* Another buffer `buffer` is allocated for receiving incoming packets.

7.   ### Random Number Generation: ###
* Uses C++ `<random>` library features (`std::random_device`, `std::mt19937`, `std::uniform_int_distribution`) to generate less predictable ephemeral source ports and IP identification numbers for outgoing packets.

8.   ### SYN Packet Construction and Sending: ### 
* The `packet` buffer is zeroed using `memset`.
* Pointers (`ip_header`, `tcp_header`) are set to the beginning of the buffer and the position immediately after the IP header, respectively.
* **IP Header:**  Fields like version (IPv4), header length (IHL=5), total length, a random ID, TTL, protocol (TCP), source IP (localhost), and destination IP are populated. The IP checksum (`ip_header->check`) is set to 0, relying on the kernel to compute it since `IP_HDRINCL` is set.
* **TCP Header:**  Fields are set for the SYN packet:
    * `source`: A random ephemeral port.
    * `dest`: The server's port (`SERVER_PORT`).
    * `seq`: The required initial sequence number (`CLIENT_SEQ_SYN=200`) [cite: 6, 10, server.cpp].
    * `ack_seq`: 0 (as this is the initial packet).
    * `doff`: Data offset (header length in 32-bit words, 5 for a 20-byte header).
    * Flags: `syn=1`, `ack=0`[cite: 6]. Other flags (FIN, RST, PSH, URG) are 0.
    * `window`: A typical window size.
    * `check`: Set to 0 initially before calculation.
*  **TCP Checksum:**  The checksum is calculated using the `csum` function on a temporary buffer (`pseudogram`) containing the pseudo-header followed by the TCP header. The result is stored in `tcp_header->check`.
* ##Sending:## `sendto()` is used to send the constructed packet (IP header + TCP header) to the server's address.

9.  ### Receiving and Parsing SYN-ACK:###
* The client enters a `while(true)` loop, waiting to receive packets using `recvfrom()`.
* Pointers `received_ip` and `received_tcp` are declared *outside* this loop's validation `if` block but *inside* the loop to ensure correct scope after the loop breaks. They are initially null.
* Inside the loop, after `recvfrom`, these pointers are assigned to the start of the IP header and the calculated start of the TCP header within the received `buffer`.
* **Packet Filtering:** A check ensures the received packet is from the expected server IP (`received_ip->saddr == server_addr.sin_addr.s_addr`) and is destined for the client's ephemeral source port (`ntohs(received_tcp->dest) == ntohs(tcp_header->source)`). This prevents processing unrelated packets.
* **SYN-ACK Validation:** If the packet passes the filter, the TCP flags and sequence numbers are checked: `syn=1`, `ack=1`, `seq=SERVER_EXPECTED_SEQ_SYN_ACK (400)`, and `ack_seq=CLIENT_EXPECTED_ACK_SYN_ACK (201)` [cite: 7, server.cpp].
* If the validation passes, a confirmation message is printed, and the loop is exited using `break`. If not, it's ignored, and the loop continues.

10. ### ACK Packet Construction and Sending: ###
* This step occurs *after* the loop has successfully broken, meaning a valid SYN-ACK was received and `received_tcp` points to its header.
* The `packet` buffer is zeroed again.
* **IP Header:** Similar to the SYN packet, but with a new random IP ID.
* **TCP Header:** Fields are set for the final ACK packet:
    * `source` / `dest`: Same ports as before.
    * `seq`: The required sequence number for the ACK (`CLIENT_SEQ_ACK=600`) [cite: 8, 10, server.cpp].
    * `ack_seq`: Calculated as the server's SYN sequence number plus one (`ntohl(received_tcp->seq) + 1`), which acknowledges the SYN-ACK. This should result in 401.
    * Flags: `syn=0`, `ack=1`[cite: 8]. Other flags are 0.
* **TCP Checksum:** Recalculated for the ACK packet.
* **Sending:** `sendto()` sends the final ACK packet to the server.

11. ### Completion and Cleanup: ###
* A success message is printed.
* `close(sock)` closes the raw socket, releasing the associated resources.

This detailed breakdown explains the purpose of each code section, the use of raw sockets and specific options, the manual construction of headers, the validation logic based on the assignment's requirements, and the importance of correct sequence and acknowledgment numbers throughout the TCP handshake process. Detailed comments are also present throughout the `client.cpp` code itself[cite: 12].

## Contributors and contributions ##
Ankit Kaushik (220158)- 33.33% 

Devansh Agrawal (220340) -33.33% 

Harshit Srivastava (220444)- 33.33% 