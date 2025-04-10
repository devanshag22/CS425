# CS425 - Assignment 3: TCP Handshake Client

This assignment implements the client-side of a simplified TCP three-way handshake using raw sockets in C++.


## Objective: ##

The goal was to manually construct and send TCP packets (SYN, ACK) and receive/parse the server's SYN-ACK response to establish a connection according to the sequence numbers specified in the assignment description and implied by the provided `server.cpp`

## Files: ##

* `client.cpp`: The C++ source code for the TCP handshake client
* `server.cpp`: The provided server code (for reference and testing)
* `Makefile`: Makefile to compile both client and server
* `README.md`: This file contains the documentation 

### How to Compile: ###

1.  Navigate to the directory containing the `Makefile`, `client.cpp`, and `server.cpp`.
2.  Run the following command in the terminal:
    ```bash
    make
    ```
    This will compile both `client.cpp` and `server.cpp` using the provided `Makefile`, creating executables named `client` and `server`

### How to Run: ###

1.  **Start the Server:** Open a terminal window, navigate to the assignment directory, and run:
    ```bash
    sudo ./server
    ```
    The server will start listening on port 12345 

2.  **Run the Client:** Open another terminal window, navigate to the assignment directory, and run:
    ```bash
    sudo ./client
    ```
   **Note:** Running the server and client typically requires `sudo` or root privileges because creating raw sockets is a privileged operation on most systems.

3.  **Observe Output:**
    * The server terminal will show messages when it receives the SYN, sends the SYN-ACK, and receives the final ACK.
    * The client terminal will show messages indicating it's sending SYN, receiving SYN-ACK, and sending the final ACK, ultimately confirming the handshake completion.

## Code Explanation: ##

The `client.cpp` program implements the client-side logic for a simplified TCP three-way handshake using raw sockets. It manually constructs and sends IP/TCP packets, interacts with the server, and adheres to the specific sequence numbers required by the assignment [cite: 10, Assignment 3.pdf].

1.  **Headers and Constants:**
    * Includes necessary headers for C++ standard library functions (`iostream`, `cstring`, `cstdlib`) and network programming (`sys/socket.h`, `netinet/ip.h`, `netinet/tcp.h`, `arpa/inet.h`, `unistd.h`) [cite: client.cpp].
    * Defines constants for the target server's IP (`SERVER_IP`) and port (`SERVER_PORT`, which is 12345 based on the server code) [cite: client.cpp, server.cpp].

2.  **Checksum Calculation (`checksum` function):**
    * Implements the standard internet checksum algorithm required for TCP header validation [cite: client.cpp].
    * Calculates the 16-bit one's complement of the one's complement sum of the data provided (which includes a pseudo-header and the TCP header itself for TCP checksums) [cite: client.cpp].

3.  **SYN Packet Transmission (`send_syn` function):**
    * Creates a packet buffer and pointers to IP (`iphdr`) and TCP (`tcphdr`) header structures within it [cite: client.cpp].
    * **IP Header Construction:** Populates the IP header fields: version (IPv4), header length (IHL), total packet length, identification (using a fixed value 54321), TTL, protocol (TCP), source IP (localhost "127.0.0.1"), and destination IP (`SERVER_IP`) [cite: client.cpp]. The IP checksum is left to the kernel as `IP_HDRINCL` is set later.
    * **TCP Header Construction (SYN):** Populates the TCP header fields for the initial SYN packet: source port (fixed 54321), destination port (`SERVER_PORT`), sequence number (required `200`) [cite: 6, 10, client.cpp, server.cpp], acknowledgment number (0), data offset (`doff`), SYN flag set (`syn=1`) [cite: 6, client.cpp], window size, and checksum (initially 0) [cite: client.cpp].
    * **TCP Checksum Calculation:** Constructs a TCP pseudo-header (containing source/destination IP, protocol, and TCP length) and calculates the checksum over the pseudo-header and the TCP header using the `checksum` function. Stores the result in `tcp->check` [cite: client.cpp].
    * **Sending:** Uses `sendto()` to send the constructed IP/TCP packet to the server address [cite: client.cpp].

4.  **Receiving SYN-ACK and Sending ACK (`receive_syn_ack_and_send_ack` function):**
    * Enters an infinite loop (`while(true)`) to wait for incoming packets [cite: client.cpp].
    * **Receiving:** Uses `recvfrom()` to receive data into a buffer [cite: client.cpp].
    * **Packet Parsing:** Casts parts of the buffer to IP and TCP header structures (`iphdr`, `tcphdr`) [cite: client.cpp].
    * **Filtering:** Checks if the received packet is from the expected server port (`SERVER_PORT`) and destined for the client's source port (54321) [cite: client.cpp]. If not, it continues to the next iteration.
    * **SYN-ACK Validation:** Checks if the TCP flags (`syn=1`, `ack=1`), sequence number (`ntohl(tcp->seq) == 400`), and acknowledgment number (`ntohl(tcp->ack_seq) == 201`) match the expected values for a valid SYN-ACK response from the server [cite: 7, client.cpp, server.cpp].
    * **ACK Packet Construction:** If a valid SYN-ACK is received:
        * Creates a new packet buffer for the outgoing ACK [cite: client.cpp].
        * Populates the IP header similarly to the SYN packet, using a new ID (fixed 12345) [cite: client.cpp].
        * Populates the TCP header for the final ACK: source/destination ports swapped from the received packet, sequence number (required `600`) [cite: 8, 10, client.cpp, server.cpp], acknowledgment number (received SYN-ACK sequence number + 1, i.e., 400 + 1 = 401), ACK flag set (`ack=1`) [cite: 8, client.cpp].
        * Calculates the TCP checksum for the ACK packet [cite: client.cpp].
        * **Sending ACK:** Uses `sendto()` to send the final ACK packet [cite: client.cpp].
        * Prints a success message and breaks the loop [cite: client.cpp].

5.  **Main Function (`main`):**
    * **Raw Socket Creation:** Creates a raw socket using `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`. This allows building packets starting from the IP layer for the TCP protocol [cite: 4, client.cpp]. Error handling checks for failure [cite: client.cpp].
    * **`IP_HDRINCL` Option:** Sets the `IP_HDRINCL` socket option using `setsockopt()`. This tells the kernel that the application will provide the IP header itself [cite: 4, client.cpp]. Error handling is included [cite: client.cpp].
    * **Server Address Setup:** Configures a `sockaddr_in` structure (`server_addr`) with the server's IP address (`SERVER_IP`) and port (`SERVER_PORT`) [cite: client.cpp].
    * **Handshake Execution:** Calls `send_syn()` to initiate the handshake and `receive_syn_ack_and_send_ack()` to handle the rest of the process [cite: client.cpp].
    * **Cleanup:** Closes the raw socket using `close(sock)` [cite: client.cpp].

## Contributors and contributions ##
Ankit Kaushik (220158)- 33.33% 

Devansh Agrawal (220340) -33.33% 

Harshit Srivastava (220444)- 33.33% 