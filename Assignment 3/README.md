# CS425 - Assignment 3: TCP Handshake Client

This assignment implements the client-side of a simplified TCP three-way handshake using raw sockets in C++.

**Group Members:**

* Member 1 Name - Roll Number
* Member 2 Name - Roll Number (Optional)
* Member 3 Name - Roll Number (Optional)

**Objective:**

The goal was to manually construct and send TCP packets (SYN, ACK) and receive/parse the server's SYN-ACK response to establish a connection according to the sequence numbers specified in the assignment description and implied by the provided `server.cpp`[cite: 2, 5].

**Files:**

* `client.cpp`: The C++ source code for the TCP handshake client[cite: 14].
* `server.cpp`: The provided server code (for reference and testing)[cite: 3].
* `Makefile`: Makefile to compile both client and server[cite: 21].
* `README.md`: This file[cite: 15].

**How to Compile:**

1.  Make sure you have a C++ compiler (like g++) installed.
2.  Navigate to the directory containing the `Makefile`, `client.cpp`, and `server.cpp`.
3.  Run the following command in the terminal:
    ```bash
    make
    ```
    This will compile both `client.cpp` and `server.cpp` using the provided `Makefile`, creating executables named `client` and `server`[cite: 21].

**How to Run:**

1.  **Start the Server:** Open a terminal window, navigate to the assignment directory, and run:
    ```bash
    ./server
    ```
    The server will start listening on port 12345 [cite: server.cpp].

2.  **Run the Client:** Open another terminal window, navigate to the assignment directory, and run:
    ```bash
    sudo ./client
    ```
   **Note:** Running the client typically requires `sudo` or root privileges because creating raw sockets is a privileged operation on most systems.

3.  **Observe Output:**
    * The server terminal will show messages when it receives the SYN, sends the SYN-ACK, and receives the final ACK.
    * The client terminal will show messages indicating it's sending SYN, receiving SYN-ACK, and sending the final ACK, ultimately confirming the handshake completion.

**Code Explanation:**

* The client uses `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` to create a raw socket.
* `IP_HDRINCL` socket option is set to allow manual construction of the IP header[cite: 4].
* IP and TCP headers are manually populated in a character buffer (`packet`).
* **SYN Packet:** Sent with `SEQ=200`, `SYN=1`, `ACK=0` [cite: 6, 10, server.cpp].
* **SYN-ACK Handling:** The client waits for a packet from the server. It validates the incoming packet flags (`SYN=1`, `ACK=1`), sequence number (`SEQ=400`), and acknowledgment number (`ACK_SEQ=201`) [cite: 7, server.cpp].
* **ACK Packet:** Sent with `SEQ=600`, `SYN=0`, `ACK=1`, and `ACK_SEQ` set to the server's `SEQ + 1` [cite: 8, 10, server.cpp].
* TCP checksums are calculated using a pseudo-header for both SYN and ACK packets.
* Detailed comments are included in `client.cpp` explaining each step[cite: 12].