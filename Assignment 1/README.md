# Chat Server

## Assignment Features Implemented

### Implemented Features:

#### User Authentication:
- Users log in using credentials stored in `users.txt`.
- Prevents duplicate logins for the same username.

#### Multi-Client Support:
- Handles multiple clients concurrently using threads.

#### Group Management:
- Users can create, join, leave, and send messages to groups.
- Groups are dynamically created and deleted as users join/leave.

#### Messaging:
- **Private Messaging:** : Users can send private messages to specific users.
- **Group Messaging:** : Users can send messages to all members of a group.
- **Broadcast Messaging:** : Users can broadcast messages to all connected users.

#### Graceful Exit:
- Clients can disconnect from the server using the `/exit` command.

#### Commands:
- `/msg <username> <message>`: Send a private message to a user.
- `/broadcast <message>`: Broadcast a message to all connected users.
- `/group_msg <group> <message>`: Send a message to all members of a group.
- `/create_group <group>`: Create a new group.
- `/join_group <group>`: Join an existing group.
- `/leave_group <group>`: Leave a group.
- `/exit`: Disconnect from the server.

#### Thread Safety:
- Uses mutexes to protect shared data structures.
- Ensures thread-safe access to shared resources.


## Design Decisions

### 1. Thread-Per-Client Model:
- **Decision:** A new thread is created in the server for each client connection.
- **Reason:**Threads are an efficient and lightweight way to manage multiple clients simultaneously without causing blocking.

### 2. Mutex Synchronization:
- **Decision:** Used `std::mutex` to protect shared data structures like `username_to_socket`, `groups`, and `active_usernames`.
- **Reason:** Ensures thread safety when multiple threads access or modify shared resources.
   - Example:
   - Adding/removing users from groups.
   - Broadcasting messages to multiple clients.

### 3. Not updating groups when a user exits:
- **Decision:** When a user disconnects, not updating the groups they were a part of to avoid futile computation
- **Reason:** Whenever a user logs in again. He/She is remained joined in the groups he was a part of which makes it less tedious for him/her to join all groups again. 

### 4. Data Structures:
- **Decision:** Used `std::unordered_map` and `std::unordered_set` for storing users, groups, and active connections.
- **Reason:** These data structures provide **O(1)** average time complexity for lookups, insertions, and deletions, making them efficient for real-time operations.

### 5. Fixed Buffer Size:
- **Decision:** Messages are limited to `BUFFER_SIZE (1024 bytes)`.
- **Reason:** Simplifies message handling and avoids dynamic memory allocation for each message, though it restricts message size.

### 6. Command Parsing:
- **Decision:** Messages are parsed and handled based on their prefix (e.g., `/msg`, `/broadcast`, `/group_msg`).
- **Reason:** This design allows for easy extensibility to add new commands in the future and simplifies message routing.

## Implementation

### High-Level Idea of Key Functions:

#### `load_users()`
- Reads user credentials from `users.txt` at server startup.
- Populates the `users` map with username-password pairs.

#### `handle_client_messages()`
- Manages client authentication and command processing.
- Continuously listens for incoming messages from the client and processes them.

### Command Handlers:
- `handle_create_group()`: Creates a new group and adds the user as the first member.
- `handle_join_group()`: Adds a user to an existing group.
- `handle_group_message()`: Sends a message to all members of a group.
- `handle_leave_group()`: Removes a user from a group and deletes the group if empty.
- `handle_private_message()`: Sends a private message to a specific user.
- `handle_broadcast_message()`: Broadcasts a message to all active users.
- `handle_exit_command()`: Handles client disconnection and cleanup.

### Messaging Functions:
- `send_message()`: Sends a message to a specific client.
- `broadcast_message()`: Sends a message to all clients except the sender.
- `group_message()`: Sends a message to all members of a group except sender.
- `private_message()`: Sends a private message to a specific user.

## Code Flow

### 1. **Loading Users**
   - The `load_users` function loads user credentials from a file (`users.txt`). The file contains username-password pairs separated by a colon (`:`).
   - The users are stored in the `users` map with the username as the key and password as the value.

### 2. **Server Initialization**
   - The server creates a socket (`server_socket`) and binds it to a specific port (12345).
   - It listens for incoming client connections using the `listen` function.

### 3. **Handling Client Connections**
   - When a new client connects, the server accepts the connection and starts a new thread (`client_thread`) to handle communication with that client.
   - Each client is authenticated by entering their username and password. If valid, they can proceed to interact with the server.
   
### 4. **Client Authentication**
   - The client is prompted to enter a username and password.
   - If the username is already active, the client is disconnected. If the credentials match, the client is allowed to join the server.

### 5. **Handling Commands**
   - The server processes various commands received from the clients. The supported commands include:
     - `/create_group <group_name>`: Creates a new group with the specified name.
     - `/join_group <group_name>`: Joins an existing group.
     - `/group_msg <group_name> <message>`: Sends a message to a specified group.
     - `/leave_group <group_name>`: Leaves the specified group.
     - `/msg <username> <message>`: Sends a private message to a specific user.
     - `/broadcast <message>`: Sends a broadcast message to all connected clients.
     - `/exit`: Exits the chat session.

### 6. **Broadcasting and Private Messages**
   - **Broadcasting**: Messages can be broadcasted to all connected clients, except the sender.
   - **Private Messaging**: Users can send private messages to each other. If the recipient is not found, an error message is sent.

### 7. **Group Messaging**
   - Users can create groups and join them.
   - Messages sent to a group are forwarded to all members, except the sender. If the user is not a member of the group, they will be notified.

### 8. **Client Exit**
   - When a client sends the `/exit` command or disconnects, the server removes them from the active users list and notifies other clients of their exit.
   - The client's socket is closed, and the thread handling that client is terminated.

### 9. **Thread Safety**
   - The server uses mutexes (`clients_mutex` and `cout_mutex`) to ensure thread safety when accessing shared resources like user data, active users, and client sockets.

## Requirements

- C++20 or higher
- A server and client that support TCP/IP communication using sockets.
- A file named `users.txt` containing valid username-password pairs (one per line) in the format `username:password`.

# Testing

## Correctness Testing

- **Authentication**: Verified that only valid usernames and passwords allow access.
- **Broadcast Messaging**: Confirmed that messages are received by all connected clients.
- **Private Messaging**: Verified that private messages are delivered only to the intended recipient.
- **Group Messaging**: Tested group creation, joining, leaving, and messaging within groups.

### Edge Cases Considered:
1. **Joining non-existent groups**  
   - Attempting to join a group that does not exist should return an appropriate error message.  

2. **Sending empty messages**  
   - The system should prevent users from sending empty messages to maintain meaningful communication.  

3. **Logging in multiple times**  
   - A user should not be able to log in multiple times simultaneously using the same credentials, preventing session conflicts.  

4. **Creating a group with the same name twice**  
   - Duplicate group names should not be allowed to maintain unique group identities.  

5. **Sending a message to a group without joining**  
   - A user must join a group before being able to send messages to it, ensuring proper access control.  

6. **Leaving a group the user is not part of**  
   - If a user tries to leave a group they never joined, the system should prevent it and return an appropriate message.  

7. **Leaving a group twice**  
   - A user should not be able to leave a group multiple times after they have already left it.  

8. **Group names cannot contain whitespace**  
   - The system should enforce naming rules to prevent unintended errors caused by spaces in group names.  

9. **Joining a group multiple times**  
   - A user who has already joined a group should not be able to join it again, preventing duplicate entries.  

## Stress Testing
- **Multiple Clients**: Tested with multiple clients connected simultaneously to ensure the server handles concurrency correctly. As many clients can be added as needed.
- Validated synchronization under high load.  

## Limitations
- No automated test cases or unit tests.  
- Manual testing was performed for all features.  

## Restrictions

- **Max Clients:** The server can handle as many clients as the system's thread limit allows.
- **Max Groups:** No explicit limit; depends on server memory.
- **Group Size:** There is no explicit limit on the number of members in a group.
- **Message Size:** 1024 bytes per message (`BUFFER_SIZE`).

## Challenges

### **1. Synchronization**
- Race conditions during group operations were resolved using `clients_mutex`.

### **2. Command Parsing**
- Handling malformed commands (e.g., extra spaces) required careful substring extraction.

### **3. Resource Management**
- Ensuring sockets and threads are properly closed on `/exit` to prevent leaks.

## Contribution of Each Member

- **Ankit Kaushik (220158)**: 33.33% -implemented server logic , Implemented group management, Designed threading model, and handled testing and debugging.  
- **Harshit Shrivastava (220444)**: 33.33% - developed user authentication, debugged the synchronisation issues and message parsing, wrote README.  
- **Devansh Agarwal (220340)**: 33.33% - Worked on client-side communication, error handling, and assisted with testing and optimization.


## Declaration
We declare that we have not indulged in any form of plagiarism while completing this assignment.