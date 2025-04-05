#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define PORT 12345

std::unordered_map<std::string, int> username_to_socket;                 // Map of username to socket
std::unordered_map<std::string, std::unordered_set<std::string>> groups; // Group -> usernames
std::unordered_set<std::string> active_usernames;                        // Set of active usernames
std::unordered_map<std::string, std::string> users;                      // Global map of username to password
std::mutex clients_mutex;                                                // Mutex for thread safety
std::mutex cout_mutex;

// Function to load users from the "users.txt" file
void load_users(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Error opening users.txt file " << filename << std::endl;
        exit(1);
    }
    std::string line;
    while (std::getline(file, line))
    {
        size_t delimiter_pos = line.find(':');
        if (delimiter_pos != std::string::npos)
        {
            std::string username = line.substr(0, delimiter_pos);
            std::string password = line.substr(delimiter_pos + 1);
            users[username] = password;
        }
    }
    file.close();
}

// Function to send a message to a specific client
void send_message(int client_socket, const std::string &message)
{
    send(client_socket, message.c_str(), message.size(), 0);
}

// Broadcast a message to all clients except the sender
void broadcast_message(const std::string &message, const std::string &sender_username)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto &pair : username_to_socket)
    {
        if (pair.first != sender_username)
        {
            send_message(pair.second, message);
        }
    }
}

// Send message to all members of a group except the sender
void group_message(const std::string &sender_username, const std::string &group_name, const std::string &message)
{
    if (groups.find(group_name) != groups.end())
    {
        for (const auto &username : groups[group_name])
        {
            if (username != sender_username && active_usernames.count(username))
            {
                send_message(username_to_socket[username], "[Group " + group_name + "] : " + message);
            }
        }
    }
}

// Send private message to a specific client
void private_message(const std::string &sender_username, const std::string &receiver_username, const std::string &message)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    if (username_to_socket.find(receiver_username) != username_to_socket.end())
    {
        send_message(username_to_socket[receiver_username], "[" + sender_username + "] : " + message);
    }
    else
    {
        send_message(username_to_socket[sender_username], "User " + receiver_username + " not found.");
    }
}


void handle_create_group(const std::string &username, int client_socket, const std::string &message){
    std::string group_name = message.substr(14);
    // Check for intermediate whitespace in group name
    if (group_name.find(' ') != std::string::npos) {

        send_message(client_socket, "Error: Invalid group Name.");
        return;
    }
    

    std::lock_guard<std::mutex> lock(clients_mutex);

    // Check if the group already exists
    if (groups.find(group_name) != groups.end())
    {
        send_message(client_socket, "Group " + group_name + " already exists.");
    }
    else
    {
        groups[group_name].insert(username); // Create group and add user as the first member
        send_message(client_socket, "Group " + group_name + " created.");
    }

}
void handle_join_group(const std::string &username, int client_socket, const std::string &message){
    std::string group_name = message.substr(12);

    std::lock_guard<std::mutex> lock(clients_mutex);

    // Check if the group exists
    if (groups.find(group_name) == groups.end())
    {
        send_message(client_socket, "Group " + group_name + " does not exist.");
    }
    // Check if the user is already a member of the group
    else if (groups[group_name].count(username))
    {
        send_message(client_socket, "You are already a member of group " + group_name + ".");
    }
    else
    {
        groups[group_name].insert(username); // Add user to the group
        send_message(client_socket, "You joined the group " + group_name + ".");
    }
}

void handle_group_message(const std::string &username, int client_socket, const std::string &message){
    size_t space1 = message.find(' ');
    size_t space2 = message.find(' ', space1 + 1);

    if (space1 != std::string::npos && space2 != std::string::npos)
    {
        std::string group_name = message.substr(space1 + 1, space2 - space1 - 1);
        std::string group_msg = message.substr(space2 + 1);

        if(group_msg.empty()){
            send_message(client_socket, "Error: Empty message.");
            return;
        }

        // Check if the user is a member of the group
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = groups.find(group_name);
        if (it != groups.end() && it->second.count(username))
        {
            // User is a member of the group
            group_message(username, group_name, group_msg);
        }
        else
        {
            // User is not a member of the group
            send_message(client_socket, "You are not a member of the group: " + group_name);
        }
    }
    else
    {
        send_message(client_socket, "Invalid /group_msg format. Use: /group_msg <group_name> <message>");
    }
}
void handle_leave_group(const std::string &username, int client_socket, const std::string &message){
    std::string group_name = message.substr(13);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        auto group_it = groups.find(group_name);
        if (group_it != groups.end() && group_it->second.count(username))
        {
            group_it->second.erase(username); // Remove user from the group

            if (group_it->second.empty())
            {
                groups.erase(group_name); // Remove the group if empty
            }

            // Notify user and group
            send_message(client_socket, "You have left group " + group_name + ".");
            if (!group_it->second.empty())
            {
                //group_message(username, group_name, username + " has left the group.");
            }
        }
        else
        {
            send_message(client_socket, "You are not a member of group " + group_name + ".");
        }
    }
}
void handle_private_message(const std::string &username, const std::string &message){
    size_t space1 = message.find(' ', 5);
    if (space1 != std::string::npos)
    {
        std::string receiver = message.substr(5, space1 - 5);

        if(receiver == username){
            send_message(username_to_socket[username], "Error: You cannot send message to yourself.");
            return;
        }
        std::string private_msg = message.substr(space1 + 1);

        if(private_msg.empty()){
            send_message(username_to_socket[username], "Error: Empty message.");
            return;
        }
        private_message(username, receiver, private_msg);
    }
}
void handle_broadcast_message(const std::string &username, const std::string &message){
    std::string broadcast_msg = message.substr(11); // Extract the message after "/broadcast "
    if(broadcast_msg.empty()){
        send_message(username_to_socket[username], "Error: Empty message.");
        return;
    }
    std::string full_message = "[Broadcast from " + username + "] " + broadcast_msg;
    broadcast_message(full_message, username);
}

void handle_exit_command(int client_socket, const std::string &username){
    std::string exit_message;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::cout << username << " exited." << std::endl;
        username_to_socket.erase(username);
        for (auto &it : groups) {
            if (it.second.find(username) != it.second.end()) {
                it.second.erase(username);
                if (it.second.empty()) {
                    groups.erase(it.first);
                }
            }
        }
        active_usernames.erase(username);
        exit_message = username + " has left the chat.";
    }
    broadcast_message(exit_message, username);
    close(client_socket);
}

// Handle communication with a specific client
void handle_client_messages(int client_socket)
{
    char buffer[BUFFER_SIZE];
    std::string username;

    // Authentication
    send_message(client_socket, "Enter username: ");
    memset(buffer, 0, BUFFER_SIZE);
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    username = buffer;
    username.erase(username.find_last_not_of("\n\r") + 1);

    send_message(client_socket, "Enter password: ");
    memset(buffer, 0, BUFFER_SIZE);
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    std::string password = buffer;
    password.erase(password.find_last_not_of("\n\r") + 1);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (active_usernames.find(username) != active_usernames.end())
        {
            send_message(client_socket, "Error: User already logged in.");
            close(client_socket);
            return;
        }
    }

    // Check credentials
    if (users.find(username) != users.end() && users[username] == password)
    {
        send_message(client_socket, "Welcome to the server!\n");
    }
    else
    {
        send_message(client_socket, "Authentication failed.\n");
        close(client_socket);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        username_to_socket[username] = client_socket;
        active_usernames.insert(username);
    }

    broadcast_message(username + " has joined the chat.", username);
    {
    std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
    std::cout << username << " has connected." << std::endl;
    }

    // Main loop for receiving messages from this client
    while (true)
    {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (bytes_received <= 0)
        {
            std::string disconnect_message;
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                username_to_socket.erase(username);
                active_usernames.erase(username);
                disconnect_message = username + " has left the chat.\n";
            }
            broadcast_message(disconnect_message, username);
            close(client_socket);
            break;
        }

        std::string message = buffer;

        // Handle diffenent commands
        if(message.starts_with("/create_group ")){
            handle_create_group(username, client_socket, message);
        }
        else if(message.starts_with("/join_group ")){
            handle_join_group(username, client_socket, message);
        }
        else if(message.starts_with("/group_msg ")){
            handle_group_message(username, client_socket, message);
        }
        else if(message.starts_with("/leave_group ")){
            handle_leave_group(username, client_socket, message);
        }
        else if(message.starts_with("/msg ")){
            handle_private_message(username, message);
        }
        else if(message.starts_with("/broadcast ")){
            handle_broadcast_message(username, message);
        }
        else if(message == "/exit"){
            handle_exit_command(client_socket, username);
            break;
        }
        else
        {
            send_message(client_socket, "Error: Invalid Command");
        }
    
    }
}

int main()
{
    // Load users at server start
    load_users("users.txt");

    int server_socket, client_socket;
    sockaddr_in server_address{}, client_address{};
    socklen_t client_len = sizeof(client_address);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {   
        std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
        std::cerr << "Error binding socket." << std::endl;
        return 1;
    }

    if (listen(server_socket, 10) < 0)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
        std::cerr << "Error listening on socket." << std::endl;
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
        std::cout << "Server started. Waiting for connections..." << std::endl;
    }

    while (true)
    {
        client_socket = accept(server_socket, (sockaddr *)&client_address, &client_len);
        if (client_socket < 0)
        {   
            std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
            std::cerr << "Error accepting connection." << std::endl;
            continue;
        }
        else{
            std::lock_guard<std::mutex> lock(cout_mutex);  // Lock mutex before printing
            std::cout << "New client is connecting." << std::endl;
        }

        // Create a thread to handle the new client
        std::thread client_thread(handle_client_messages, client_socket);
        client_thread.detach();
        
    }

    close(server_socket);
    return 0;
}