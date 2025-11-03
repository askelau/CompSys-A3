#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>


#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"



// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;
NetworkAddress_t** network = NULL;      // Number of known peers in network
uint32_t peer_count = 0;
pthread_mutex_t network_lock = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------
 * Creates a salted SHA-256 hash signature for a password
 *-------------------------------------------------------------------------- */ 
void get_signature(void* password, int password_len, char* salt, hashdata_t hash){
    if (!password || !salt) return;

    // Createing a buffer big enough to hold password + salt
    int combined_len = password_len + SALT_LEN; // Inputs should be valid
    char *buf = malloc(combined_len);
    if(!buf){
        fprintf(stderr, "Memory allocation failed  in get_signature");
        return;
    }

    // Copy password, then append salt
    memcpy(buf, password, password_len);
    memcpy(buf + password_len, salt, SALT_LEN);

    // Hashing the combined buffer with SHA-256
    get_data_sha(buf, hash, combined_len, SHA256_HASH_SIZE);

    // Clean up temporary buffer
    free(buf);
}

/* --------------------------------------------------------------------------
 * Sends a reply header + optional body to peer connection
 * ---------------------------------------------------------------------------  */
void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length){
    if (response_length > MAX_MSG_LEN){
        fprintf(stderr, "Response to large to send\n");
        return;
    }

     // Initialize reply header
    ReplyHeader_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.length = htonl(response_length);
    reply.status = htonl(status);
    reply.this_block = htonl(1);
    reply.block_count = htonl(1);

     // Compute hash of the response body if present
    hashdata_t body_hash;
    if (response_length > 0 && response_body != NULL){
        get_data_sha(response_body, body_hash, response_length, SHA256_HASH_SIZE);
        memcpy(reply.block_hash, body_hash, SHA256_HASH_SIZE);  // For this block
        memcpy(reply.total_hash, body_hash, SHA256_HASH_SIZE);  // For total message
    } else {
        // Zero hashes already from memset
    }

    // Send header
    compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN);
    // Send body if present
    if (response_length > 0 && response_body){
        compsys_helper_writen(connfd, response_body, response_length);
    }
}

/* -------------------------------------------------------------------------
 * Reads and validates the reply from another peer after sending register
 * -------------------------------------------------------------------------*/
void parse_register_response(int connfd){
    ReplyHeader_t header;
    // Read header
    if (compsys_helper_readn(connfd, &header, REPLY_HEADER_LEN) != REPLY_HEADER_LEN){
        fprintf(stderr, "Failed to reply to header\n");
        return;
    }

    // Convert network byte order to host byte order
    uint32_t body_len = ntohl(header.length);
    uint32_t status = ntohl(header.status);

    // Check for valid status
    if (status != STATUS_OK && status != STATUS_PEER_EXISTS){
        fprintf(stderr, "Register response error: %u\n", status);
        return;
    }

    // Validate length
    if (body_len > MAX_MSG_LEN){
        fprintf(stderr, "Reply body exceeds maximum length\n");
        return;
    }

    // Allocate buffer for body
    char *body = calloc(1, body_len);
    if (compsys_helper_readn(connfd, body, body_len) != body_len){
        fprintf(stderr, "Failed to read reply body\n");
        free(body);
        return;
    }

    // Verify hash matches header hash
    hashdata_t check_hash;
    get_data_sha(body, check_hash, body_len, SHA256_HASH_SIZE);
    if (memcmp(check_hash, header.block_hash, SHA256_HASH_SIZE) != 0){
        fprintf(stderr, "Hash mismatch in reply body\n");
        free(body);
        return;
    }

    // Determine number of peer entries
    int entry_size = PEER_ADDR_LEN;
    if (entry_size <= 0) {
        free(body);
        return;
    }
    int count = body_len / entry_size;

    pthread_mutex_lock(&network_lock);
    for (int i = 0; i < count; i++){
        int offset = i * entry_size;
        // Extract IP from body
        char ip[IP_LEN];
        memset(ip, 0, IP_LEN);
        memcpy(ip, body + offset, IP_LEN);

        // Extract port from body
        uint32_t port_net = 0;
        memcpy(&port_net, body + offset + 16, 4);
        uint32_t port = ntohl(port_net);

        // Check if peer already exists
        int duplicate = 0;
        for (uint32_t j = 0; j < peer_count; j++){
            if (string_equal(network[j]->ip, ip) && network[j]->port == port){
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;    // Skip duplicate peer

        // Add new peer to the network list
        NetworkAddress_t *new_peer = malloc(sizeof(NetworkAddress_t));
        memset(new_peer, 0, sizeof(NetworkAddress_t));
        strncpy(new_peer->ip, ip, IP_LEN - 1);
        new_peer->port = port;

        memcpy(new_peer->signature, body + offset + 20, SHA256_HASH_SIZE);
        memcpy(new_peer->salt, body + offset + 20 + SHA256_HASH_SIZE, SALT_LEN);

        // Expand network array and append
        network = realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
        network[peer_count++] = new_peer;
    }

    fprintf(stdout, "Register reponse parsed: %u peers now known\n", peer_count);
    pthread_mutex_unlock(&network_lock);
    free(body); // Clean up memory
    
}

/* -------------------------------------------------------------------------
 * Creates and sends a network request to another peer
 * -------------------------------------------------------------------------*/
void send_message(NetworkAddress_t peer_address, int command, 
                    char* request_body, int request_len){
    
    // Convert port int to string for helper function
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%u", peer_address.port);

    // Open client connection
    int connfd = compsys_helper_open_clientfd(peer_address.ip, port_str);
    if (connfd < 0){
        fprintf(stderr, "Unable to connect to %s:%s\n", peer_address.ip, port_str);
        return;
    }

    // Assemble request header
    RequestHeader_t request_header;
    memset(&request_header, 0, sizeof(request_header));
    memcpy(request_header.ip, my_address->ip, IP_LEN);          // Include own IP
    request_header.port = htonl(my_address->port);              // Include own port
    memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE);
    request_header.command = htonl(command);
    request_header.length = htonl(request_len);

    // Send header then optional body
    compsys_helper_writen(connfd, &request_header, REQUEST_HEADER_LEN);
    if (request_len > 0 && request_body){
        compsys_helper_writen(connfd, request_body, request_len);
    }

    // Expect a response for REGISTER command
    if (command == COMMAND_REGISTER){
        parse_register_response(connfd);
    }

    close(connfd);
}

/* --------------------------------------------------------------------------
 * Validates and registers a new peer connection (server-side)
 * --------------------------------------------------------------------------*/
void handle_register_request(int connfd, RequestHeader_t* req){
    uint32_t host_port = ntohl(req->port);

    // Validate IP and port
    if (!is_valid_ip(req->ip) || !is_valid_port(host_port)){
        fprintf(stderr, "Invalid register request IP/Port\n");
        close(connfd);
        return;
    }

    pthread_mutex_lock(&network_lock);
    // Check if peer already known
    for (uint32_t i = 0; i < peer_count; i++){
        if (string_equal(network[i]->ip, req->ip) && network[i]->port == host_port){
            fprintf(stdout, "Peer already registered: %s:%d\n", req->ip, host_port);
            pthread_mutex_unlock(&network_lock);
            send_response(connfd, STATUS_PEER_EXISTS, NULL, 0);
            close(connfd);
            return; 
        }
    }

    // Add new peer
    NetworkAddress_t *new_peer = malloc(sizeof(NetworkAddress_t));
    memset(new_peer, 0, sizeof(NetworkAddress_t));
    strncpy(new_peer->ip, req->ip, IP_LEN);
    new_peer->port = host_port;

    // Generate random salt and compute salted signature
    generate_random_salt(new_peer->salt);
    hashdata_t salted_hash;
    get_signature(req->signature, SHA256_HASH_SIZE, new_peer->salt, salted_hash);
    memcpy(new_peer->signature, salted_hash, SHA256_HASH_SIZE);

    // Append to global network list
    network = realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
    network[peer_count++] = new_peer;
    pthread_mutex_unlock(&network_lock);

    // Build reponse body: concatenate all known peers
    pthread_mutex_lock(&network_lock);
    int entry_len = PEER_ADDR_LEN;
    int body_len = entry_len * peer_count;
    char *body = calloc(1, body_len);

    for (uint32_t i = 0; i < peer_count; i++){
        int offset = i * entry_len;
        memcpy(body + offset, network[i]->ip, IP_LEN);

        uint32_t port_net = htonl(network[i]->port);
        memcpy(body + offset + 16, &port_net, 4);

        memcpy(body + offset + 20, network[i]->signature, SHA256_HASH_SIZE);
        memcpy(body + offset + 20 + SHA256_HASH_SIZE, network[i]->salt, SALT_LEN);
    }

    pthread_mutex_unlock(&network_lock);

    // Send success reponse with complete network list
    send_response(connfd, STATUS_OK, body, body_len);
    free(body);
    close(connfd);
}

/* -------------------------------------------------------------------------
 * Handle incoming connections
 * -------------------------------------------------------------------------*/
void* handle_server_request_thread(void* arg){
    int connfd = *(int*)arg;
    free(arg);  // Free memory allocated for connection fd
    pthread_detach(pthread_self());

    // Read the header of the incoming request
    RequestHeader_t req;
    if (compsys_helper_readn(connfd, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN){
        fprintf(stderr, "Failed to read request header\n");
        close(connfd);
        return NULL;
    }

    uint32_t command = ntohl(req.command);

    // Dispatch to appropriate handler
    switch(command){
        case COMMAND_REGISTER:
            handle_register_request(connfd, &req);
            break;
        default:
            fprintf(stderr, "Unknown command: %u\n", command);
            send_response(connfd, STATUS_BAD_REQUEST, NULL, 0);
            close(connfd);
            break;
    }

    return NULL;
}

/* ------------------------------------------------------------------------------
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 * ------------------------------------------------------------------------------*/ 
void* client_thread() {
    // Prompt user for peer IP to connect to
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Prompt user for peer port
    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%8s", peer_port);

    // Building peer address structure
    NetworkAddress_t peer_address;
    memset(&peer_address, 0, sizeof(peer_address));
    strncpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // Ask user for their own password to regenerate signature
    char password[PASSWORD_LEN];
    fprintf(stdout, "Enter your password again: ");
    scanf("%16s", password);

    // Re-generate signature using the same salt
    get_signature(password, PASSWORD_LEN, my_address->salt, my_address->signature);

    fprintf(stdout, "Registering with peer %s:%d...\n", peer_address.ip, peer_address.port);
    // Send REGISTER request to the specified peer
    send_message(peer_address, COMMAND_REGISTER, NULL, 0);

    return NULL;
}

/* -------------------------------------------------------------------------------
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 * --------------------------------------------------------------------------------*/
void* server_thread() {
    // Convert own port to string for listening socket helper function
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%u", my_address->port);

    // Open TCP listening socket on given port
    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0){
        fprintf(stderr, "Failed to open listening socket on port %s\n", port_str);
        pthread_exit(NULL);
    }

    fprintf(stdout, "Listening for connections on %s:%s...\n", my_address->ip, port_str);

    // Accept incoming peers and create handler threads
    while(1){
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *connfd_ptr = malloc(sizeof(int));

        // Accept incoming connection; blocks until a peer connects
        *connfd_ptr = accept(listenfd, (struct sockaddr*)&client_addr, &addr_len);
        if (*connfd_ptr < 0){
            free(connfd_ptr);
            continue;
        }

        // Spawn new thread to handle connection
        pthread_t tid;
        pthread_create(&tid, NULL, handle_server_request_thread, connfd_ptr);
    }

    close(listenfd);
    return NULL;
}

/* -----------------------------------------------------------------------------
 * Main function 
 * ------------------------------------------------------------------------------*/

int main(int argc, char **argv) {
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(my_address->salt);   // can use this but makes testing harder
    memcpy(my_address->salt, salt, SALT_LEN);

    // Compute salted signature
    get_signature(password, PASSWORD_LEN, my_address->salt, my_address->signature);

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}