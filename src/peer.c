#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>


#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "common.h"
#include "compsys_helpers.h"


// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;
NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_lock = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------
 * Signature calculation
 *-------------------------------------------------------------------------- */ 
void get_signature(void* password, int password_len, char* salt, hashdata_t hash){
    if (!password || !salt) return;

    // Create a buffer big enough to hold password + salt
    int combined_len = password_len + SALT_LEN; // Inputs should be valid
    char *buf = malloc(combined_len);
    if(!buf){
        fprintf(stderr, "Memory allocation failed  in get_signature");
        return;
    }

    // Copy password, then append salt
    memcpy(buf, password, password_len);
    memccpy(buf + password_len, salt, SALT_LEN)

    // Hashing the combined buffer with SHA-256
    get_data_sha(buf, hash, combined_len, SHA256_HASH_SIZE);

    // Clean up temporary buffer
    free(buf);
}

/* --------------------------------------------------------------------------
 * Generic response sender
 * ---------------------------------------------------------------------------  */
void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length){
    if (response_length > MAX_MSG_LEN){
        fprintf(stderr, "Response to large to send\n");
        return;
    }

    ReplyHeader_t reply;
    memset(&reply, 0, sizeof(reply));

    reply.length = htonl(response_length);
    reply.status = htonl(status);
    reply.this_block = htonl(1);
    reply.block_count = htonl(1);

    // Hash the body to fill block_hash and total_hash
    hashdata_t body_hash;
    get_data_sha(response_body, body_hash, response_length, SHA256_HASH_SIZE);
    memcpy(reply.block_hash, body_hash, SHA256_HASH_SIZE);
    memcpy(reply.total_hash, body_hash, SHA256_HASH_SIZE);

    // Write header then body
    compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN);
    if (response_length > 0){
        compsys_helper_writen(connfd, response_body, response_length);
    }
}

/* -------------------------------------------------------------------------
 * Reads and validates the reply from another peer after sending register
 * -------------------------------------------------------------------------*/
void parse_register_response(int connfd){

}

/* -------------------------------------------------------------------------
 * Creates and sends a network request to another peer
 * -------------------------------------------------------------------------*/
void send_message(NetworkAddress_t peer_address, int command, 
                    char* request_body, int request_len){
    
    // Convert port int to string for helper function
    char port_str[PORT_STR_LEN];
    snprintf(port_str, size_of(port_str), "%u", peer_address.port);

    // Open client connection
    int connfd = compsys_helper_open_clientfd(peer_address.ip, port_str);
    if (connfd < 0){
        fprintf(stderr, "Unable to connect to %s:%s\n", peer_address.ip, port_str);
        return;
    }

    // Assemble request header
    ReplyHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(command);
    req.length = htonl(request_len);

    // Send header then optional body
    compsys_helper_writen(connfd, &req, REQUEST_HEADER_LEN);
    if (request_len > 0 && request_body){
        compsys_helper_writen(connfd, request_body, request_len);
    }

    // Expect a response for REGISTER command
    if (command == COMMAND_REGISTER){
        parse_register_response(connfd);
    }

    close(connfd);
}



/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

    return NULL;
}


int main(int argc, char **argv)
{
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
    //generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);

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