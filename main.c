//
//  main.c
//  DHCPv6
//
//  Created by Jan Vaculik on 17/10/2019.
//  Copyright © 2019 Jan Vaculik. All rights reserved.
//
// git test

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ifaddrs.h>

#define MESSAGE "hi there"

struct dhcpv6_relay_packet {
    unsigned char msg_type;
    unsigned char hop_count;
    unsigned char link_address[16];
    unsigned char peer_address[16];
    unsigned char options[];
};


int main(int argc, const char * argv[]) {

    struct dhcpv6_relay_packet *packet = malloc(sizeof(*packet));
    struct sockaddr_in6 server;
    memset(&server, 0, sizeof(server));
    server.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:67c:1220:80c::93e5:dd2", &server.sin6_addr);
    server.sin6_port = htons(547);

    packet->msg_type = 1;
    packet->hop_count = 1;
    strcpy(packet->peer_address, "fe80::5cea:36ff:fe26:585f");
    strcpy(packet->link_address, "0");


    int sockfd;
    if ((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Error opening a socket on local machine\n");
    }
    else {
        printf("Socket opened successfully\n");
    }

    if (sendto(sockfd, MESSAGE, sizeof(MESSAGE), 0, (struct sockaddr *)&server,
               sizeof(server)) < 0) {
        perror("This is your error: ");
    }
    //sendto(sockfd, *buffer, <#size_t#>, <#int#>, <#const struct sockaddr *#>, <#socklen_t#>);

/*
    struct ifaddrs *ifa, *ifa_tmp;
    char addr[50];

    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs failed");
        exit(1);
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                                  (ifa_tmp->ifa_addr->sa_family == AF_INET6))) {
            if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
                // create IPv4 string
                struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
            } else { // AF_INET6
                // create IPv6 string
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
            }
            printf("name = %s\n", ifa_tmp->ifa_name);
            printf("addr = %s\n", addr);
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
 */
    return 0;
}




/* typedef struct {
     int MSG_TYPE : 8;
     int C: 1;
     int reserved : 16;
     int prefix: 7;
     __int128_t client_address : 128;
     __int128_t relay_address : 128;

 } message_buffer;

 message_buffer *buffer = malloc(sizeof(message_buffer));

 buffer->MSG_TYPE = 1;
 buffer->C = 0;
 buffer->reserved = 0;
 buffer->prefix = 64;
 buffer->client_address = (int)strtol("fe80::5cea:36ff:fe26:585f", NULL, 0);
 buffer->relay_address = (int)strtol("fe80::1c08:ffc9:9a58:c7bf", NULL, 0);
*/