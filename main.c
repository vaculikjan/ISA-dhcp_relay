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


struct dhcpv6_relay_packet {
    unsigned char msg_type;
    unsigned char hop_count;
    unsigned char link_address[16];
    char peer_address[16];
    unsigned char options[];
};


int main(int argc, const char * argv[]) {

    struct dhcpv6_relay_packet *packet = malloc(sizeof(*packet));
    struct sockaddr_in6 server, client;
    memset(&server, 0, sizeof(server));
    server.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:67c:1220:80c::93e5:dd2", &server.sin6_addr);
    server.sin6_port = htons(547);

    packet->msg_type = 1;
    packet->hop_count = 1;
    //memcpy(packet->peer_address, "fe80::5cea:36ff:fe26:585f", sizeof(packet->peer_address));
    strcpy(packet->peer_address, "fe80::5cea:36ff:fe26:585f");
    memcpy(packet->link_address, "0", sizeof(packet->link_address));

    char reply[1024];
    int sockfd;
    socklen_t client_length= sizeof(client);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if ((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Error opening a socket on local machine\n");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval))) {
        perror("This is your error: ");
        exit(-1);
    }

    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&server,
               sizeof(server)) < 0) {
        perror("This is your error: ");
    }


    if ((recvfrom(sockfd, reply, sizeof(reply), 0, (struct sockaddr *)&client, &client_length) ) < 0) {
      perror("This is your error: ")  ;
    }

    printf("Message: %s \n", reply);

    close(sockfd);

    return 0;
}

//----------------------------------------------------------------------------------------------------------------------

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