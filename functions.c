//
//  functions.c
//  Functions definitions
//
//  Created by Jan Vaculik on 15/11/2019.
//  Copyright © 2019 Jan Vaculik. All rights reserved.
//

#include "structs.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <net/if.h>

//function serves for creating a socket and setting it up
int createSocket(const char *iface_name, int port) {

    int sockfd;

    struct timeval tv;
    tv.tv_sec = 1; //setting timout to 1 sec
    tv.tv_usec = 0;

    //create socket and save the file descriptor
    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        perror("Error opening a socket.");
        exit(-1);
    }

    //setting up address for bind, port is important for us
    struct sockaddr_in6 sockaddrIn6;
    memset(&sockaddrIn6, 0, sizeof(sockaddrIn6));
    sockaddrIn6.sin6_family = AF_INET6;
    sockaddrIn6.sin6_port = htons(port);
    sockaddrIn6.sin6_addr = in6addr_any;

    int reuse = 1;

    //setting socket options so that we can bind to an address and port even if it already is under use
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed.");
        exit(-1);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed.");
        exit(-1);
    }

    //bind socket to previously declared port
    if (bind(sockfd, (struct sockaddr *)&sockaddrIn6, sizeof(sockaddrIn6)) < 0) {
        perror("Error in binding a socket.");
        exit(-1);
    }

    //get the length of an interface
    int len = strnlen(iface_name, IFNAMSIZ);

    //if we do not want to bind socket to an interface we pass 0 to this function
    if (strcmp(iface_name, "0") != 0) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, len)) {
            perror("setsockopt(SO_BINDTODEVICE) failed.");
            exit(-1);
        }
    }

    //set the timeout for recvfrom
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval))) {
        perror("setsockopt(SO_RCVTIME0) failed.");
        exit(-1);
    }
    return sockfd;
}
//function serves for creating a DHCPv6 option struct
struct dhcpv6_relay_message_options* setOptions(int option_len, int opt_num) {

    struct dhcpv6_relay_message_options *options = malloc(sizeof(*options));

    options->options_type[0] = 0;
    options->options_type[1] = opt_num;

    options->len[1] = option_len & 0xFF;
    options->len[0] = (option_len >> 8) & 0xFF;

    return options;
}
//function goes through the message and looks for specific option type, if it finds it, it returns an int
//that points on the position of the message identifier otherwise returns -1
int lookForOptionType(int option_no, const unsigned char reply[1024], int msg_lngth, int counter, int *option_length) {

    //arbitrary number
    int options = 128;
    *option_length = reply[counter + 3] | reply[counter + 2] <<8;

    //loop to look for position of relay message option (9)
    while (counter < msg_lngth) {
        options = reply[counter + 1] | reply[counter] <<8;

        if (options == option_no) {
            break;
        }

        counter += *option_length + 4;
        *option_length = reply[counter + 3] | reply[counter + 2] <<8;
    }
    if (options == option_no) {
        return counter;
    }
    return -1;
}