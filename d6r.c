//
//  d6r.c
//  Main file for the relay
//
//  Created by Jan Vaculik on 15/11/2019.
//  Copyright © 2019 Jan Vaculik. All rights reserved.
//
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

//includes
#include "structs.h"
#include "functions.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <syslog.h>

//defines
#define SIZE_ETHERNET (14)
#define SIZE_IPV6 (40)
#define SIZE_UDP (8)
#define TYPE_UDP (17)

#define SIZE_RELAY (38) //size of relay-forward header + relay message options header
#define SIZE_MAC_LINK (12) //size of client link layer address options

#define IA_NA_OP (3)
#define IA_TA_OP (4)
#define IADDAR_OP (5)
#define IA_PD_OP (25)
#define IAPREFIX_OP (26)
#define REPLY (7)
#define RELAY_MSG (9)
#define RELAY_REPLY (13)
#define CLIENT_LINK (79)

//----------------------------------------------------------------------------------------------------------------------

int main(int argc, const char * argv[]) {


    //argument flags
    bool s_flag = false;
    bool i_flag = false;
    bool d_flag = false;
    bool l_flag = false;

    //variables for pcap routines
    char err_buff[PCAP_ERRBUF_SIZE]; //error buffer for pcap routines
    pcap_t *pcap_handle; //pcap handle for pcap routines

    const u_char *data; //datagram sniffed through pcap_next()
    struct pcap_pkthdr pcap_header; //capture driver packet header
    struct ether_header *ethernet_header; //we store the Ethernet header into this struct
    struct ip6_hdr *ip6_header; //we store the IPv6 header into this struct

    bpf_u_int32 net_addr;
    bpf_u_int32 mask;

    struct bpf_program filter_program; //holds the compiled filter
    char filter_exp[] = "port 547"; //the text to filter on port 547

    struct sockaddr_in6 server, client; //structs holding addresses
    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));

    const char *iface_name = "0"; //name of an interface used, changes for each process
    struct ifaddrs *if_addr, *if_addr_current; //variables used for interface related operations


//----------------------------------------------------------------------------------------------------------------------
//Checking arguments passed to the program

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-s") == 0) {

            if (s_flag) {

                fprintf(stderr, "-s option declared multiple times\n");
                exit(11);
            }

            else {

                s_flag = true;

                //following code taken from https://stackoverflow.com/questions/2962664/ipv6-parsing-in-c by Ales Teska
                //checking if address passed as a program argument is a valid IPv6 address

                const char *ip6str = argv[i + 1];

                struct addrinfo *res = NULL;
                struct addrinfo hints;
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_INET6;

                if ((getaddrinfo(ip6str, NULL, &hints, &res)) != 0) {

                    fprintf(stderr, "Parsing the server address: %s failed.\n"
                                    "It likely isn't a valid address.\n"
                                    "Use the option -s in the format -s <server-name> and choose a DHCPv6 server.\n", ip6str);
                    exit(11);
                }

                //filling the server variable
                server.sin6_family = AF_INET6;
                inet_pton(AF_INET6, ip6str, &server.sin6_addr);
                server.sin6_port = htons(547);
            }
        }
        //output flag
        if (strcmp(argv[i], "-d") == 0) {

            d_flag = true;
        }

        //syslog flag
        if (strcmp(argv[i], "-l") == 0) {

            l_flag = true;
        }

        //interface flag
        if (strcmp(argv[i], "-i") == 0) {

            if (i_flag) {

                fprintf(stderr, "-i option declared multiple times\n");
                exit(12);
            }
            else {

                i_flag = true;
                iface_name = argv[i+1];
            }
        }

        if (strcmp(argv[i], "-h") == 0) {

            printf("Use the program as: sudo ./d6r -s <server> [-l] [-d] [-i interface]\n"
                   "-s a valid IPv6 address must follow this option. This option is mandatory.\n"
                   "[-d] prints debug to console. The debug contains assigned address(prefix) and MAC address.\n"
                   "[-l] logs debug output to syslog. The debug contains assigned address(prefix) and MAC address\n"
                   "[-i] a valid interface name must follow this option.\n");
            exit(14);
        }
    }

    if (!s_flag) {

        fprintf(stderr, "Use the option -s in the format -s <server-name> and choose a DHCPv6 server.\n");
        exit(11);
    }

    if (!i_flag) {

        if (getifaddrs(&if_addr) == -1) { //get first address of the first interface

            perror("Couldn't locate any interfaces.\n");
            exit(21);
        }

        if (getifaddrs(&if_addr) == -1) {

            perror("getifaddrs failed");
            exit(22);
        }

        if_addr_current = if_addr;

        while (if_addr_current) { //while there are addressess

            //In this part of the code we check for all interfaces that have an IPv6 address.
            //We create a new process for each such interface.
            //The last interface will run in the Parent process.

            if ((if_addr_current->ifa_addr) && (if_addr_current->ifa_addr->sa_family == AF_INET6) && (strcmp(iface_name, if_addr_current->ifa_name) != 0)) {

                iface_name = if_addr_current->ifa_name;
                struct ifaddrs *if_addr_tmp = if_addr_current->ifa_next;

                while(if_addr_tmp) {

                    if (if_addr_tmp->ifa_addr->sa_family == AF_INET6 && (strcmp(iface_name, if_addr_tmp->ifa_name) != 0)) {
                        break;
                    }
                    if_addr_tmp = if_addr_tmp->ifa_next;
                }

                if (if_addr_tmp == NULL) {

                    break;
                }

                if (fork() == 0) {
                    break;
                }
            }

            if_addr_current = if_addr_current->ifa_next;
        }
    }

    //if -i option was chose, we check if an interface of given name exists
    else {

        if (getifaddrs(&if_addr) == -1) {

            perror("Couldn't locate any interfaces.\n");
            exit(21);
        }

        if (getifaddrs(&if_addr) == -1) {

            perror("getifaddrs failed");
            exit(22);
        }

        if_addr_current = if_addr;

        while (if_addr_current) {

            if ((if_addr_current->ifa_addr) && (if_addr_current->ifa_addr->sa_family == AF_INET6) &&
                (strcmp(iface_name, if_addr_current->ifa_name) == 0)) {
                break;
            }
            if_addr_current = if_addr_current->ifa_next;
        }

        if (if_addr_current == NULL) {

            fprintf(stderr,"The interface doesn't exist or doesn't have an IPv6 address\n");
            exit(13);
        }
    }

    // sniffer inspired by sniff.c by Petr Matousek ("siff.c", (c) Petr Matousek, 2015)

    // obtaining net_addr and mask of an interface
    if (pcap_lookupnet(iface_name,&net_addr,&mask,err_buff) == -1) {

        perror("Couldn't receive the address of an interface.\n");
        exit(-1);
    }

    // obtaining pcap handle for packet sniffing
    if ((pcap_handle = pcap_open_live(iface_name,BUFSIZ,1,1000,err_buff)) == NULL) {

        perror("Error getting a pcap hanndle.\n");
        exit(-1);
    }

    // compiling capture filter
    if (pcap_compile(pcap_handle, &filter_program, filter_exp, 0, net_addr) == -1) {

        perror("Error compiling a pcap filter\n");
        exit(-1);
    }

    // setting capture filter
    if (pcap_setfilter(pcap_handle, &filter_program) == -1) {

        perror("Error setting a pcap filter\n");
        exit(-1);
    }


//----------------------------------------------------------------------------------------------------------------------
//After the sniffer captures a packet on port 546 it parses the headers and sends the message to server

    // starting the sniffer, the program runs in an infinite loop, sniffing packets from clients on port 546
    while ((data = pcap_next(pcap_handle,&pcap_header)) != NULL){

        ethernet_header = (struct ether_header *) data; //data pcap has given us start with an Ethernet header
        int payload_length; //holds the length of the received UDP datagram without a header

        //check if the message is IPv6
        if ((ntohs(ethernet_header->ether_type)) == ETHERTYPE_IPV6) {

            ip6_header = (struct ip6_hdr*) (data+SIZE_ETHERNET); //IPv6 header is 14 bytes from the beginning of data

            //check if the message is UDP
            if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == TYPE_UDP) {

                payload_length = (ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) - 8);
                //this is where the DHCP header starts and we obtain the message type
                struct dhcpv6_msg_reader *msgReader = (struct dhcpv6_msg_reader *) (data + SIZE_ETHERNET + SIZE_IPV6 + SIZE_UDP);

                //supports solicit, request, renew, rebind and release messages from the client
                if (msgReader->msg_type == 1 || msgReader->msg_type == 3 || msgReader->msg_type == 5
                    || msgReader->msg_type == 6 || msgReader->msg_type == 8) {

                    struct dhcpv6_relay_message_header *relay_message_header = malloc(sizeof(*relay_message_header)); //holds the relay msg header

                    //filling the DHCPv6 Relay Message header
                    relay_message_header->msg_type[0] = 12; //message type 12 for relay-forward
                    relay_message_header->hop_count[0] = 0; //hopcount 0 because solicit was directly from client
                    //IPv6 address of the interface which received message from the client
                    struct sockaddr_in6 *in6_tmp = (struct sockaddr_in6*) if_addr_current->ifa_addr;
                    memcpy(relay_message_header->link_address, in6_tmp->sin6_addr.__in6_u.__u6_addr16, sizeof(relay_message_header->link_address));
                    //link-local address of the client
                    memcpy(relay_message_header->peer_address, ip6_header->ip6_src.__in6_u.__u6_addr16, sizeof(relay_message_header->peer_address));

                    //relay-message option (9) which go directly after the header
                    struct dhcpv6_relay_message_options *relay_message_options = setOptions(payload_length, RELAY_MSG);
                    //client-link layer option (79), this program only supports MAC
                    struct dhcpv6_relay_message_options *client_link = setOptions(8,CLIENT_LINK);

                    //we get the mac address from the Ethernet header
                    unsigned char client_link_address[8];
                    client_link_address[0] = 0x00;
                    client_link_address[1] = 0x01;
                    memcpy(client_link_address + 2, ethernet_header->ether_shost,6);

                    //variable carrying the composed DHCPv6 datagram, +12 for client-link with MAC
                    unsigned char send_datagram[SIZE_RELAY+payload_length+SIZE_MAC_LINK];

                    //composing the datagram to be sent using memcpy
                    //relay forward header
                    memcpy(send_datagram, relay_message_header, SIZE_RELAY - 4);
                    //relay message option
                    memcpy(send_datagram+1+1+16+16, relay_message_options->options_type, 2);
                    memcpy(send_datagram+1+1+16+16+2,relay_message_options->len,2);
                    memcpy(send_datagram+1+1+16+16+2+2, (data+SIZE_ETHERNET+SIZE_IPV6+SIZE_UDP), payload_length);
                    //client link layer address option
                    memcpy(send_datagram+1+1+16+16+2+2+payload_length, client_link->options_type, 2);
                    memcpy(send_datagram+1+1+16+16+2+2+payload_length+2,client_link->len,2);
                    memcpy(send_datagram+1+1+16+16+2+2+payload_length+2+2,client_link_address,8);

                    //sockets for client communication (port 546) and server communication (547)
                    int server_socket = createSocket("0", 547);
                    int client_socket = createSocket(iface_name, 546);

                    //sending datagram to server
                    if (sendto(server_socket, send_datagram, SIZE_RELAY+payload_length+SIZE_MAC_LINK, 0, (struct sockaddr *)&server,
                               sizeof(server)) < 0) {

                    }

                    int msg_lngth; //length of udp message from server without ethernet and ip headers
                    unsigned char reply[1024]; //reply from server

                    if ((msg_lngth = recvfrom(server_socket, reply, sizeof(reply), 0, NULL, NULL)) < 0) {
                    }

                    else {

                        //if reply was relay-reply message
                        if (reply[0] == RELAY_REPLY) {

                            int option_length;
                            int len = msg_lngth;
                            //counter variable used as a pointer to the reply array
                            int counter = lookForOptionType(RELAY_MSG, reply, len, (SIZE_RELAY -4), &option_length);

                            //if we found relay message
                            if (counter != -1) {

                                //set client address and port
                                client.sin6_family = AF_INET6;
                                client.sin6_addr = ip6_header->ip6_src;
                                client.sin6_port = htons(546);

                                char msg_to_client[option_length];
                                memcpy(msg_to_client, reply + counter + 4, option_length);

                                //send the message from server to client through unicast
                                if (sendto(client_socket, msg_to_client, sizeof(msg_to_client), 0,
                                           (struct sockaddr *) &client,
                                           sizeof(client)) < 0) {
                                }

//----------------------------------------------------------------------------------------------------------------------
//Part for debug print and syslog logging

                                else {

                                    //if we want to print the address or log we print while in reply messages
                                    if ((d_flag || l_flag) && (reply[counter + 4] == REPLY)) {

                                        len = option_length;
                                        int counter_tmp = counter;
                                        counter = lookForOptionType(IA_NA_OP, reply, counter + len, counter + 4 + 4 , &option_length);

                                        if (counter != -1) { //if we found IA_NA option

                                            len = option_length;
                                            counter = lookForOptionType(IADDAR_OP, reply, counter + len, counter + 16 , &option_length);

                                            if (counter != -1) { //looking for IA Address option within IA_NA

                                                struct in6_addr *addressReader;
                                                char assigned_address[16];
                                                addressReader = (struct in6_addr *) (reply + counter + 4);
                                                inet_ntop(AF_INET6, addressReader, assigned_address,
                                                          INET6_ADDRSTRLEN);

                                                struct ether_addr mac_print;
                                                memcpy(mac_print.ether_addr_octet, client_link_address + 2, 6);

                                                if (d_flag) {

                                                    printf("%s,%s\n", assigned_address, ether_ntoa(
                                                            (struct ether_addr *) mac_print.ether_addr_octet));
                                                }
                                                if (l_flag) {

                                                    syslog(LOG_SYSLOG, "%s, %s\n", assigned_address, ether_ntoa(
                                                            (struct ether_addr *) mac_print.ether_addr_octet));
                                                }
                                            }
                                        }

                                        else {

                                            counter = lookForOptionType(IA_PD_OP, reply, counter_tmp + len, counter_tmp + 4 + 4 , &option_length);

                                            if (counter != -1) { //looking for OPTION_IA_PD

                                                len = option_length;
                                                counter = lookForOptionType(IAPREFIX_OP, reply, counter + len, counter + 16 , &option_length);

                                                if (counter != -1) { //looking for OPTION_IAPREFIX

                                                    struct in6_addr *addressReader;
                                                    char assigned_address[16];
                                                    addressReader = (struct in6_addr *) (reply + counter + 13);
                                                    int prefix_len = (int) reply[counter + 12];
                                                    inet_ntop(AF_INET6, addressReader, assigned_address,
                                                              INET6_ADDRSTRLEN);

                                                    struct ether_addr mac_print;
                                                    memcpy(mac_print.ether_addr_octet, client_link_address + 2, 6);

                                                    if (d_flag) {

                                                        printf("%s/%d,%s\n", assigned_address, prefix_len, ether_ntoa(
                                                                (struct ether_addr *) mac_print.ether_addr_octet));
                                                    }
                                                    if (l_flag) {

                                                        syslog(LOG_SYSLOG, "%s/%d, %s\n", assigned_address, prefix_len, ether_ntoa(
                                                                (struct ether_addr *) mac_print.ether_addr_octet));
                                                    }
                                                }
                                            }

                                            else {

                                                counter = lookForOptionType(IA_TA_OP, reply, counter_tmp + len, counter_tmp + 4 + 4 , &option_length);

                                                if (counter != -1) { //if we found IA_TA option

                                                    len = option_length;
                                                    counter = lookForOptionType(IADDAR_OP, reply, counter + len, counter + 8 , &option_length);

                                                    if (counter != -1) { //looking for IA Address option within IA_TA

                                                        struct in6_addr *addressReader;
                                                        char assigned_address[16];
                                                        addressReader = (struct in6_addr *) (reply + counter + 4);
                                                        inet_ntop(AF_INET6, addressReader, assigned_address,
                                                                  INET6_ADDRSTRLEN);

                                                        struct ether_addr mac_print;
                                                        memcpy(mac_print.ether_addr_octet, client_link_address + 2, 6);

                                                        if (d_flag) {

                                                            printf("%s,%s\n", assigned_address, ether_ntoa(
                                                                    (struct ether_addr *) mac_print.ether_addr_octet));
                                                        }
                                                        if (l_flag) {

                                                            syslog(LOG_SYSLOG, "%s, %s\n", assigned_address, ether_ntoa(
                                                                    (struct ether_addr *) mac_print.ether_addr_octet));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    //cleaning
                    close(server_socket);
                    close(client_socket);
                    free(relay_message_header);
                    free(relay_message_options);
                }
            }
        }
    }

    return 0;
}

#pragma clang diagnostic pop