//
//  structs.h
//  DHCPv6 relay structs declarations
//
//  Created by Jan Vaculik on 15/11/2019.
//  Copyright © 2019 Jan Vaculik. All rights reserved.
//
#include <stdint.h>
#include <netinet/in.h>

#ifndef ISA_STRUCTS_H
#define ISA_STRUCTS_H

struct dhcpv6_relay_message_header {
    unsigned char msg_type[1];
    unsigned char hop_count[1];
    unsigned char link_address[sizeof(struct in6_addr)];
    unsigned char peer_address[sizeof(struct in6_addr)];
};
struct dhcpv6_relay_message_options {
    unsigned char options_type[2];
    unsigned char len[2];
};
struct dhcpv6_msg_reader {
    uint8_t msg_type;
};

#endif //ISA_STRUCTS_H
