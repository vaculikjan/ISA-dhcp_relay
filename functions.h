//
//  functions.h
//  Functions declarations
//
//  Created by Jan Vaculik on 15/11/2019.
//  Copyright © 2019 Jan Vaculik. All rights reserved.
//

#ifndef ISA_FUNCTIONS_H
#define ISA_FUNCTIONS_H

int createSocket(const char *iface_name, int port);
struct dhcpv6_relay_message_options* setOptions(int option_len, int opt_num);
int lookForOptionType(int option_no, const unsigned char reply[1024], int msg_lngth, int counter, int *option_length);

#endif //ISA_FUNCTIONS_H
