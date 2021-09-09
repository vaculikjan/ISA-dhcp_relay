# ISA d6r project

## Description

The d6r program serves as a [DHCPv6 relay](https://tools.ietf.org/html/rfc8415) - it provides a layer of communication between a client and a server located on different networks. This implementation provides MAC address of a client in [Client Link-Layer Address Option](https://tools.ietf.org/html/rfc6939). 

## How to use

1) Compile the program using the ``make`` or ``make all`` command this creates a file named __d6r__
2) Run the program as a superuser e.g. sudo ./d6r -s _yourserver_ -d
3) To quit the program press CTRL+C to send the kill signal
4) You can use ``make clean`` to delete the __d6r__ file

## Arguments

The program can be run with multiple options passed as arguments:  
  
__-s__  
Mandatory option that specifies to which server any messages shall be relayed to.  
__-i__  
Option that specifies on which interface the program should listen for client messages. Only one interface can be selected at once. If the option is not selected, the program listens on all interfaces.  
__-d__  
This option enables the debug print to console. It prints the address, prefix if available and mac address of the client.  
__-l__  
When selected it logs the above debug output to syslog.  
__-h__  
Outputs help.  
