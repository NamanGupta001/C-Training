// Comes after global header
//Skipped 16bytes of packet header(it is optional)

struct ethernet_header
{
    unsigned char       ether_dhost[6];
    unsigned char       ether_shost[6];
    
    //Determines if packet is ipv4,ipv6 or arp type packet
    unsigned short int  ether_type    ;
    
    
};


