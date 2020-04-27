
struct global_header
{
    unsigned int         magic_number;
    unsigned short int   version_major;
    unsigned short int   version_minor;
    
    // 8 bytes skipped in gmt and timezone accuracy

    //65535 is the maximum length of snaplen
    unsigned int         uint32_snaplen;
    
    //1 is for ethernet in network
    unsigned int         uint32_network;
};
