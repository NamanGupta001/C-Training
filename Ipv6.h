struct Ipv6Header
{
    unsigned char       next_header;
    unsigned char       ipv6_source[16];
    unsigned char       ipv6_destn [16];

};
