struct PacketCount
{
    unsigned int ipv6AddrCount;
    unsigned int ipv4AddrCount;

    unsigned int ipv6TcpCount;
    unsigned int ipv4TcpCount;

    unsigned int ipv6UdpCount;
    unsigned int ipv4UdpCount;

    PacketCount()
    {
        ipv6AddrCount=0;
        ipv4AddrCount=0;
        ipv6TcpCount=0;
        ipv6UdpCount=0;
        ipv4TcpCount=0;
        ipv4UdpCount=0;

    }
};