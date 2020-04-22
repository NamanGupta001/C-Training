#include "Ipv4.h"
#include "Ipv6.h"

union IpAddress
{
    struct Ipv4Header ipv4obj;
    struct Ipv6Header ipv6obj;
};