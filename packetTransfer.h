/***********************************************************************************************************************************************
**************This header file defines the structure which will be used as a value in unordered map of packet transfer stats********************
***********************************************************************************************************************************************/
#ifndef PACKET_TRANSFER_STATS_H
#define PACKET_TRANSFER_STATS_H

struct PacketTransferStats
{
    unsigned int src_to_destn;
    unsigned int destn_to_src;
    unsigned int begin_ts;
    unsigned int end_ts;
   
};

#endif 
