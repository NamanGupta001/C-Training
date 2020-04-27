/***********************************************************************************************************************************************
***This header file declares hash function for unordered map for packet transfer stats alongwith functions that fills the map and display it***
***********************************************************************************************************************************************/

#ifndef PAIR_IP_DS_H
#define PAIR_IP_DS_H

#include "packetTransfer.h"

#include <unordered_map>

//Defines the hash function for using pair in unordered map
class pair_hash
{
	public:
	template <class T1, class T2>
	std::size_t operator() (const std::pair<T1, T2> &pair) const
	{
		std::hash<T1>()(pair.first)<<8;
        return std::hash<T1>()(pair.first) ^ std::hash<T2>()(pair.second);
	}
	
};

typedef std::pair<std::string,std::string> ippair;

class PairIP
{	
	public:

	//Getter func. for unordered map
	std::unordered_map<ippair,PacketTransferStats,pair_hash> getPairIpMap();	

	//Insert values in unordered map
	void populatePairMap(std::string src,std::string destn,unsigned int timeStamp);
	 
	//Displays key value pairs of map 
	void displayPairMap();

	private:

	//unordered map that stores string pair as keys and object as value
	std::unordered_map<ippair,PacketTransferStats,pair_hash> dualip_map;
};

#endif
