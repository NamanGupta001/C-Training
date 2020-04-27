#include <iostream>
#include <unordered_map>
#include <utility>
#include <iterator>

#include "pairIPds.h"


std::unordered_map<ippair,PacketTransferStats,pair_hash> PairIP::getPairIpMap()
{
	return dualip_map;
}

void PairIP::populatePairMap(std::string src,std::string destn,unsigned int timeStamp)
{
	
	std::unordered_map<ippair,PacketTransferStats,pair_hash>::iterator itrTraverse,itrExchangeTraverse;
	
	bool isSrcToDestn = false;
	bool isDestnToSrc = false;
	
	itrTraverse         = dualip_map.find(ippair(src,destn));
	itrExchangeTraverse = dualip_map.find(ippair(destn,src));
	
	if (itrTraverse != dualip_map.end())
	{
		
		isSrcToDestn = true;

		//Updates end timestamp till last packet arrives with its timestamp
		dualip_map[ippair(src,destn)].end_ts = timeStamp;
		 
		//Increment packet count between pair of ip's
		dualip_map[ippair(src,destn)].src_to_destn += 1;
	}
	
	else if (itrExchangeTraverse != dualip_map.end())
	{
		
		isDestnToSrc = true;

		//Updates end timestamp till last packet arrives with its timestamp
		dualip_map[ippair(destn,src)].end_ts = timeStamp;
		
		//Increment packet count between pair of ip's
		dualip_map[ippair(destn,src)].destn_to_src +=1;
		
	}

	else if (! (isSrcToDestn && isDestnToSrc) )
	{
		//Insert new entry in map
		PacketTransferStats obj;
		obj.src_to_destn = 1;
		obj.destn_to_src = 0;

		//For first packet the start and end timestamp would be equal
		obj.begin_ts    = timeStamp;
		obj.end_ts	   = timeStamp;
		
		dualip_map.insert(std::make_pair(ippair(src,destn),obj));
	}

	
}

//Displays ip combination map
void PairIP::displayPairMap()
{
	for (auto const &entry: dualip_map)
	{
		auto key_pair = entry.first;
		std::cout << "{" << key_pair.first << "," << key_pair.second << "}, "
				  << entry.second.src_to_destn <<" "<< entry.second.destn_to_src<<" "<<
				     "sess. time\t"<<entry.second.end_ts - entry.second.begin_ts<<'\n';
	}
}
