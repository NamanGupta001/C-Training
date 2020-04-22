#include <iostream>
#include <unordered_map>
#include <utility>
#include <iterator>
#include "packetTransfer.h"

//Defines the hash function for using pair in unordered map
struct pair_hash
{
	template <class T1, class T2>
	std::size_t operator() (const std::pair<T1, T2> &pair) const
	{
		std::hash<T1>()(pair.first)<<8;
        return std::hash<T1>()(pair.first) ^ std::hash<T2>()(pair.second);
	}
	
};

typedef std::pair<std::string,std::string> ippair;

struct PairIP
{
	 std::unordered_map<ippair,PacketTransferStats,pair_hash> dualip_map;
	 void populatePairMap(std::string src,std::string destn,unsigned int timeStamp);
	 void displayPairMap();
};

//Insert values in unordered map
void PairIP::populatePairMap(std::string src,std::string destn,unsigned int timeStamp)
{
	
	std::unordered_map<ippair,PacketTransferStats,pair_hash>::iterator traverse,exchangeTraverse;
	
	bool isSrcToDestn = false;
	bool isDestnToSrc = false;
	
	traverse = dualip_map.find(ippair(src,destn));
	exchangeTraverse = dualip_map.find(ippair(destn,src));
	
	if (traverse != dualip_map.end())
	{
		
		isSrcToDestn = true;
		dualip_map[ippair(src,destn)].endTs = timeStamp;
		 
		dualip_map[ippair(src,destn)].srcToDestn += 1;
	}
	
	else if (exchangeTraverse != dualip_map.end())
	{
		
		isDestnToSrc = true;
		dualip_map[ippair(destn,src)].endTs = timeStamp;
		dualip_map[ippair(destn,src)].destnToSrc +=1;
		
	}

	else if (! (isSrcToDestn && isDestnToSrc) )
	{
		
		PacketTransferStats obj;
		obj.srcToDestn = 1;
		obj.destnToSrc = 0;

		obj.beginTs    = timeStamp;
		obj.endTs	   = timeStamp;
		

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
				  << entry.second.srcToDestn <<" "<< entry.second.destnToSrc<<" "<<
				     "sess. time\t"<<entry.second.endTs - entry.second.beginTs<<'\n';
	}
}

int main()
{
	PairIP ob;
	ob.populatePairMap("naman","aman",2);
	ob.populatePairMap("nan","an",5);
	ob.populatePairMap("naman","aman",10);
	ob.populatePairMap("aman","naman",13);

	ob.displayPairMap();

}