all: parse
parse:  pcap-parsing.o extractFiles.o writeToCsv.o display.o uniqueIPCount.o pairIPds.o 
		g++ -ggdb3 pcap-parsing.o -lpthread extractFiles.o writeToCsv.o display.o uniqueIPCount.o pairIPds.o -o parse

pcap-parsing.o: pcap-parsing.cpp
	g++ -c -ggdb3 pcap-parsing.cpp	-lpthread

extractFiles.o: extractFiles.cpp
	g++ -c -ggdb3 extractFiles.cpp

writeToCsv.o: writeToCsv.cpp
	g++ -c -ggdb3 writeToCsv.cpp

display.o: display.cpp
	g++ -c display.cpp	

uniqueIPCount.o: uniqueIPCount.cpp
	g++ -c -std=c++11 -ggdb3 uniqueIPCount.cpp

pairIPDs.o: pairIPds.cpp
	g++ -c -std=c++11 -ggdb3 pairIPds.cpp

clean:
	rm -rf *o parse		