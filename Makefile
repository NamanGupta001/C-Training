all: hello
hello: test.o watch.o
		g++ test.o watch.o -o hello
test.o: test.cpp
	g++ -c test.cpp
watch.o: watch.cpp
	g++ -c watch.cpp

clean:
	rm -rf *o hello		