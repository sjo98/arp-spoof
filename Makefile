all : arp-spoof

arp-spoof: main.o
	g++ -g -o arp-spoof main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp-spoof
	rm -f *.o

