all: arp-spoof

arp-spoof: arp-spoof.o main.o
	gcc -o arp-spoof arp-spoof.o main.o -lpcap -lpthread

main.o: arp-spoof.h main.c

arp-spoof.o: arp-spoof.h arp-spoof.c

clean:
	rm -f arp-spoof.*
	rm -f *.o