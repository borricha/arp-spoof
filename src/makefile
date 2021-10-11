LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f arp-spoof *.o