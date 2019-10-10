all : pcap_test

pcap_test: main.o pcap_func.o
        g++ -g -o pcap_test main.o pcap_func.o -lpcap

main.o: pcap_func.h main.cpp
        g++ -g -c -o main.o main.cpp

pcap_func.o: pcap_func.h pcap_func.cpp
        g++ -g -c -o pcap_func.o pcap_func.cpp

clean:
        rm -f pcap_test
        rm -f *.o
