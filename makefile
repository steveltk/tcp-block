LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o
	g++ $^ $(LDLIBS) -g -o $@

clean:
	rm -rf tcp-block *.o
