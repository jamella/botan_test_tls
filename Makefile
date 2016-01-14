all: server client

server: credentials.cpp server.cpp
	g++ -std=c++11 -I../Botan-1.11.25/build/include -L../Botan-1.11.25 -Wall credentials.cpp  server.cpp -o server -lbotan-1.11

client: credentials.cpp client.cpp
	g++ -std=c++11 -I../Botan-1.11.25/build/include -L../Botan-1.11.25 -Wall credentials.cpp  client.cpp -o client -lbotan-1.11

