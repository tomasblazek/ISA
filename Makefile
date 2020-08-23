CC= g++
flags= -std=c++11 -pedantic -Wall -Wextra
all: popcl

popcl: main.cpp
	$(CC) $(flags) main.cpp -o popcl -L/etc/ssl/lib -lssl -lcrypto
