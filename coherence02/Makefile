CC = g++

CFLAGS = -D DEBUG -g -Werror 

#CFLAGS= -Werror

INCLUDES = -Ilibuv/ -Icryptopp/ -Iargon2/ -Ilibntru

LIBS = ./lib/libuv/.libs/libuv.so ./lib/cryptopp/libcryptopp.so ./lib/argon2/libargon2.so.1 ./lib/libntru/libntru.so

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(TARGET) $(TARGET).c


