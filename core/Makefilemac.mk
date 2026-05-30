CC = g++

#CFLAGS = -fpermissive -D DEBUG -g

CFLAGS = -fpermissive -std=c++17

LDLIBS = ./lib/cryptopp/libcryptopp.a -lpthread  -lm -loqs -lpistache

LIBS = -L./lib/liboqs/build/lib/ -L./lib/pistache/build/src/

SRC = -I./lib/liboqs/build/include/ -I./lib/rapidjson/include/ -I./lib/liboqs-cpp/include/ -I./lib/pistache/include/

RPATHS = -Wl,-rpath,@loader_path/../lib/liboqs/build/lib -Wl,-rpath,@loader_path/../lib/pistache/build/src

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	mkdir -p ./bin
	$(CC) $(CFLAGS) -o ./bin/$(TARGET) $(TARGET).cpp $(SRC) $(LIBS) $(LDLIBS) $(RPATHS)
