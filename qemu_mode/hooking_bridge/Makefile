.PHONY: clean

all: plugin
SRC=./src
BLD=./build
INC=-I./inc -I../qemuafl/include -I$(GLIB_H) -I$(GLIB_CONFIG_H)
# CC=gcc

$(BLD)/patching.o:$(SRC)/patching.c
	$(CC) -c -fPIC $(INC) -o $(BLD)/patching.o $(SRC)/patching.c
	
plugin:$(SRC)/main.c $(BLD)/patching.o
	$(CC) -c -fPIC $(INC) -o $(BLD)/plugin.o $(SRC)/main.c
	$(CC) -shared -o $(BLD)/plugin.so $(BLD)/plugin.o $(BLD)/patching.o

clean:
	rm -rf $(BLD)/*.o
	rm -rf $(BLD)/*.so