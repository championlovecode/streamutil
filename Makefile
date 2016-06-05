# targets
BIN = streamutil
OBJS= streamutil.c crypto_api.c crypto_module.c

# openssl
OPENSSLDIR = ../build-openssl-for-FIPS-x86/ssl/

# relevant path
INCLUDES = -I$(OPENSSLDIR)/include/
INCLUDES += -I$(OPENSSLDIR)/fips2.0/include/
LFLAGS = -L$(OPENSSLDIR)/lib/

# compiler
CC = $(OPENSSLDIR)/fips2.0/bin/fipsld
export FIPSLD_CC=gcc
CFLAGS = -Wall -g

# for FIPS
FIPSMODULE = $(OPENSSLDIR)/fips2.0/lib/fipscanister.o

# librarys
LIBS = $(OPENSSLDIR)/lib/libcrypto.a
LIBS += $(OPENSSLDIR)/lib/libssl.a
LIBS += -ldl

$(BIN):clean $(OBJS) $(FIPSMODULE)
	$(CC) $(CLFAGS) -o $@ $(OBJS) $(INCLUDES) $(LFLAGS) $(LIBS) -lasound `pkg-config --cflags --libs libpjproject`

clean:
	rm -rf $(BIN) *.o



##all:
##	gcc -o streamutil streamutil.c   -lasound `pkg-config --cflags --libs libpjproject`
###	gcc -o main main.c
