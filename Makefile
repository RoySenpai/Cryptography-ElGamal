# Flags for the compiler and linker.
CC = gcc
CFLAGS = -std=c11 -g
LDFLAGS = -lgmp
RM = rm -f

# Phony targets - targets that are not files but commands to be executed by make.
.PHONY: all default clean

# Default target - compile everything and create the executables and libraries.
all: elgamal

# Alias for the default target.
default: all


############
# Programs #
############
elgamal: elgamal.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

################
# Object files #
################
%.o: %.c
	$(CC) $(CFLAGS) -c $<
	
#################
# Cleanup files #
#################
clean:
	$(RM) *.o *.so elgamal