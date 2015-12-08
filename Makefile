
all: des.c
	gcc -o des_c des.c

clean:
	rm des_c
	rm des.o
