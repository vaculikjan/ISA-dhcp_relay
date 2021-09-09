all: d6r

d6r: d6r.c functions.c
	@gcc -o d6r d6r.c functions.c -lpcap
clean:
	@rm -f d6r
