SRC     := $(wildcard src/*.c)
PKGS    :=
CC      := clang
CFLAGS  := -Iheaders
CFLAGS  += -Wall -std=c17 #$(shell pkg-config --cflags $(PKGS))
LDFLAGS := -lcrypto #$(shell pkg-config --libs $(PKGS))
COFLAGS := -O3

.PHONY: dev clean compile cnr

dev:
	echo $(CFLAGS) | tr " " "\n" > compile_flags.txt
	echo $(LDFLAGS) | tr " " "\n" >> compile_flags.txt

clean:
	$(RM) *.o a.out

compile: $(SRC)
	$(CC) $(CFLAGS) $(COFLAGS) $(LDFLAGS) $^ -o fenc

cnr: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o a.out
	./a.out
	$(RM) *.o a.out
