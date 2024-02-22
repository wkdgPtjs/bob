LDLIBS += -lnetfilter_queue

all: 1m-block

1m-block: 1m-block.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f 1m-block *.o
