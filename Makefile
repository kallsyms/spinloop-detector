build: test

test: test.c
	gcc test.c -o test

clean:
	rm -f test
