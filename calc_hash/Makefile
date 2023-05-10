TARGETS = calc_hash.out

all: ${TARGETS}

calc_hash.out: calc_hash.c
	clang $< -o $@

clean:
	rm -f ${TARGETS}
