TARGETS = mmap_test.out

all: ${TARGETS}

mmap_test.out: mmap_test.cpp
	clang -std=c++14 $< -o $@

clean:
	rm -rf ${TARGETS}
