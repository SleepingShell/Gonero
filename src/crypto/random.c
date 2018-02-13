#include "random.h"
#include "./hash/hash.h"

#if defined(_WIN32)

//TODO: Generate randomness on Windows
//TODO: Look into replacing with Bitcoin RNG
#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>

union hash_state state;
bool init = false;

void random_bytes_system(size_t n, void* dest) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        err(EXIT_FAILURE, "error opening /dev/urandom");
    } else {
        ssize_t res = read(fd, dest, n);
        if (res < n) {
            err(EXIT_FAILURE, "error reading /dev/urandom");
        }

    }
    close(fd);
}

void init_rng() {
    random_bytes_system(32, &state);
}

//Not thread safe
void gen_random_bytes(size_t n, void* dest) {
    if (!init) {
        init_rng();
    }
    for (;;) {
        keccakf(&state,25);
        if (n <= HASH_DATA_AREA) {
            memcpy(dest, &state, n);
            return;
        } else {
            memcpy(dest,&state,HASH_DATA_AREA);
            dest = dest + HASH_DATA_AREA; //Move pointer along to next chunk of bytes
            n -= HASH_DATA_AREA;
        }
    }
}

#endif