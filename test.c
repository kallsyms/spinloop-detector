#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    unsigned char stuff[1024];
    int data_left = read(0, stuff, sizeof(stuff));

    if (data_left <= 1) {
        return 0;
    }

    printf("Read %d bytes\n", data_left);

    unsigned char *ptr = stuff;
    unsigned char *end = ptr + data_left;

    while (ptr < end) {
        unsigned char opt = ptr[0];
        int optlen = ptr[1];

        switch (opt) {
            case 0:
                puts("END");
                goto done;
            case 1:
                optlen = 1;
                puts("NOP");
                break;
            case 2: // write
                puts("WRITE");
                write(1, &ptr[2], optlen-2);
                break;
            default:
                puts("INVALID");
                return 0;
        }

        ptr += optlen;
    }

done:
    return 0;
}
