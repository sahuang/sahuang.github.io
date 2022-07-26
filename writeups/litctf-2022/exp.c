#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// image info with width, height and pixels
typedef struct {
    int w, h;
    unsigned char *px;
    unsigned char *head;
    int header; // header size
} image_t;

image_t parse_bmp(char* fname) {
    image_t x;

    FILE *tempfile = fopen(fname, "rb");
    if (!tempfile) {
        exit(1);
    }
    unsigned char* tmp = malloc(16 * sizeof(unsigned char));
    fread(tmp, sizeof(unsigned char), 16, tempfile);
    x.header = tmp[11] * 256 + tmp[10];
    fclose(tempfile);

    FILE *file = fopen(fname, "rb");
    x.head=malloc(x.header * sizeof(unsigned char));
    fread(x.head, sizeof(unsigned char), x.header, file);
    x.w = x.head[19] * 256 + x.head[18];
    x.h = x.head[23] * 256 + x.head[22];

    fseek(file, x.header, SEEK_SET);
    x.px = calloc(x.w * x.h * 3, sizeof(unsigned char));
    unsigned char *curr_pixel = calloc(1, sizeof(unsigned char));
    for(int i = 0; i < x.w * x.h * 3; i++) {
        fread(curr_pixel, 1, 1, file);
        x.px[i] = curr_pixel[0];
    }
    free(curr_pixel);
    fclose(file);
    return x;
}

unsigned char alter(unsigned char a1, int a2, unsigned char a3) {
  unsigned char result = a1;
  result ^= (a3 ^ ((((int)result >> (a2 % 8)) & 1) != 0)) << (a2 % 8);
  return result;
}

int main(int argc, char *argv[]) {
	image_t x = parse_bmp("yougotrickrolledChallenge.bmp");

    printf("Width: %d, Height: %d, Header: %d\n", x.w, x.h, x.header);

    int v3 = 0, v12 = 0, v13 = 0, v14 = 0;
    int flag[400];

    for (int jj = 0; jj <= 399; ++jj) {
        int curr = 0;
        if (v14 < 8) curr = x.px[3600 * v12 + 3 * v13 + 0];
        else if (v14 < 16) curr = x.px[3600 * v12 + 3 * v13 + 1];
        else curr = x.px[3600 * v12 + 3 * v13 + 2];
        // printf("Current pixel value: %d\n", curr);
        int cc[2]; cc[0] = 0; cc[1] = 0;
        for (int u = 1; u < 256; u++) {
            for (int v = 0; v <= 1; v++) {
                if (alter(u, v14, v) == curr) {
                    // printf("alter(%d, %d, %d) == %d\n", u, v14, v, curr);
                    cc[v]++;
                }
            }
        }
        // cc will always be (2,0) or (0,2)
        flag[jj] = (cc[0] > cc[1]) ? 0 : 1;
        v3 = v14 + 1;
        v14 = (v14 + 1) / 24;
        v14 = v3 - 24 * v14;
        if (flag[jj] == 1)
            ++v12;
        else
            ++v13;
    }

    for (int i = 0; i < 400; i+=8) {
        // binary to int
        int curr = 0;
        for (int j = 0; j < 8; j++) {
            curr = curr * 2 + flag[i+j];
        }
        printf("%c", curr);
    }

	return 0;
}