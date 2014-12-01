#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include "rabin.h"
#include "md5.h"

// 1MiB buffer
uint8_t buf[1024 * 1024];
size_t bytes;


int main(void) {
	struct rabin_t *hash;
	struct cvs_MD5Context context;
	unsigned char checksum[16];
	size_t len;
	uint8_t *ptr;

	hash = rabin_init();
	cvs_MD5Init(&context);
	unsigned int chunks = 0;
	while (!feof(stdin)) {
		len = fread(buf, 1, sizeof(buf), stdin);
		ptr = &buf[0];

		bytes += len;

		while (1) {
			int remaining = rabin_next_chunk(hash, ptr, len);

			if (remaining < 0) {
				cvs_MD5Update(&context, ptr, len);
				break;
			}
			else
			{
				cvs_MD5Update(&context, ptr, remaining);
				cvs_MD5Final(checksum, &context);
				len -= remaining;
				ptr += remaining;

				printf("%d %016llx, md5: ", last_chunk.length, (long long unsigned int)last_chunk.cut_fingerprint);
				for (int i = 0; i < 16; i++) printf("%02x", (unsigned int)checksum[i]);
				printf("\n");
				chunks++;
				cvs_MD5Init(&context);
			}
		}
	}

	if (rabin_finalize(hash) != NULL) {
		cvs_MD5Final(checksum, &context);
		chunks++;
		printf("%d %016llx, md5: ",
			last_chunk.length,
			(long long unsigned int)last_chunk.cut_fingerprint);
		for (int i = 0; i < 16; i++) printf("%02x", (unsigned int)checksum[i]);
		printf("\n");
	}

	unsigned int avg = 0;
	if (chunks > 0) avg = bytes / chunks;
	printf("%d chunks, average chunk size %d\n", chunks, avg);

	return 0;
}
