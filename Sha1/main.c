
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif 

#include "sha1.h"

#include <stdio.h>
#include <stdlib.h>


static const size_t PAGE_SIZE = 8192 * 64;

int main(int argc, char* argv[])
{
	const char* filename;
	void * data;
	FILE* file;
	sha1_context_t ctx;
	uint8_t bytes[20];

	if (argc != 2) {
		fprintf(stderr, "USAGE: %s <filename>\n", argv[0]);
		return -2;
	}
	
	filename = argv[1];

	data = malloc(PAGE_SIZE);
	
	if (data == NULL) {
		fprintf(stderr, "CAN'T ALLOCATE : %zu  bytes\n", PAGE_SIZE);
		return -2;
	}

	file = fopen(filename, "rb");
	
	if (file == NULL)
	{
		fprintf(stderr, "Can't open a file `%s` \n", filename);
		free(data);
		return -2;
	}

	sha1_ctx_init(&ctx);

	while (1)
	{
		size_t size;
		size = fread(data, 1, PAGE_SIZE, file);
		sha1_ctx_update(&ctx, data, size);
		if (size < PAGE_SIZE)
			break;
	}
	
	fclose(file);
	free(data);

	
	sha1_ctx_finish(&ctx);
	
	sha1_ctx_result(&ctx, bytes);

	printf("digest (sha1) of `%s` file: ", filename);

	for (size_t i = 0; i < 20; ++i) {
		printf("%02x", bytes[i]);
		if (i % 5 == 4 && i != 19)printf(" ");
	}
	
	printf("\n");

	return 0;
}