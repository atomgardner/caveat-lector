#include <stdio.h>
#include <stdlib.h>

#include "blob.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	char *path = argv[1];

	struct blob all = { 0 };

	if (!blob_from_file(&all, path))
		return 1;

	struct blob **lines;
	size_t n = blob_split(&lines, &all, '\n');

	for (size_t i = 0; i < n; i++) {
		printf("%s\n", lines[i]->buf);
	}
	return 0;
}
