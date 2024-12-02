#include <stdio.h>

#include "blob.h"
#include "detect.h"


int main(void)
{
	struct blob s, **lines = NULL;
	size_t i, n;

	blob_from_file(&s, "./f/8.txt");
	n = blob_split(&lines, &s, '\n');

	for (i = 0; i < n; i++)
		if (detect_aes_ecb(lines[i], 32))
			blob_print(lines[i], 0);
}
