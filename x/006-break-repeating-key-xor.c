#include <stdio.h>

#include "blob.h"
#include "break.h"

int main(void)
{
	struct blob a;
	struct blob b = { 0 };
	struct blob **lines;

	blob_from_file(&a, "./f/6.txt");
	//blob_from_file(&a, "./foo.txt");
	size_t n = blob_split(&lines, &a, '\n');

	for (size_t k = 0; k < n; k++)
		blob_add_slice(&b, lines[k]);

	blob_decode_b64(&b);
	break_repeating_key_xor(&b);

	return 0;
}
