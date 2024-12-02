#include <stdio.h>

#include "blob.h"

int main() {
	uint8_t msg[] = "49276d206b696c6c696e6720796f757220627261"
		"696e206c696b65206120706f69736f6e6f757320";
	struct blob *m;

	m = blob_from_buf(msg, sizeof(msg) - 1);
	printf("%s\n", m->buf);
	blob_free(m);
	free(m);

	return 0;
}
