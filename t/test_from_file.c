#include "blob.h"

int main(void)
{ 
	struct blob data = { 0 };

	blob_from_file(&data, "f/4.txt");
	blob_print(&data, 0);
	blob_free(&data);
}
