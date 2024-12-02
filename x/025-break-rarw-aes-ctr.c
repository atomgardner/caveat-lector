#include <stdio.h>
#include <string.h>

#include "blob.h"

int main(void)
{
	struct blob ctr_key = { 0 }, *ecb_key, msg = { 0 };
	uint8_t ecb_k[] = "YELLOW SUBMARINE";

	blob_from_file(&msg, "f/25.txt");
	blob_split_and_join(&msg, '\n');
	blob_decode_b64(&msg);

	ecb_key = blob_from_buf(ecb_k, sizeof(ecb_k));
	blob_decrypt_aes_ecb(&msg, ecb_key);

	blob_init_rand(&ctr_key, 16);
	blob_do_aes_ctr(&msg, &ctr_key);
	blob_print_ascii(&msg);

	//
	// edit everything with 0 to recover the keystream
	//
	struct blob *keystream = blob_from_buf(msg.buf, msg.len);
	struct blob *zeros = blob_from_buf(msg.buf, msg.len);
	memset(zeros->buf, 0, zeros->len);
	blob_edit_aes_ctr(&ctr_key, keystream, 0, zeros);
	//
	// recover the message by xoring with the keystream
	// 
	blob_xor_buf(&msg, keystream->buf, keystream->len);
	blob_print(&msg, 0);
	
	return 0;
}
