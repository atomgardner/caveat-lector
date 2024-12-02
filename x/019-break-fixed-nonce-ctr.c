#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <termios.h>

#include "blob.h"

#define AES_BLK_SZ 16

uint8_t *strings[] = {
	(uint8_t *)"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	(uint8_t *)"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	(uint8_t *)"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	(uint8_t *)"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	(uint8_t *)"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	(uint8_t *)"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	(uint8_t *)"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	(uint8_t *)"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	(uint8_t *)"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	(uint8_t *)"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	(uint8_t *)"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	(uint8_t *)"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	(uint8_t *)"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	(uint8_t *)"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	(uint8_t *)"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	(uint8_t *)"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	(uint8_t *)"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	(uint8_t *)"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	(uint8_t *)"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	(uint8_t *)"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	(uint8_t *)"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	(uint8_t *)"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	(uint8_t *)"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	(uint8_t *)"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	(uint8_t *)"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	(uint8_t *)"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	(uint8_t *)"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	(uint8_t *)"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	(uint8_t *)"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	(uint8_t *)"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	(uint8_t *)"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	(uint8_t *)"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	(uint8_t *)"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	(uint8_t *)"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	(uint8_t *)"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	(uint8_t *)"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	(uint8_t *)"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	(uint8_t *)"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	(uint8_t *)"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	(uint8_t *)"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
};

void print_with_mask(struct blob **lines, uint8_t *mask, size_t num) {
	printf("\033[2J\033[1;1H");
	for (size_t k = 0; k < num; k++) {
		blob_xor_buf(lines[k], mask, lines[k]->len);
		blob_print_ascii(lines[k]);
		blob_xor_buf(lines[k], mask, lines[k]->len);
	}
	printf("\n\ncmds: ?hjklr q\n");
}


//
// Might be worth restructuring this as an exercise in good coding practices.
//
int main(void)
{
	struct blob *msg, **msgs;
	struct blob key  = { 0 };
	size_t len_keystream = 0;
	size_t len_msgs = sizeof(strings)/sizeof(strings[0]);

	blob_init_rand(&key, AES_BLK_SZ);
	msgs = malloc(len_msgs * sizeof(*msgs));

	for (size_t k = 0; k < len_msgs; k++) {
		size_t len;

		msg = blob_from_buf(strings[k], strlen((char *)strings[k]));
		len = blob_decode_b64(msg);
		if (len > len_keystream)
			len_keystream = len;

		blob_do_aes_ctr(msg, &key);

		msgs[k] = msg;
	}


	struct termios before, after = { 0 };
	tcgetattr(STDIN_FILENO, &before);
	after = before;
	after.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, 0, &after);

	uint8_t *guesses = malloc(len_keystream * sizeof(*guesses));
	size_t row = 0, col = 0;
	char c;

	print_with_mask(msgs, guesses, len_msgs);
	for (;;) {
		print_with_mask(msgs, guesses, len_msgs);
		printf("\033[%ld;%ldH", row + 1, col + 1);
		fflush(stdout);
		if (read(STDIN_FILENO, &c, 1) != 1)
			break;

		switch (c) {
		case '?':
			printf("\033[2J\033[1;1H\n");
			printf( ". move around with ViM keys `hkjl`\n"
				". go into guessing mode with `r`\n"
				". exit guessing mode with escape\n"
				"\npress any button to get back to work\n");
			fflush(stdout);
			read(STDIN_FILENO, &c, 1);
			break;

		case 'h':
			col = col == 0 ? 0 : col - 1;
			break;

		case 'l':
			col = col == msgs[row]->len - 1 ? col : col + 1;
			break;

		case 'j':
			row = row == len_msgs - 1 ? row : row + 1;
			break;

		case 'k':
			row = row == 0 ? 0 : row - 1;
			break;

		case 'r': {
			// makes things a little safer
			if (col > msgs[row]->len - 1)
				col = msgs[row]->len - 1;

			for (;;) {
				read(STDIN_FILENO, &c, 1);
				if (c == 27)
					break;
				guesses[col] = msgs[row]->buf[col] ^ c;
				print_with_mask(msgs, guesses, len_msgs);
				printf("\033[%ld;%ldH", row + 1, col + 1);
				fflush(stdout);
			}
			break;
		}

		case 'q':
		case 4:
			goto done;

		default:
			break;
		}
	}

done:
	tcsetattr(STDIN_FILENO, 0, &before);
	printf("\033[2J\033[1;1H");
	return 0;
}
