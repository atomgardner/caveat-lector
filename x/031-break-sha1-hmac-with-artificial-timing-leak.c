#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>

#include "hmac.h"
#include "sha1.h"
#include "blob.h"
#include "utils.h"

pthread_t hmac_server_thread;
struct sockaddr_un w_addr = {
	.sun_family = AF_UNIX,
	.sun_path = "\x00x031", // Linux Abstract Socket Namespace
};

// Messages are delimited by 0x00
int read_msg(int fd, struct blob *pending, struct blob *data)
{
	ssize_t cnt = 0, i = 0;
	uint8_t buf[BUFSIZ];

	for (;;) {
		cnt = read(fd, buf, BUFSIZ);
		if (cnt < 0)
			return 0;

		blob_add(pending, buf, cnt);
		i = blob_contains(pending, 0x00);

		if (i < 0)
			continue;
		//
		// unprocessed reads contain a message boundary;
		//
		blob_add(data, pending->buf, i + 1);
		memcpy(pending->buf, pending->buf + i + 1, cnt - i - 1);
		pending->len = cnt - i - 1;

		return 1;
	}
}

void *hmac_server(void *args)
{
	int leak = 1, naps = -1;
	struct blob secret_key = { 0 };
	struct timespec sleep_for  = {
		.tv_sec = 0,
		// .tv_nsec = 50 * 1000000,// 50    ms
		// .tv_nsec = 50 * 100000, //  5    ms
		// .tv_nsec = 10 * 100000, //  1    ms
		// .tv_nsec =  1 * 100000, //   100 us
		   .tv_nsec =       75000, //    75 us
		//
		// these need better stats to work reliably
		//
		// .tv_nsec =       50000, //    50 us
		// .tv_nsec =       10000, //    10 us
		// .tv_nsec =       1000, //      1 us
	};
	struct hmac hmac = {
		.key = &secret_key,
		.hash = sha1_oneshot,
	};
	uint8_t hmac_hash[40] = { 0 }; 
	blob_init_rand(&secret_key, 32);

	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(s, (struct sockaddr *)&w_addr, sizeof(struct sockaddr_un)) < 0) {
		printf("bind failed\n");
		return NULL;
	}

	if (listen(s, 1) == -1) {
		printf("listen failed\n");
		return NULL;
	}

	int in = accept(s, NULL, NULL);
	struct blob pending = { 0 };
	struct blob resp = { 0 };
	struct blob data = { 0 };
	struct blob file_data = { 0 };
	struct blob digest = { 0 };
	for (;;) {
		struct blob **file_hmac_pair = NULL;

		if (!read_msg(in, &pending, &data))
			exit(1);
		int n = blob_split(&file_hmac_pair, &data, '&');
		if (n != 2 ) {
			fprintf(stderr, " s| err: split msg into %d pieces\n", n);
			exit(1);
		} else if (file_hmac_pair[0]->len < 6	// file=
		|| file_hmac_pair[1]->len < 30) {	// signature=<20 bytes hex-encoded>
			fprintf(stderr, " s| err: malformed message\n");
			blob_print(file_hmac_pair[0], 0);
			blob_print(file_hmac_pair[1], 0);
			exit(1);
		}

		// - open the file
		// - calculate the hmac
		// - validate
		blob_add_byte(file_hmac_pair[0], 0x00, 1);
		blob_from_file(&file_data, (char *)(file_hmac_pair[0]->buf + 5));
		if (file_data.len < 2) {
			fprintf(stderr, "boo!\n");
			exit(123);
		}

		hmac_create(&hmac, &file_data, &digest);
		for (size_t t = 0; t < 5; t++)
			sprintf((char *)(hmac_hash + 8*t), "%08x", ((uint32_t *)digest.buf)[t]);

		if (leak) {
			printf(" s|   target: %40s\n", hmac_hash);
			leak = 0;
		}

		for (size_t k = 0; k < 39; k += 2) {
			if (hmac_hash[k] == file_hmac_pair[1]->buf[10 + k]
			&& hmac_hash[k + 1] == file_hmac_pair[1]->buf[10 + k + 1]) {
				if (k > naps) {
					blob_print_hex(&digest);
					naps = k;
				}
				nanosleep(&sleep_for, NULL);
			} else {
				blob_add(&resp, (uint8_t *)"badd", 5);
				goto early_exit;
			}
		}
		blob_add(&resp, (uint8_t *)"good", 5);

early_exit:
		blob_write(&resp, in);
		blob_reset(&resp);
		blob_reset(&data);
		blob_reset(&file_data);
		blob_reset(&digest);

		blob_free(file_hmac_pair[0]);
		blob_free(file_hmac_pair[1]);
		free(file_hmac_pair);
	}

	return NULL;
}

int main(void)
{
	pthread_create(&hmac_server_thread, NULL, hmac_server, NULL);

        // We know there's a 50ms sleep after checking each byte, and an early
        // exit when we get it wrong. So search over the first byte until we
        // detect a delay; repeat for the next 38 bytes.

        int conn = socket(AF_UNIX, SOCK_STREAM, 0);
	int res;
	fprintf(stderr, " c| connecting.");
	do {
		fprintf(stderr, ".");
		fflush(stderr);
		res = connect(conn, (struct sockaddr *)&w_addr, sizeof(w_addr));
	} while (res != 0);
	printf("\r c| connected                         \n");


	uint64_t last = 0;
	uint8_t guess[20] = { 0 };
	struct blob req = { 0 };

	uint8_t msg[] = "file=f/4.txt&signature=";
	blob_add(&req, msg, sizeof(msg));
	blob_add_byte(&req, 0x00, 2*sizeof(guess));

	for (size_t index = 0; index < sizeof(guess); index++) {
		uint64_t wait = last;
		uint8_t leader = 0x00;
		struct blob pending = { 0 };

		for (uint32_t b = 0; b < 256; b++) {
			uint64_t split = 0; // resp time

			guess[index] = b;
			bytes_to_hex(guess, sizeof(guess),
					&req.buf[req.len - 41]);

			// Hollywood theatrics
			fprintf(stderr,
				" c|  testing: %s\r", &req.buf[req.len-41]);

			for (size_t s = 0; s < 500; s++) {
				struct timespec then = { 0 }, now = { 0 };
				struct blob data = { 0 };

				blob_write(&req, conn);
				clock_gettime(CLOCK_MONOTONIC, &then);
				read_msg(conn, &pending, &data);
				clock_gettime(CLOCK_MONOTONIC, &now);

				// split is in nanoseconds
				split += now.tv_sec == then.tv_sec ?
					(now.tv_nsec - then.tv_nsec) :
					(1000000000 * (now.tv_sec - then.tv_sec)
						+ now.tv_nsec) - then.tv_nsec;

				blob_free(&data);
			}
			if (split > wait) {
				wait = split;
				leader = b;
			}
		}

		guess[index] = leader;
	}

	close(conn);
}
