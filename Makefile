SHELL   := bash # for <() diffing

bins    := $(basename $(shell find x/*.c))
bins    += $(basename $(shell find t/*.c))
libs    := $(shell find *.c)
objs    := $(libs:.c=.o)
ltests  := $(basename $(shell find t/*.c))

CFLAGS += -O2 -I. -Wall -ggdb
# CFLAGS += -O2 -I. -Wall -ggdb -Dblob_v2
LDLIBS += -lcrypto

all: $(bins) $(ltests)

# XXX: lots of unnecessary linking here
$(ltests): $(objs)
$(bins): $(objs)
x/031%: x/031%.c $(objs)
	cc $(CFLAGS)    $^ $(LDLIBS) -pthread -o $@ 
x/033%: x/033%.c $(objs)
	cc $(CFLAGS)    $^ $(LDLIBS) -lgmp -o $@ 
x/034%: x/034%.c $(objs)
	cc $(CFLAGS)    $^ $(LDLIBS) -lgmp -o $@ 

set1: x001 x002 x003 x004 x005 x006 x007 x008
set2: x009 x010 x011 x012 x013 x014 x015 x016
set3: x017 x018 x019 x020 x021 x022 x023 x024
set4: x025 x026 x027 x028 x029 x030 x031 x032 
set5: x033 x034 x035 

x001:
	@echo -n "001: "
	@diff <(./x/001-bytes_to_b64 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d) \
	<(echo "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") >/dev/null \
	&& echo "success" || echo "failure" 

x002:
	@echo -n "002: "
	@diff <(./x/002-fixed_xor 1c0111001f010100061a024b53535009181c 686974207468652062756c6c277320657965) \
	<(echo 746865206b696420646f6e277420706c6179) >/dev/null \
	&& echo "success" || echo "failure" 

x003:
	@echo -n "003: "
	@./x/003-single-byte_xor_cipher 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

x004:
	@echo -n "004: "
	@./x/004-detect_single_char_xor ./f/4.txt

x005:
	@echo -n "005: "
	@diff <(./x/005-repeating-key-xor) \
	<(echo 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f) >/dev/null \
	&& echo "success" || echo "failure" 

x006:
	@echo -n "006: "
	@./x/006-break-repeating-key-xor

x007:
	@echo -n "007: "
	@./x/007-aes-in-ecb-mode |hexdump -C
	
x008:
	@echo -n "008: "
	@./x/008-detect-aes-in-ecb-mode

x009:
	@echo -n "009: "
	@./x/009-pkcs-padding
x010:
	@echo -n "010: "
	@./x/010-aes-in-cbc-mode
x011:
	@echo -n "011: "
	@./x/011-ecb-cbc-detection-oracle
x012:
	@echo -n "012: "
	@./x/012-byte-at-a-time-ecb-decryption
x013:
	@echo -n "013:"
	@./x/013-ecb-cut-and-paste
x014:
	@echo -n "014:"
	@./x/014-byte-at-a-time-ecb-decryption
x015:
	@echo -n "$@: "
	./x/015-pkcs-padding-validation
x016:
	./x/016-cbc-bit-flipping
x017:
	./x/017-the-cbc-padding-oracle
x018:
	./x/018-aes-ctr
x019:
	@echo 'This one is interactive; exec the following if you want to play'
	@echo '	./x/019-break-fixed-nonce-ctr'
x020:
	./x/020-break-fixed-nonce-ctr-using-stats
x021:
	./x/021-mersenne-twister
x022:
	./x/022-crack-an-mt19937-seed
x023:
	./x/023-clone-an-mt19937
x024:
	./x/024-mt19937-stream-cipher
x025:
	./x/025-break-rarw-aes-ctr
x026:
	./x/026-ctr-bitflipping
x027:
	./x/027-recover-cbc-key-when-key-eq-iv
x028:
	./x/028-hash1-hmac
x029:
	./x/029-sha1-keyed-hmac-length-extension
x030:
	./x/030-md4-hmac-length-extension

x031 x032:
	@echo 'This one is very time consuming'
	@echo './x/031-break-sha1-hmac-with-artificial-timing-leak'
x033:

clean:
	rm -f $(objs) $(bins)
