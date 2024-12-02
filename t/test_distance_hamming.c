#include <stdio.h>
#include <stdint.h>

#include "utils.h"

int main(void)
{
	return distance_hamming((uint8_t *)"this is a test", (uint8_t *)"wokka wokka!!!", 14);
}
