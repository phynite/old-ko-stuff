/*** USKO Encrypter by phynite ***/
/***     KOLegends Project    ***/


#include "Encrypter.h"
#include <string>
#include <string.h>
#include <stdlib.h>

#define VALID_ENC 36

std::string enc_pass;

extern "C" __declspec (dllexport) uint32_t __cdecl first(uint32_t input)
{
	uint32_t result = 0;
	uint32_t data;

	uint8_t* KEY = (uint8_t*)	"\x1A\x1F\x11\x0A\x1E\x10\x18\x02\x1D\x08\x14\x0F\x1C\x0B\x0D\x04"
								"\x13\x17\x00\x0C\x0E\x1B\x06\x12\x15\x03\x09\x07\x16\x01\x19\x05"
								"\x12\x1D\x07\x19\x0F\x1F\x16\x1B\x09\x1A\x03\x0D\x13\x0E\x14\x0B"
								"\x05\x02\x17\x10\x0A\x18\x1C\x11\x06\x1E\x00\x15\x0C\x08\x04\x01";

	for (int i = 0; i < 64; ++i) {
		data = input - (input & 0xFFFFFFFE);

		input >>= 1;

		if (data)
			result += data << KEY[i];

		if (!input)
			return result;
	}

	return result;
}

extern "C" __declspec (dllexport) void __cdecl last(uint32_t input)
{
	uint8_t* KEY = (uint8_t*)"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	uint32_t data = 0;


	for (int i = 0; i < 7; i++) {
		data = (((uint64_t)input) * 0x38e38e39) >> 35;

		input -= ((data * 9) << 2);

		if (input < VALID_ENC)
			enc_pass += KEY[input];

		input = data;
	}
}

extern "C" __declspec (dllexport) const char* __cdecl phycrypt(const char *passwd)
{
	uint8_t length = strlen(passwd);
	uint8_t x;
	uint32_t *data;

	x = length % 4;

	if (x)
		x = 4 - x;
		
	data = (uint32_t*)malloc(length + x);
	memcpy((void*)data, (void*)passwd, length);

	if (x) {
		memset((void*)(((uint8_t*)data) + length), 0, x);
		length += x;
	}

	length /= 4;

	for (int i = 0; i < length; i++)
		last(first(data[i] + 0x3e8));

	return enc_pass.c_str();
}
