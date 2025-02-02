#pragma once
#include <stddef.h>
#include <stdint.h>

// --------------------------------------------------------------------
// 現在は、最大 64 bytes 表示するようになっている
void DBG_dump(const void* const pbuf, const int bytes);

// --------------------------------------------------------------------
consteval uint32_t operator"" _ip4_to32(const char* psrc, size_t len)
{
	uint32_t ret_val = 0;
	uint32_t cur = 0;
	for (;; --len)
	{
		if (len == 0)
		{
			ret_val = (cur << 24) + (ret_val >> 8);
			return ret_val;;
		}

		uint8_t chr = *psrc++;
		if (chr == '.')
		{
			ret_val = (cur << 24) + (ret_val >> 8);
			cur = 0;
			continue;
		}

		chr -= '0';
		if (chr >= 10) { throw "chr >= 10"; }

		cur = cur * 10 + chr;
	}
}

// --------------------------------------------------------------------
consteval uint16_t CEV_ntohs(const uint16_t val)
{
	return (val << 8) | (val >> 8);
}

// --------------------------------------------------------------------
constexpr uint16_t Cx_ntohs(const uint16_t val)
{
	return (val << 8) | (val >> 8);
}


