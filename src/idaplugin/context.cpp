
#include <sstream>
#include <iomanip>

#include "context.h"

int demo_msg(const char *format, ...)
{
	static unsigned msgCntr = 0;

	va_list va;
	va_start(va, format);
	std::stringstream ss;
	ss << "demo #" << std::setw(5) << std::left << msgCntr++
			<< " -- " << format;
	auto ret = vmsg(ss.str().c_str(), va);
	va_end(va);
	return ret;
}
