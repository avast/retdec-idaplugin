
#include <sstream>

#include "yx.h"

const YX YX::starting_yx = YX(YX::starting_y, YX::starting_x);

YX::YX(std::size_t _y, std::size_t _x)
		: y(_y)
		, x(_x)
{

}

bool YX::operator<(const YX& rhs) const
{
	std::pair<std::size_t, std::size_t> _this(y, x);
	std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
	return _this < other;
}

bool YX::operator<=(const YX& rhs) const
{
	std::pair<std::size_t, std::size_t> _this(y, x);
	std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
	return _this <= other;
}

bool YX::operator>(const YX& rhs) const
{
	std::pair<std::size_t, std::size_t> _this(y, x);
	std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
	return _this > other;
}

bool YX::operator>=(const YX& rhs) const
{
	std::pair<std::size_t, std::size_t> _this(y, x);
	std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
	return _this >= other;
}

bool YX::operator==(const YX& rhs) const
{
	std::pair<std::size_t, std::size_t> _this(y, x);
	std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
	return _this == other;
}

std::string YX::toString() const
{
	std::stringstream ss;
	ss << *this;
	return ss.str();
}

std::ostream& operator<<(std::ostream& os, const YX& yx)
{
	os << "[y=" << std::dec << yx.y << ",x=" << std::dec << yx.x << "]";
	return os;
}
