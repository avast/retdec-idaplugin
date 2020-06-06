
#ifndef HEXRAYS_DEMO_YX_H
#define HEXRAYS_DEMO_YX_H

#include <iostream>
#include <utility>

/**
 * YX coordinates
 * Y = lines
 * X = columns
 */
struct YX
{
	/// lines
	std::size_t y = YX::starting_y;
	/// columns
	std::size_t x = YX::starting_x;

	inline static const std::size_t starting_y = 1;
	inline static const std::size_t starting_x = 0;
	static const YX starting_yx;

	YX(std::size_t _y = starting_y, std::size_t _x = starting_x);

	bool operator<(const YX& rhs) const;
	bool operator<=(const YX& rhs) const;
	bool operator>(const YX& rhs) const;
	bool operator>=(const YX& rhs) const;
	bool operator==(const YX& rhs) const;

	std::string toString() const;
	friend std::ostream& operator<<(std::ostream& os, const YX& yx);
};

#endif
