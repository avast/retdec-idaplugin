
#ifndef HEXRAYS_DEMO_FUNCTION_H
#define HEXRAYS_DEMO_FUNCTION_H

#include <iostream>
#include <map>
#include <set>
#include <vector>

#include <pro.h>

#include "token.h"
#include "yx.h"

/**
 * Decompiled function - i.e. its source code.
 * The object is XY-aware and EA-aware.
 */
class Function
{
	public:
		Function(
				const std::string& name,
				ea_t start,
				ea_t end,
				const std::vector<Token>& tokens
		);

		const std::string& getName() const;
		ea_t getStart() const;
		ea_t getEnd() const;
		/// Token at YX.
		const Token* getToken(YX yx) const;

		/// YX of the first token.
		YX min_yx() const;
		/// YX of the last token.
		YX max_yx() const;
		/// YX of the token before the token on the given YX.
		YX prev_yx(YX yx) const;
		/// YX of the token after the token on the given YX.
		YX next_yx(YX yx) const;
		/// [Starting] YX of the token which contains the given YX.
		YX adjust_yx(YX yx) const;
		/// Entire colored line containing the given YX.
		/// I.e. concatenation of all the tokens with y == yx.y
		std::string line_yx(YX yx) const;
		/// Address of the given YX.
		ea_t yx_2_ea(YX yx) const;
		/// Addresses of all the XYs with y == yx.y
		std::set<ea_t> yx_2_eas(YX yx) const;
		/// [The first] XY with the given address.
		YX ea_2_yx(ea_t ea) const;
		/// Is address inside this function?
		bool ea_inside(ea_t ea) const;

		/// Lines with associated addresses.
		std::vector<std::pair<std::string, ea_t>> toLines() const;
		std::string toString() const;
		friend std::ostream& operator<<(std::ostream& os, const Function& f);

	private:
		std::string _name;
		ea_t _start;
		ea_t _end;
		std::map<YX, Token> _tokens;
		/// Multiple YXs can be associated with the same address.
		/// This stores the first such XY.
		std::map<ea_t, YX> _ea2yx;
};

#endif
