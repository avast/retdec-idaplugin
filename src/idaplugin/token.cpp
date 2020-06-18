
#include <map>

#include <lines.hpp>
#include <pro.h>

#include "token.h"

std::map<Token::Kind, std::string> TokenColors =
{
	{Token::Kind::NEW_LINE, SCOLOR_DEFAULT},
	{Token::Kind::WHITE_SPACE, SCOLOR_DEFAULT},
	{Token::Kind::PUNCTUATION, SCOLOR_KEYWORD},
	{Token::Kind::OPERATOR, SCOLOR_KEYWORD},
	{Token::Kind::ID_GVAR, SCOLOR_DREF},
	{Token::Kind::ID_LVAR, SCOLOR_DREF},
	{Token::Kind::ID_MEM, SCOLOR_DREF},
	{Token::Kind::ID_LAB, SCOLOR_DREF},
	{Token::Kind::ID_FNC, SCOLOR_DEFAULT},
	{Token::Kind::ID_ARG, SCOLOR_DREF},
	{Token::Kind::KEYWORD, SCOLOR_MACRO},
	{Token::Kind::TYPE, SCOLOR_MACRO},
	{Token::Kind::PREPROCESSOR, SCOLOR_AUTOCMT},
	{Token::Kind::INCLUDE, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_BOOL, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_INT, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_FP, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_STR, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_SYM, SCOLOR_NUMBER},
	{Token::Kind::LITERAL_PTR, SCOLOR_NUMBER},
	{Token::Kind::COMMENT, SCOLOR_AUTOCMT},
};

std::map<Token::Kind, std::string> TokenKindStrings =
{
	{Token::Kind::NEW_LINE, "NEW_LINE"},
	{Token::Kind::WHITE_SPACE, "WHITE_SPACE"},
	{Token::Kind::PUNCTUATION, "PUNCTUATION"},
	{Token::Kind::OPERATOR, "OPERATOR"},
	{Token::Kind::ID_GVAR, "ID_GVAR"},
	{Token::Kind::ID_LVAR, "ID_LVAR"},
	{Token::Kind::ID_MEM, "ID_MEM"},
	{Token::Kind::ID_LAB, "ID_LAB"},
	{Token::Kind::ID_FNC, "ID_FNC"},
	{Token::Kind::ID_ARG, "ID_ARG"},
	{Token::Kind::KEYWORD, "KEYWORD"},
	{Token::Kind::TYPE, "TYPE"},
	{Token::Kind::PREPROCESSOR, "PREPROCESSOR"},
	{Token::Kind::INCLUDE, "INCLUDE"},
	{Token::Kind::LITERAL_BOOL, "LITERAL_BOOL"},
	{Token::Kind::LITERAL_INT, "LITERAL_INT"},
	{Token::Kind::LITERAL_FP, "LITERAL_FP"},
	{Token::Kind::LITERAL_STR, "LITERAL_STR"},
	{Token::Kind::LITERAL_SYM, "LITERAL_SYM"},
	{Token::Kind::LITERAL_PTR, "LITERAL_PTR"},
	{Token::Kind::COMMENT, "COMMENT"},
};

Token::Token()
{

}

Token::Token(Kind k, ea_t a, const std::string& v)
		: kind(k)
		, ea(a)
		, value(v)
{

}

const std::string& Token::getKindString() const
{
	return TokenKindStrings[kind];
}

const std::string& Token::getColorTag() const
{
	return TokenColors[kind];
}
