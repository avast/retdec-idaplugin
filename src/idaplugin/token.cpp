
#include <map>

#include <lines.hpp>
#include <pro.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include <retdec/common/address.h>

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

std::vector<Token> parseTokens(const std::string& json, ea_t defaultEa)
{
	std::vector<Token> res;

	rapidjson::StringStream rss(json.c_str());
	rapidjson::Document d;
	rapidjson::ParseResult ok = d.ParseStream(rss);
	if (!ok)
	{
		std::string errMsg = GetParseError_En(ok.Code());
		WARNING_GUI("Unable to parse decompilation output: "
				<< errMsg << std::endl
		);
		return res;
	}

	auto tokens = d.FindMember("tokens");
	if (tokens == d.MemberEnd() || !tokens->value.IsArray())
	{
		WARNING_GUI("Unable to parse tokens from decompilation output.\n");
		return res;
	}

	ea_t ea = defaultEa;

	for (auto i = tokens->value.Begin(), e = tokens->value.End(); i != e; ++i)
	{
		auto& obj = *i;
		if (obj.IsNull())
		{
			continue;
		}

		auto addr = obj.FindMember("addr");
		if (addr != obj.MemberEnd() && addr->value.IsString())
		{
			retdec::common::Address a(addr->value.GetString());
			ea = a.isDefined() ? a.getValue() : defaultEa;
		}
		auto kind = obj.FindMember("kind");
		auto val = obj.FindMember("val");
		if (kind != obj.MemberEnd() && kind->value.IsString()
				&& val != obj.MemberEnd() && val->value.IsString())
		{
			Token::Kind kk;
			std::string k = kind->value.GetString();
			if (k == "nl") kk = Token::Kind::NEW_LINE;
			else if (k == "ws") kk = Token::Kind::WHITE_SPACE;
			else if (k == "punc") kk = Token::Kind::PUNCTUATION;
			else if (k == "op") kk = Token::Kind::OPERATOR;
			else if (k == "i_gvar") kk = Token::Kind::ID_GVAR;
			else if (k == "i_lvar") kk = Token::Kind::ID_LVAR;
			else if (k == "i_mem") kk = Token::Kind::ID_MEM;
			else if (k == "i_lab") kk = Token::Kind::ID_LAB;
			else if (k == "i_fnc") kk = Token::Kind::ID_FNC;
			else if (k == "i_arg") kk = Token::Kind::ID_ARG;
			else if (k == "keyw") kk = Token::Kind::KEYWORD;
			else if (k == "type") kk = Token::Kind::TYPE;
			else if (k == "preproc") kk = Token::Kind::PREPROCESSOR;
			else if (k == "inc") kk = Token::Kind::INCLUDE;
			else if (k == "l_bool") kk = Token::Kind::LITERAL_BOOL;
			else if (k == "l_int") kk = Token::Kind::LITERAL_INT;
			else if (k == "l_fp") kk = Token::Kind::LITERAL_FP;
			else if (k == "l_str") kk = Token::Kind::LITERAL_STR;
			else if (k == "l_sym") kk = Token::Kind::LITERAL_SYM;
			else if (k == "l_ptr") kk = Token::Kind::LITERAL_PTR;
			else if (k == "cmnt") kk = Token::Kind::COMMENT;
			else continue;

			res.emplace_back(Token(kk, ea, val->value.GetString()));
		}
	}

	return res;
}
