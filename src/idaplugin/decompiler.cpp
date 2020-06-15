
#include <map>
#include <fstream>

#include <ida.hpp>
#include <fpro.h>

#include <retdec/retdec/retdec.h>
#include <rapidjson/error/en.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "config.h"
#include "context.h"
#include "decompiler.h"
#include "utils.h"

std::map<func_t*, Function> _fnc2fnc;

bool isRelocatable()
{
	if (inf_get_filetype() == f_COFF && inf_get_start_ea() == BADADDR)
	{
		return true;
	}
	else if (inf_get_filetype() == f_ELF)
	{
		auto inFile = getInputPath();
		if (inFile.empty())
		{
			return false;
		}

		std::ifstream infile(inFile, std::ios::binary);
		if (infile.good())
		{
			std::size_t e_type_offset = 0x10;
			infile.seekg(e_type_offset, std::ios::beg);

			// relocatable -- constant 0x1 at <0x10-0x11>
			// little endian -- 0x01 0x00
			// big endian -- 0x00 0x01
			char b1 = 0;
			char b2 = 0;
			if (infile.get(b1))
			{
				if (infile.get(b2))
				{
					if (std::size_t(b1) + std::size_t(b2) == 1)
					{
						return true;
					}
				}
			}
		}
	}

	// f_BIN || f_PE || f_HEX || other
	return false;
}

bool runDecompilation(retdec::config::Config& config)
{
	try
	{
		auto rc = retdec::decompile(config);
		if (rc != 0)
		{
			throw std::runtime_error(
					"decompilation error code = " + std::to_string(rc)
			);
		}
	}
	catch (const std::runtime_error& e)
	{
		WARNING_GUI("Decompilation exception: " << e.what() << std::endl);
		return true;
	}
	catch (...)
	{
		WARNING_GUI("Decompilation exception: unknown" << std::endl);
		return true;
	}

	return false;
}

Function* parseOutput(func_t* fnc, const std::string& out)
{
	std::ifstream ifs(out);
	if (!ifs)
	{
		WARNING_GUI("Unable to open decompilation output: "
				<< out << std::endl
		);
		return nullptr;
	}

	rapidjson::IStreamWrapper isw(ifs);
	rapidjson::Document d;
	rapidjson::ParseResult ok = d.ParseStream(isw);
	if (!ok)
	{
		std::string errMsg = GetParseError_En(ok.Code());
		WARNING_GUI("Unable to parse decompilation output: "
				<< out << std::endl
				<< "Parser error: " << errMsg << std::endl
		);
		return nullptr;
	}

	auto tokens = d.FindMember("tokens");
	if (tokens == d.MemberEnd() || !tokens->value.IsArray())
	{
		WARNING_GUI("Unable to parse tokens from decompilation output: "
				<< out << std::endl
		);
		return nullptr;
	}

	std::vector<Token> ts;
	ea_t ea = fnc->start_ea;

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
			ea = a.isDefined() ? a.getValue() : fnc->start_ea;
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
			else if (k == "i_var") kk = Token::Kind::ID_VAR;
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

			ts.emplace_back(Token(kk, ea, val->value.GetString()));
		}
	}

	qstring qFncName;
	get_func_name(&qFncName, fnc->start_ea);

	auto p = _fnc2fnc.emplace(
			fnc,
			Function(
					qFncName.c_str(),
					fnc->start_ea,
					fnc->end_ea,
					ts
			)
	);

	return &p.first->second;
}

void Decompiler::decompile(const std::string& out)
{
	retdec::config::Config config;
	if (fillConfig(config, out))
	{
		return;
	}
	config.parameters.setOutputFormat("c");
	runDecompilation(config);
}

Function* Decompiler::decompile(ea_t ea, bool redecompile)
{
	if (isRelocatable() && inf_get_min_ea() != 0)
	{
		WARNING_GUI("RetDec plugin can selectively decompile only "
				"relocatable objects loaded at 0x0.\n"
				"Rebase the program to 0x0 or use full decompilation."
		);
		return nullptr;
	}

	func_t* fnc = get_func(ea);
	if (fnc == nullptr)
	{
		WARNING_GUI("Function must be selected by the cursor.\n");
		return nullptr;
	}

	if (!redecompile)
	{
		auto it = _fnc2fnc.find(fnc);
		if (it != _fnc2fnc.end())
		{
			return &it->second;
		}
	}

	retdec::config::Config config;
	if (fillConfig(config))
	{
		return nullptr;
	}

	config.parameters.setOutputFormat("json");
	retdec::common::AddressRange r(fnc->start_ea, fnc->end_ea);
	config.parameters.selectedRanges.insert(r);
	config.parameters.setIsSelectedDecodeOnly(true);

	if (runDecompilation(config))
	{
		return nullptr;
	}

	return parseOutput(fnc, config.parameters.getOutputFile());
}
