/**
 * @file idaplugin/config_generator.cpp
 * @brief Module contains classes/methods dealing with information export
 *        from IDA Pro to Retargetable Decompiler config database.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <iostream>
#include <sstream>

#include "config_generator.h"

namespace idaplugin {

/**
 * Initialize config with empty content.
 */
ConfigGenerator::ConfigGenerator(RdGlobalInfo& gi) :
		decompInfo(gi),
		config(gi.configDB)
{
	config = retdec::config::Config();
}

/**
 * Generate decompiler config file.
 * @return Name of generated config file.
 */
std::string ConfigGenerator::generate()
{
	DBG_MSG("Configuration Generator:\n");

	structIdSet.clear();

	generateHeader();
	generateFunctions();
	generateSegmentsAndGlobals();

	return config.generateJsonFile();
}

/**
 * Generate general information about analysed file.
 */
void ConfigGenerator::generateHeader()
{
	config.setInputFile(decompInfo.workIdb);
	config.setEntryPoint(inf.start_ea);
	config.setIsIda(true);
}

/**
 * Convert IDA's object location (address, register, etc.) into
 * retdec-config representation.
 *
 * @param loc     Location.
 * @param locType Location type.
 * @return False if ok, true otherwise.
 */
retdec::config::Storage ConfigGenerator::generateObjectLocation(
		const argloc_t &loc,
		const tinfo_t &locType)
{
	if (loc.is_reg()) // is_reg1() || is_reg2()
	{
		qstring buff;
		if (get_reg_name(&buff, loc.reg1(), locType.get_size()) <= 0)
		{
			return retdec::config::Storage::undefined();
		}

		return retdec::config::Storage::inRegister(buff.c_str());
	}
	else if (loc.is_stkoff())
	{
		return retdec::config::Storage::onStack(loc.stkoff());
	}
	else if (loc.is_ea())
	{
		return retdec::config::Storage::inMemory(loc.get_ea());
	}
	else if (loc.is_rrel())
	{
		return retdec::config::Storage::undefined();
	}
	else if (loc.is_scattered())
	{
		return retdec::config::Storage::undefined();
	}
	else if (loc.is_fragmented())
	{
		return retdec::config::Storage::undefined();
	}
	else if (loc.is_custom())
	{
		return retdec::config::Storage::undefined();
	}
	else if (loc.is_badloc())
	{
		return retdec::config::Storage::undefined();
	}
	else
	{
		return retdec::config::Storage::undefined();
	}
}

/**
 * Convert IDA's calling convention into retdec-config representation.
 * @param      idaCC    IDA calling convention.
 * @param[out] configCC retdec-config calling convention.
 */
void ConfigGenerator::generateCallingConvention(
		const cm_t &idaCC,
		retdec::config::CallingConvention &configCC)
{
	switch (idaCC)
	{
		case CM_CC_VOIDARG:  configCC.setIsVoidarg(); break;
		case CM_CC_CDECL:    configCC.setIsCdecl(); break;
		case CM_CC_ELLIPSIS: configCC.setIsEllipsis(); break;
		case CM_CC_STDCALL:  configCC.setIsStdcall(); break;
		case CM_CC_PASCAL:   configCC.setIsPascal(); break;
		case CM_CC_FASTCALL: configCC.setIsFastcall(); break;
		case CM_CC_THISCALL: configCC.setIsThiscall(); break;
		case CM_CC_MANUAL:   configCC.setIsManual(); break;
		case CM_CC_SPOILED:  configCC.setIsSpoiled(); break;
		case CM_CC_SPECIALE: configCC.setIsSpecialE(); break;
		case CM_CC_SPECIALP: configCC.setIsSpecialP(); break;
		case CM_CC_SPECIAL:  configCC.setIsSpecial(); break;

		case CM_CC_INVALID:
		case CM_CC_UNKNOWN:
		case CM_CC_RESERVE4:
		case CM_CC_RESERVE3:
		default:             configCC.setIsUnknown(); break;
	}
}

/**
 * Convert IDA's function type into retdec-config representation.
 * @param fncType IDA's function type.
 * @param ccFnc   retdec-config function type.
 */
void ConfigGenerator::generateFunctionType(
		const tinfo_t &fncType,
		retdec::config::Function &ccFnc)
{
	// Generate arguments and return from function type.
	//
	func_type_data_t fncInfo;
	if (fncType.get_func_details(&fncInfo))
	{
		// Return info.
		//
		ccFnc.returnType.setLlvmIr(type2string(fncInfo.rettype));
		ccFnc.returnStorage = generateObjectLocation(
				fncInfo.retloc,
				fncInfo.rettype);

		// Argument info.
		//
		unsigned cntr = 1;
		for (auto const& a : fncInfo)
		{
			std::string name = a.name.c_str();
			if (name.empty())
			{
				name = "a" + std::to_string(cntr);
			}

			auto s = generateObjectLocation(a.argloc, a.type);
			retdec::config::Object arg(name, s);
			arg.type.setLlvmIr( type2string(a.type) );

			ccFnc.parameters.insert(arg);

			++cntr;
		}

		// Calling convention.
		//
		generateCallingConvention(fncType.get_cc(), ccFnc.callingConvention);
	}
	else
	{
		// TODO: ???
	}
}

/**
 * @return @c True if provided function is linked.
 * TODO: Do we really want to do this? What is the point?
 */
bool isLinkedFunction(func_t *fnc)
{
	// Either there is no code in function = no instructions,
	// or only instructions have "retn" mnemonics.
	//
	for (ea_t addr = fnc->start_ea; addr < fnc->end_ea; ++addr)
	{
		flags_t flags = get_flags(addr);
		if (is_code(flags))
		{
			qstring mnem;
			print_insn_mnem(&mnem, addr);
			if (mnem != "retn")
			{
				return false;
			}
		}
	}

	return true;
}

/**
 * Generate function information from the analysed file.
 */
void ConfigGenerator::generateFunctions()
{
	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t *fnc = getn_func(i);

		while((fnc->start_ea < fnc->end_ea) && (fnc->start_ea != BADADDR))
		{
			qstring qFncName;
			get_func_name(&qFncName, fnc->start_ea);

			std::string fncName = qFncName.c_str();
			std::replace(fncName.begin(), fncName.end(), '.', '_');

			INFO_MSG("\t%s @ [start:%" RetDecUInt ", end:%" RetDecUInt "], #args = %d\n",
					fncName.c_str(),
					fnc->start_ea,
					fnc->end_ea,
					fnc->regargqty);

			retdec::config::Function ccFnc(fncName);
			ccFnc.setStart(fnc->start_ea);
			ccFnc.setEnd(fnc->end_ea);
			// TODO: return type is always set to default: ugly, make it better.
			ccFnc.returnType.setLlvmIr("i32");

			qstring qCmt;
			if (get_func_cmt(&qCmt, fnc, false) > 0)
			{
				ccFnc.setComment(qCmt.c_str());
			}

			qstring qDemangled;
			if (demangle_name(&qDemangled, fncName.c_str(), MNG_SHORT_FORM) > 0)
			{
				ccFnc.setDemangledName(qDemangled.c_str());
			}

			if (fnc->flags & FUNC_STATICDEF)
			{
				ccFnc.setIsStaticallyLinked();
			}
			else if (fnc->flags & FUNC_LIB)
			{
				ccFnc.setIsDynamicallyLinked();
			}

			if (isLinkedFunction(fnc))
			{
				ccFnc.setIsDynamicallyLinked();
			}

			// Because Support has been upgraded to IDA 7 get_tinfo2 no longer exist
			//
			tinfo_t fncType;
			get_tinfo(&fncType, fnc->start_ea);
			if (!fncType.is_func())
			{
				// Guess type from first instruction address.
				//
				const auto guess = guess_tinfo(&fncType, fnc->start_ea);
				if(guess != GUESS_FUNC_OK)
				{
					// TODO: problem
					fncType.clear();
				}
			}
			else
			{
				generateFunctionType(fncType, ccFnc);
			}

			config.functions.insert( ccFnc );
		}
	}
}

/**
 * Generate segments, and generate all global data from segments.
 */
void ConfigGenerator::generateSegmentsAndGlobals()
{
	qstring buff;

	int segNum = get_segm_qty();
	for (int i = 0; i < segNum; ++i)
	{
		segment_t* seg = getnseg(i);
		if (seg == nullptr)
		{
			continue;
		}

		if (get_visible_segm_name(&buff, seg) <= 0)
		{
			continue;
		}

		retdec::config::Segment segment(retdec::utils::Address(seg->start_ea));
		segment.setName(buff.c_str());
		segment.setEnd(seg->end_ea);
		config.segments.insert(segment);

		ea_t head = seg->start_ea - 1;
		while ( (head = next_head(head, seg->end_ea)) != BADADDR)
		{
			flags_t f = get_full_flags(head);
			if (f == 0)
			{
				continue;
			}

			// Argument 1 should not be present for data.
			// Some object do have argument 0 (off_X), some dont (strings).
			//
			if (!is_data(f) || !is_head(f) || /*!is_defarg0(f) ||*/ is_defarg1(f))
			{
				continue;
			}

			if (!has_any_name(f)) // usually alignment.
			{
				continue;
			}

			if (get_name(&buff, head) <= 0)
			{
				continue;
			}

			auto s = retdec::config::Storage::inMemory(
					retdec::utils::Address(head));
			retdec::config::Object global(buff.c_str(), s);

			// Get type.
			//
			tinfo_t getType;
			get_tinfo(&getType, head);
			if (getType.empty() || !getType.present())
			{
				// Guess type from first instruction address.
				//
				const auto guess = guess_tinfo(&getType, head);
				if(guess != GUESS_FUNC_OK)
				{
					// TODO: problem
					getType.clear();
				}
			}

			if (!getType.empty() && getType.present() && getType.is_func())
			{
				std::string fncName = buff.c_str();
				std::replace(fncName.begin(), fncName.end(), '.', '_');

				retdec::config::Function ccFnc(fncName);
				ccFnc.setStart(head);
				ccFnc.setEnd(head);
				ccFnc.setIsDynamicallyLinked();
				generateFunctionType(getType, ccFnc);

				qstring qDemangled;
				if (demangle_name(&qDemangled, fncName.c_str(), MNG_SHORT_FORM) > 0)
				{
					ccFnc.setDemangledName(qDemangled.c_str());
				}

				config.functions.insert(ccFnc);
				continue;
			}

			// Continue creating global variable.
			//
			if (!getType.empty() && getType.present())
			{
				global.type.setLlvmIr(type2string(getType));
			}
			else
			{
				global.type.setLlvmIr(addrType2string(head));
			}

			config.globals.insert( global );
		}
	}
}

/**
 * @brief Get LLVM IR representation of item type on provided address.
 * @return LLVM IR type string.
 */
std::string ConfigGenerator::addrType2string(ea_t addr)
{
	flags_t f = get_full_flags(addr);
	if (f == 0)
	{
		return defaultTypeString();
	}

	asize_t itemSize = get_item_size(addr);
	asize_t elemSize = get_data_elsize(addr, f);
	asize_t arraySize = 0;
	if (itemSize > elemSize)
	{
		arraySize = itemSize / elemSize;
	}

	std::string item = defaultTypeString();
	if (is_byte(f))
	{
		item = "i8";
	}
	else if (is_word(f))
	{
		item = "i16";
	}
	else if (is_dword(f))
	{
		item = "i32";
	}
	else if (is_qword(f))
	{
		item = "i64";
	}
	else if (is_oword(f))
	{
		item = "i128";
	}
	else if (is_yword(f))
	{
		item = "i256";
	}
	else if (is_tbyte(f))
	{
		item = "i80";
	}
	else if (is_float(f))
	{
		item = "float";
	}
	else if (is_double(f))
	{
		item = "double";
	}
	else if (is_pack_real(f))
	{
		item = "x86_fp80"; // TODO: ??? maybe 12B = 96b.
	}
	else if (is_strlit(f))
	{
		item = "i8";
	}
	else if (is_struct(f))
	{
		item = defaultTypeString(); // TODO: not supported right now.
	}
	else if (is_align(f))
	{
		item = "i" + std::to_string(elemSize);
	}
	else if (is_custom(f))
	{
		item = defaultTypeString(); // TODO: not supported right now.
	}
	else
	{
		item = defaultTypeString();
	}

	std::string ret = defaultTypeString();
	if (arraySize)
	{
		ret = "[" + std::to_string(arraySize) + " x " + item + "]";
	}
	else
	{
		ret = item;
	}
	return ret;
}

/**
 * Get LLVM IR representation of the provided IDA Pro data type.
 * @param type IDA Pro type.
 * @return LLVM IR data type.
 *
 * TODO - recursive structure types?
 */
std::string ConfigGenerator::type2string(const tinfo_t &type)
{
	std::string ret = defaultTypeString();

	if (type.empty())
		return ret;

	if (type.is_char() || type.is_uchar()) ret = "i8";
	else if (type.is_int16() || type.is_uint16()) ret = "i16";
	else if (type.is_int32() || type.is_uint() || type.is_uint32()) ret = "i32";
	else if (type.is_int64() || type.is_uint64()) ret = "i64";
	else if (type.is_int128()) ret = "i128";
	else if (type.is_ldouble()) ret = "f80";
	else if (type.is_double()) ret = "double";
	else if (type.is_float()) ret = "float";
	else if (type.is_bool()) ret = "i1";
	else if (type.is_void()) ret = "void";
	else if (type.is_unknown()) ret = "i32";

	else if (type.is_ptr())
	{
		tinfo_t base = type.get_pointed_object();
		ret = type2string(base) + "*";
	}
	else if (type.is_func())
	{
		func_type_data_t fncType;
		if (type.get_func_details(&fncType))
		{
			ret = type2string( fncType.rettype );
			ret += "(";

			bool first = true;
			for (auto const &a : fncType)
			{
				if (first)
				{
					first = false;
				}
				else
				{
					ret += ", ";
				}

				ret += type2string(a.type);
			}

			ret += ")";
		}
		else
		{
			ERROR_MSG("ConfigGenerator::type2string() -- function type failed\n");
			ret = "i32*";
		}
	}
	else if (type.is_array())
	{
		tinfo_t base = type.get_array_element();
		std::string baseType = type2string(base);
		int arraySize = type.get_array_nelems();

		if (arraySize > 0)
		{
			ret = "[" + std::to_string(arraySize) + " x " + baseType + "]";
		}
		else
		{
			ret = baseType + "*";
		}
	}
	else if (type.is_struct())
	{
		auto it = structIdSet.find(type);
		std::string strName = "%";

		// This structure have already been generated.
		//
		if (it != structIdSet.end())
		{
			return it->second;
		}
		else
		{
			qstring idaStrName = ""; // make sure it is empty.

			if (type.get_final_type_name(&idaStrName) && !idaStrName.empty())
			{
				strName += idaStrName.c_str();
			}
			else
			{
				strName += "struct_" + std::to_string(config.structures.size());
			}

			structIdSet[type] = strName;
		}

		std::string body;

		int elemCnt = type.get_udt_nmembers();
		if (elemCnt > 0)
		{
			body = "{ ";

			bool first = true;
			for (int i=0; i<elemCnt; ++i)
			{
				udt_member_t mem;
				mem.offset = i;
				std::string memType = defaultTypeString();

				if (type.find_udt_member(&mem, STRMEM_INDEX) >= 0)
				{
					memType = type2string( mem.type );
				}

				if (first)
				{
					first = false;
				}
				else
				{
					body += ", ";
				}

				body += memType;
			}

			body += " }";
		}
		else
		{
			body = "{ " + defaultTypeString() + " }";
		}

		ret = strName;  // only structure name is returned.

		retdec::config::Type ccType( strName + " = type " + body );
		config.structures.insert( ccType );
	}
	else if (type.is_union())
	{
		ERROR_MSG("ConfigGenerator::type2string() -- union type not supported\n");
		ret = defaultTypeString();
	}
	else if (type.is_enum())
	{
		ERROR_MSG("ConfigGenerator::type2string() -- enum type not supported\n");
		ret = defaultTypeString();
	}
	else if (type.is_sue())
	{
		ERROR_MSG("ConfigGenerator::type2string() -- SUE type not supported\n");
		ret = defaultTypeString();
	}
	else if (type.is_bitfield()) // http://en.cppreference.com/w/cpp/language/bit_field
	{
		ERROR_MSG("ConfigGenerator::type2string() -- bitfield type not supported\n");
		ret = defaultTypeString();
	}
	else
	{
		ERROR_MSG("ConfigGenerator::type2string() -- some unknown type\n");
		ret = defaultTypeString();
	}

	return ret;
}

/**
 * Get LLVM IR representation of the default data type.
 * @return LLVM IR data type.
 */
std::string ConfigGenerator::defaultTypeString()
{
	return "i32";
}

} // namespace idaplugin
