///**
// * @file idaplugin/config_generator.cpp
// * @brief Module contains classes/methods dealing with information export
// *        from IDA Pro to Retargetable Decompiler config database.
// * @copyright (c) 2017 Avast Software, licensed under the MIT license
// */
//
//#include <algorithm>
//#include <iostream>
//#include <sstream>
//
//#include "config_generator.h"
//
//namespace idaplugin {
//
///**
// * Initialize config with empty content.
// */
//ConfigGenerator::ConfigGenerator(RdGlobalInfo &gi) :
//		decompInfo(gi),
//		config(gi.configDB)
//{
//	config = retdec::config::Config();
//}
//
///**
// * Generate decompiler config file.
// * @return Name of generated config file.
// */
//std::string ConfigGenerator::generate()
//{
//	DBG_MSG("Configuration Generator:\n");
//
//	structIdSet.clear();
//
//	generateHeader();
//	generateFunctions();
//	generateSegmentsAndGlobals(); // TODO: causes freeze for MIPS.
//
//	return config.generateJsonFile();
//}
//
///**
// * Generate general information about analysed file.
// */
//void ConfigGenerator::generateHeader()
//{
//	config.setInputFile(decompInfo.workIdb);
//	config.setEntryPoint(inf.beginEA);
//	config.setIsIda(true);
//}
//
///**
// * Convert IDA's object location (address, register, etc.) into retdec-config representation.
// * @param loc     Location.
// * @param locType Location type.
// * @return False if ok, true otherwise.
// */
//retdec::config::Storage ConfigGenerator::generateObjectLocation(const argloc_t &loc, const tinfo_t &locType)
//{
//	if (loc.is_reg()) // is_reg1() || is_reg2()
//	{
//		char buff[MAXSTR];
//		ssize_t nameSz = get_reg_name(loc.reg1(), locType.get_size(), buff, sizeof(buff));
//		if (nameSz <= 0)
//			return retdec::config::Storage::undefined();
//
//		return retdec::config::Storage::inRegister(buff);
//	}
//	else if (loc.is_stkoff())
//	{
//		return retdec::config::Storage::onStack(loc.stkoff());
//	}
//	else if (loc.is_ea())
//	{
//		return retdec::config::Storage::inMemory(loc.get_ea());
//	}
//	else if (loc.is_rrel())
//	{
//		return retdec::config::Storage::undefined();
//	}
//	else if (loc.is_scattered())
//	{
//		return retdec::config::Storage::undefined();
//	}
//	else if (loc.is_fragmented())
//	{
//		return retdec::config::Storage::undefined();
//	}
//	else if (loc.is_custom())
//	{
//		return retdec::config::Storage::undefined();
//	}
//	else if (loc.is_badloc())
//	{
//		return retdec::config::Storage::undefined();
//	}
//	else
//	{
//		return retdec::config::Storage::undefined();
//	}
//}
//
///**
// * Convert IDA's calling convention into retdec-config representation.
// * @param      idaCC    IDA calling convention.
// * @param[out] configCC retdec-config calling convention.
// */
//void ConfigGenerator::generateCallingConvention(const cm_t &idaCC, retdec::config::CallingConvention &configCC)
//{
//	switch (idaCC)
//	{
//		case CM_CC_VOIDARG:  configCC.setIsVoidarg(); break;
//		case CM_CC_CDECL:    configCC.setIsCdecl(); break;
//		case CM_CC_ELLIPSIS: configCC.setIsEllipsis(); break;
//		case CM_CC_STDCALL:  configCC.setIsStdcall(); break;
//		case CM_CC_PASCAL:   configCC.setIsPascal(); break;
//		case CM_CC_FASTCALL: configCC.setIsFastcall(); break;
//		case CM_CC_THISCALL: configCC.setIsThiscall(); break;
//		case CM_CC_MANUAL:   configCC.setIsManual(); break;
//		case CM_CC_SPOILED:  configCC.setIsSpoiled(); break;
//		case CM_CC_SPECIALE: configCC.setIsSpecialE(); break;
//		case CM_CC_SPECIALP: configCC.setIsSpecialP(); break;
//		case CM_CC_SPECIAL:  configCC.setIsSpecial(); break;
//
//		case CM_CC_INVALID:
//		case CM_CC_UNKNOWN:
//		case CM_CC_RESERVE4:
//		case CM_CC_RESERVE3:
//		default:             configCC.setIsUnknown(); break;
//	}
//}
//
///**
// * Convert IDA's function type into retdec-config representation.
// * @param fncType IDA's function type.
// * @param ccFnc   retdec-config function type.
// */
//void ConfigGenerator::generateFunctionType(const tinfo_t &fncType, retdec::config::Function &ccFnc)
//{
//	// Generate arguments and return from function type.
//	//
//	func_type_data_t fncInfo;
//	if (fncType.get_func_details(&fncInfo))
//	{
//		// Return info - TODO: support in retdec-config.
//		//
//		ccFnc.returnType.setLlvmIr( type2string(fncInfo.rettype) );
//		ccFnc.returnStorage = generateObjectLocation(fncInfo.retloc, fncInfo.rettype);
//
//		// Argument info.
//		//
//		unsigned cntr = 1;
//		for (auto const &a : fncInfo)
//		{
//			std::string name = a.name.c_str();
//			if (name.empty())
//				name = "a" + std::to_string(cntr);
//
//			auto s = generateObjectLocation(a.argloc, a.type);
//			retdec::config::Object arg(name, s);
//			arg.type.setLlvmIr( type2string(a.type) );
//
//			ccFnc.parameters.insert(arg);
//
//			++cntr;
//		}
//
//		// Calling convention.
//		//
//		generateCallingConvention(fncType.get_cc(), ccFnc.callingConvention);
//	}
//	else
//	{
//		// ???
//	}
//}
//
///**
// * @return @c True if provided function is linked.
// */
//bool isLinkedFunction(func_t *fnc)
//{
//	// Either there is no code in function = no instructions,
//	// or only instructions have "retn" mnemonics.
//	//
//	for (ea_t addr = fnc->startEA; addr < fnc->endEA; ++addr)
//	{
//		flags_t flags = get_flags_novalue(addr);
//		if (isCode(flags))
//		{
//			char mnem[MAXSTR];
//			ua_mnem(addr, mnem, sizeof(mnem));
//			if (std::string(mnem) != "retn")
//			{
//				return false;
//				break;
//			}
//		}
//	}
//
//	return true;
//}
//
///**
// * Generate function information from the analysed file.
// */
//void ConfigGenerator::generateFunctions()
//{
//	for (unsigned i = 0; i < get_func_qty(); ++i)
//	{
//		func_t *fnc = getn_func(i);
//
//		char cFncName[MAXSTR];
//		get_func_name(fnc->startEA, cFncName, sizeof(cFncName));
//
//		std::string fncName = cFncName;
//		std::replace(fncName.begin(), fncName.end(), '.', '_');
//
//		DBG_MSG("\t%s @ %a, #args = %d\n", fncName.c_str(), fnc->startEA, fnc->regargqty);
//
//		retdec::config::Function ccFnc(fncName);
//		ccFnc.setStart(fnc->startEA);
//		ccFnc.setEnd(fnc->endEA);
//		ccFnc.returnType.setLlvmIr("i32"); // TODO: return type is always set to default: ugly, make it better somehow.
//
//		auto* cmt = get_func_cmt(fnc, false);
//		if (cmt)
//			ccFnc.setComment(cmt);
//		qfree(static_cast<void*>(cmt));
//
//		char demangled[MAXSTR];
//		if ( demangle(demangled, sizeof(demangled), cFncName, MNG_SHORT_FORM) > 0 )
//		{
//			ccFnc.setDemangledName( demangled );
//		}
//
//		if (fnc->flags & FUNC_STATICDEF)
//			ccFnc.setIsStaticallyLinked();
//		else if (fnc->flags & FUNC_LIB)
//			ccFnc.setIsDynamicallyLinked();
//		if (isLinkedFunction(fnc))
//			ccFnc.setIsDynamicallyLinked();
//
//		// Guess function type.
//		// get_tinfo2() is preferred before guess_func_tinfo2()
//		// for unknown reason, guess_func_tinfo2() sometimes mix up the arguments (vawtrak sub_10021A76).
//		//
//		tinfo_t fncType;
//		get_tinfo2(fnc->startEA, &fncType);
//		if (!fncType.is_func())
//		{
//			// Guess type from first instruction address.
//			//
//			if (guess_func_tinfo2(fnc, &fncType) != GUESS_FUNC_OK)
//			{
//				// problem
//			}
//		}
//
//		if (fncType.is_func())
//		{
//			generateFunctionType(fncType, ccFnc);
//		}
//
//		config.functions.insert( ccFnc );
//	}
//}
//
///**
// * Generate segments, and generate all global data from segments.
// */
//void ConfigGenerator::generateSegmentsAndGlobals()
//{
//	char buff[MAXSTR];
//
//	int segNum = get_segm_qty();
//	for (int i=0; i<segNum; ++i)
//	{
//		segment_t *seg = getnseg(i);
//		if (seg == nullptr)
//			continue;
//
//		if ( (get_segm_name(seg, buff, sizeof(buff))) == -1)
//			continue;
//
//		retdec::config::Segment segment( retdec::utils::Address(seg->startEA) );
//		segment.setName(buff);
//		segment.setEnd(seg->endEA);
//		config.segments.insert(segment);
//
//		ea_t head = seg->startEA - 1;
//		while ( (head = next_head(head, seg->endEA)) != BADADDR)
//		{
//			flags_t f = getFlags(head);
//			if (f == 0)
//				continue;
//
//			// Argument 1 should not be present for data.
//			// Some object do have argument 0 (off_X), some dont (strings).
//			//
//			if (!isData(f) || !isHead(f) || /*!isDefArg0(f) ||*/ isDefArg1(f))
//				continue;
//
//			if (!has_any_name(f)) // usually alignment.
//				continue;
//
//			if ( (get_name(head, head, buff, sizeof(buff))) == nullptr)
//				continue;
//
//			if (has_user_name(f))
//			{
//				// TODO: user name, tag it somehow.
//			}
//
//			auto s = retdec::config::Storage::inMemory(retdec::utils::Address(head));
//			retdec::config::Object global(buff, s);
//
//			tinfo_t guessType;
//			tinfo_t getType;
//			tinfo_t fncType;
//
//			// To avoid get_tinfo2() crashes (see below) we introduced this address type check before using it.
//			// However, guess_tinfo2() might freeze -> ida hangs (ack.mips.pspgcc-4.3.5.O0.g.elf).
//			// Therefore, we are a bit screwed.
//			// Right now, we always use get_tinfo2() and hope it wont crash IDA -- it is ok for the currently tested inputs.
//			// I dont known on which input it crashed, so maybe it will be ok now.
//			//
//			int guessRet = GUESS_FUNC_OK;
//			//int guessRet = guess_tinfo2(head, &guessType);
//			int getRet = 0;
//
//			// get_tinfo2() sometimes crashes IDA, call only if guess_tinfo2() OK.
//			// hope it will solve the problem, if not, then we have got serious problem.
//			//
//			if (guessRet == GUESS_FUNC_OK)
//			{
//				getRet = get_tinfo2(head, &guessType);
//			}
//
//			// Create function if function type for this address.
//			//
//			if (guessRet == GUESS_FUNC_OK && guessType.is_func())
//			{
//				fncType = guessType;
//			}
//			else if (getRet && getType.is_func())
//			{
//				fncType = getType;
//			}
//
//			if (!fncType.empty() && fncType.present() && fncType.is_func())
//			{
//				std::string fncName = buff;
//				std::replace(fncName.begin(), fncName.end(), '.', '_');
//
//				retdec::config::Function ccFnc(fncName);
//				ccFnc.setStart(head);
//				ccFnc.setEnd(head);
//				ccFnc.setIsDynamicallyLinked();
//				generateFunctionType(fncType, ccFnc);
//
//				char demangled[MAXSTR];
//				if ( demangle(demangled, sizeof(demangled), buff, MNG_SHORT_FORM) > 0 )
//				{
//					ccFnc.setDemangledName( demangled );
//				}
//
//				config.functions.insert( ccFnc );
//				continue;
//			}
//
//			// Continue creating global variable.
//			//
//			if (guessRet == GUESS_FUNC_OK &&
//				!guessType.empty() && guessType.present())
//			{
//				global.type.setLlvmIr( type2string(guessType) );
//			}
//			else
//			{
//				global.type.setLlvmIr( addrType2string(head) );
//			}
//
//			config.globals.insert( global );
//		}
//	}
//}
//
///**
// * @brief Get LLVM IR representation of item type on provided address.
// * @return LLVM IR type string.
// */
//std::string ConfigGenerator::addrType2string(ea_t addr)
//{
//	flags_t f = getFlags(addr);
//	if (f == 0)
//		return defaultTypeString();
//
//	asize_t itemSize = get_item_size(addr);
//	asize_t elemSize = get_data_elsize(addr, f);
//	asize_t arraySize = 0;
//	if (itemSize > elemSize)
//	{
//		arraySize = itemSize / elemSize;
//	}
//
//	std::string item = defaultTypeString();
//	if (isByte(f))
//	{
//		item = "i8";
//	}
//	else if (isWord(f))
//	{
//		item = "i16";
//	}
//	else if (isDwrd(f))
//	{
//		item = "i32";
//	}
//	else if (isQwrd(f))
//	{
//		item = "i64";
//	}
//	else if (isOwrd(f))
//	{
//		item = "i128";
//	}
//	else if (isYwrd(f))
//	{
//		item = "i256";
//	}
//	else if (isTbyt(f))
//	{
//		item = "i80";
//	}
//	else if (isFloat(f))
//	{
//		item = "float";
//	}
//	else if (isDouble(f))
//	{
//		item = "double";
//	}
//	else if (isPackReal(f))
//	{
//		item = "x86_fp80"; // TODO: ??? maybe 12B = 96b.
//	}
//	else if (isASCII(f))
//	{
//		item = "i8";
//	}
//	else if (isStruct(f))
//	{
//		item = defaultTypeString(); // TODO: not supported right now.
//	}
//	else if (isAlign(f))
//	{
//		item = "i" + std::to_string(elemSize);
//	}
//	else if (is3byte(f))
//	{
//		item = "i24";
//	}
//	else if (isCustom(f))
//	{
//		item = defaultTypeString(); // TODO: not supported right now.
//	}
//	else
//	{
//		item = defaultTypeString();
//	}
//
//	std::string ret = defaultTypeString();
//	if (arraySize)
//	{
//		ret = "[" + std::to_string(arraySize) + " x " + item + "]";
//	}
//	else
//	{
//		ret = item;
//	}
//	return ret;
//}
//
///**
// * Get LLVM IR representation of the provided IDA Pro data type.
// * @param type IDA Pro type.
// * @return LLVM IR data type.
// *
// * TODO - recursive structure types?
// */
//std::string ConfigGenerator::type2string(const tinfo_t &type)
//{
//	std::string ret = defaultTypeString();
//
//	if (type.empty())
//		return ret;
//
//	if (type.is_char() || type.is_uchar()) ret = "i8";
//	else if (type.is_int16() || type.is_uint16()) ret = "i16";
//	else if (type.is_int32() || type.is_uint() || type.is_uint32()) ret = "i32";
//	else if (type.is_int64() || type.is_uint64()) ret = "i64";
//	else if (type.is_int128()) ret = "i128";
//	else if (type.is_ldouble()) ret = "f80";
//	else if (type.is_double()) ret = "double";
//	else if (type.is_float()) ret = "float";
//	else if (type.is_bool()) ret = "i1";
//	else if (type.is_void()) ret = "void";
//	else if (type.is_unknown()) ret = "i32";
//
//	else if (type.is_ptr())
//	{
//		tinfo_t base = type.get_pointed_object();
//		ret = type2string(base) + "*";
//	}
//	else if (type.is_func())
//	{
//		func_type_data_t fncType;
//		if (type.get_func_details(&fncType))
//		{
//			ret = type2string( fncType.rettype );
//			ret += "(";
//
//			bool first = true;
//			for (auto const &a : fncType)
//			{
//				if (first)
//				{
//					first = false;
//				}
//				else
//				{
//					ret += ", ";
//				}
//
//				ret += type2string(a.type);
//			}
//
//			ret += ")";
//		}
//		else
//		{
//			ERROR_MSG("ConfigGenerator::type2string() -- function type failed\n");
//			ret = "i32*";
//		}
//	}
//	else if (type.is_array())
//	{
//		tinfo_t base = type.get_array_element();
//		std::string baseType = type2string(base);
//		int arraySize = type.get_array_nelems();
//
//		if (arraySize > 0)
//		{
//			ret = "[" + std::to_string(arraySize) + " x " + baseType + "]";
//		}
//		else
//		{
//			ret = baseType + "*";
//		}
//	}
//	else if (type.is_struct())
//	{
//		auto it = structIdSet.find(type);
//		std::string strName = "%";
//
//		// This structure have already been generated.
//		//
//		if (it != structIdSet.end())
//		{
//			return it->second;
//		}
//		else
//		{
//			qstring idaStrName = ""; // make sure it is empty.
//
//			if (type.get_final_type_name(&idaStrName) && !idaStrName.empty())
//			{
//				strName += idaStrName.c_str();
//			}
//			else
//			{
//				strName += "struct_" + std::to_string(config.structures.size());
//			}
//
//			structIdSet[type] = strName;
//		}
//
//		std::string body;
//
//		int elemCnt = type.get_udt_nmembers();
//		if (elemCnt > 0)
//		{
//			body = "{ ";
//
//			bool first = true;
//			for (int i=0; i<elemCnt; ++i)
//			{
//				udt_member_t mem;
//				mem.offset = i;
//				std::string memType = defaultTypeString();
//
//				if (type.find_udt_member(STRMEM_INDEX, &mem) >= 0)
//				{
//					memType = type2string( mem.type );
//				}
//
//				if (first)
//				{
//					first = false;
//				}
//				else
//				{
//					body += ", ";
//				}
//
//				body += memType;
//			}
//
//			body += " }";
//		}
//		else
//		{
//			body = "{ " + defaultTypeString() + " }";
//		}
//
//		ret = strName;  // only structure name is returned.
//
//		retdec::config::Type ccType( strName + " = type " + body );
//		config.structures.insert( ccType );
//	}
//	else if (type.is_union())
//	{
//		ERROR_MSG("ConfigGenerator::type2string() -- union type not supported\n");
//		ret = defaultTypeString();
//	}
//	else if (type.is_enum())
//	{
//		ERROR_MSG("ConfigGenerator::type2string() -- enum type not supported\n");
//		ret = defaultTypeString();
//	}
//	else if (type.is_sue())
//	{
//		ERROR_MSG("ConfigGenerator::type2string() -- SUE type not supported\n");
//		ret = defaultTypeString();
//	}
//	else if (type.is_bitfield()) // http://en.cppreference.com/w/cpp/language/bit_field
//	{
//		ERROR_MSG("ConfigGenerator::type2string() -- bitfield type not supported\n");
//		ret = defaultTypeString();
//	}
//	else
//	{
//		ERROR_MSG("ConfigGenerator::type2string() -- some unknown type\n");
//		ret = defaultTypeString();
//	}
//
//	return ret;
//}
//
///**
// * Get LLVM IR representation of the default data type.
// * @return LLVM IR data type.
// */
//std::string ConfigGenerator::defaultTypeString()
//{
//	return "i32";
//}
//
//} // namespace idaplugin
