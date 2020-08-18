
#include <retdec/utils/binary_path.h>

#include "config.h"
#include "retdec.h"
#include "utils.h"

/**
 * Perform startup check that determines, if plugin can decompile IDA's input file.
 * @return True if plugin can decompile IDA's input, false otherwise.
 */
bool canDecompileInput(
		std::string& arch,
		std::string& endian,
		unsigned& bitSize,
		retdec::common::Address& rawSectionVma,
		retdec::common::Address& rawEntryPoint,
		bool& isRaw
)
{
	std::string procName = inf_get_procname().c_str();
	auto fileType = inf_get_filetype();

	// 32-bit binary -> is_32bit() == 1 && is_64bit() == 0.
	// 64-bit binary -> is_32bit() == 1 && is_64bit() == 1.
	// Allow 64-bit x86 and arm.
	if (inf_is_64bit())
	{
		if (!isX86() && procName != "ARM")
		{
			WARNING_GUI(RetDec::pluginName << " version " << RetDec::pluginVersion
					<< " cannot decompile 64-bit for PROCNAME = " << procName
			);
			return false;
		}
	}
	else if (!inf_is_32bit())
	{
		WARNING_GUI(RetDec::pluginName << " version " << RetDec::pluginVersion
				<< " cannot decompile PROCNAME = " << procName
		);
		return false;
	}

	if (!(fileType == f_BIN
			|| fileType == f_PE
			|| fileType == f_ELF
			|| fileType == f_COFF
			|| fileType == f_MACHO
			|| fileType == f_HEX))
	{
		if (fileType == f_LOADER)
		{
			WARNING_GUI("Custom IDA loader plugin was used.\n"
					"Decompilation will be attempted, but:\n"
					"1. RetDec idaplugin can not check if the input can be "
					"decompiled. Decompilation may fail.\n"
					"2. If the custom loader behaves differently than the RetDec "
					"loader, decompilation may fail or produce nonsensical result."
			);
		}
		else
		{
			WARNING_GUI(RetDec::pluginName
					<< " version " << RetDec::pluginVersion
					<< " cannot decompile this input file (file type = "
					<< fileType << ").\n"
			);
			return false;
		}
	}

	// Check Intel HEX.
	//
	if (fileType == f_HEX)
	{
		if (procName == "mipsr" || procName == "mipsb")
		{
			arch = "mips";
			endian = "big";
		}
		else if (procName == "mipsrl"
				|| procName == "mipsl"
				|| procName == "psp")
		{
			arch = "mips";
			endian = "little";
		}
		else
		{
			WARNING_GUI("Intel HEX input file can be decompiled only for one of "
					"these {mipsr, mipsb, mipsrl, mipsl, psp} processors, "
					"not \"" << procName << "\".\n");
			return false;
		}
	}

	// Check BIN (RAW).
	//
	if (fileType == f_BIN)
	{
		if (inf_is_64bit) bitSize = 64;
		else if (inf_is_32bit) bitSize = 32;
		else
		{
			WARNING_GUI("Can decompile only 32/64 bit f_BIN.\n");
			return false;
		}
		isRaw = true;

		// Section VMA.
		//
		rawSectionVma = inf_get_min_ea();

		// Entry point.
		//
		if (inf_get_start_ea() != BADADDR)
		{
			rawEntryPoint = inf_get_start_ea();
		}
		else
		{
			rawEntryPoint = rawSectionVma;
		}

		// Architecture + endian.
		//
		if (procName == "mipsr" || procName == "mipsb")
		{
			arch = "mips";
			endian = "big";
		}
		else if (procName == "mipsrl" || procName == "mipsl" || procName == "psp")
		{
			arch = "mips";
			endian = "little";
		}
		else if (procName == "ARM")
		{
			arch = "arm";
			endian = "little";
		}
		else if (procName == "ARMB")
		{
			arch = "arm";
			endian = "big";
		}
		else if (procName == "PPCL")
		{
			arch = "powerpc";
			endian = "little";
		}
		else if (procName == "PPC")
		{
			arch = "powerpc";
			endian = "big";
		}
		else if (isX86())
		{
			arch = inf_is_64bit() ? "x86-64" : "x86";
			endian = "little";
		}
		else
		{
			WARNING_GUI("Binary input file can be decompiled only for one of these "
					"{mipsr, mipsb, mipsrl, mipsl, psp, ARM, ARMB, PPCL, PPC, 80386p, "
					"80386r, 80486p, 80486r, 80586p, 80586r, 80686p, p2, p3, p4} "
					"processors, not \"" << procName << "\".\n");
			return false;
		}
	}

	return true;
}

bool generateHeader(retdec::config::Config& config, std::string out)
{
	auto inFile = getInputPath();
	if (inFile.empty())
	{
		WARNING_GUI("Cannot decompile - there is no input file.");
		return true;
	}

	std::string arch;
	std::string endian;
	unsigned bitSize = 0;
	retdec::common::Address rawSectionVma;
	retdec::common::Address rawEntryPoint;
	bool isRaw = false;
	if (!canDecompileInput(
			arch,
			endian,
			bitSize,
			rawSectionVma,
			rawEntryPoint,
			isRaw))
	{
		return true;
	}

	auto idaPath = retdec::utils::getThisBinaryDirectoryPath();
	auto configPath = idaPath;
	configPath.append("plugins");
	configPath.append("retdec");
	configPath.append("decompiler-config.json");
	if (fs::exists(configPath))
	{
		config = retdec::config::Config::fromFile(configPath.string());
		config.parameters.fixRelativePaths(idaPath.string());
	}

	if (!arch.empty())
	{
		config.architecture.setName(arch);
	}
	if (endian == "little")
	{
		config.architecture.setIsEndianLittle();
	}
	else if (endian == "big")
	{
		config.architecture.setIsEndianBig();
	}
	if (rawSectionVma.isDefined())
	{
		config.parameters.setSectionVMA(rawSectionVma);
	}
	if (rawEntryPoint.isDefined())
	{
		config.parameters.setEntryPoint(rawEntryPoint);
	}

	if (isRaw && bitSize)
	{
		config.fileFormat.setIsRaw();
		config.fileFormat.setFileClassBits(bitSize);
		config.architecture.setBitSize(bitSize);
	}

	config.parameters.setInputFile(inFile);
	config.parameters.setOutputFile(out);

	return false;
}

std::string defaultTypeString()
{
	return "i32";
}

/**
 * TODO - recursive structure types?
 */
std::string type2string(
		retdec::config::Config& config,
		std::map<tinfo_t, std::string>& structIdSet,
		const tinfo_t &type)
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
		ret = type2string(config, structIdSet, base) + "*";
	}
	else if (type.is_func())
	{
		func_type_data_t fncType;
		if (type.get_func_details(&fncType))
		{
			ret = type2string(config, structIdSet, fncType.rettype);
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

				ret += type2string(config, structIdSet, a.type);
			}

			ret += ")";
		}
		else
		{
			ret = "i32*";
		}
	}
	else if (type.is_array())
	{
		tinfo_t base = type.get_array_element();
		std::string baseType = type2string(config, structIdSet, base);
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
					memType = type2string(config, structIdSet, mem.type);
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

		retdec::common::Type ccType(strName + " = type " + body);
		config.structures.insert(ccType);
	}
	else if (type.is_union())
	{
		ret = defaultTypeString();
	}
	else if (type.is_enum())
	{
		ret = defaultTypeString();
	}
	else if (type.is_sue())
	{
		ret = defaultTypeString();
	}
	// http://en.cppreference.com/w/cpp/language/bit_field
	else if (type.is_bitfield())
	{
		ret = defaultTypeString();
	}
	else
	{
		ret = defaultTypeString();
	}

	return ret;
}

std::string addrType2string(ea_t addr)
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

bool isLinkedFunction(func_t* fnc)
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

void generateCallingConvention(
		const cm_t &idaCC,
		retdec::common::CallingConvention &configCC)
{
	switch (idaCC)
	{
		case CM_CC_VOIDARG:  configCC.setIsVoidarg(); break;
		case CM_CC_CDECL:    configCC.setIsCdecl(); break;
		case CM_CC_ELLIPSIS: configCC.setIsCdecl(); break;
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

retdec::common::Storage generateObjectLocation(
		const argloc_t &loc,
		const tinfo_t &locType)
{
	if (loc.is_reg()) // is_reg1() || is_reg2()
	{
		qstring buff;
		if (get_reg_name(&buff, loc.reg1(), locType.get_size()) <= 0)
		{
			return retdec::common::Storage::undefined();
		}

		return retdec::common::Storage::inRegister(buff.c_str());
	}
	else if (loc.is_stkoff())
	{
		return retdec::common::Storage::onStack(loc.stkoff());
	}
	else if (loc.is_ea())
	{
		return retdec::common::Storage::inMemory(loc.get_ea());
	}
	else if (loc.is_rrel())
	{
		return retdec::common::Storage::undefined();
	}
	else if (loc.is_scattered())
	{
		return retdec::common::Storage::undefined();
	}
	else if (loc.is_fragmented())
	{
		return retdec::common::Storage::undefined();
	}
	else if (loc.is_custom())
	{
		return retdec::common::Storage::undefined();
	}
	else if (loc.is_badloc())
	{
		return retdec::common::Storage::undefined();
	}
	else
	{
		return retdec::common::Storage::undefined();
	}
}

void generateFunctionType(
		retdec::config::Config& config,
		std::map<tinfo_t, std::string>& structIdSet,
		const tinfo_t &fncType,
		retdec::common::Function &ccFnc)
{
	// Generate arguments and return from function type.
	//
	func_type_data_t fncInfo;
	if (fncType.get_func_details(&fncInfo))
	{
		// Return info.
		//
		ccFnc.returnType.setLlvmIr(type2string(
				config,
				structIdSet,
				fncInfo.rettype)
		);
		ccFnc.returnStorage = generateObjectLocation(
				fncInfo.retloc,
				fncInfo.rettype
		);

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
			retdec::common::Object arg(name, s);
			arg.type.setLlvmIr(type2string(config, structIdSet, a.type));

			ccFnc.parameters.push_back(arg);

			++cntr;
		}

		// Calling convention.
		//
		generateCallingConvention(fncType.get_cc(), ccFnc.callingConvention);
		if (fncType.get_cc() == CM_CC_ELLIPSIS)
		{
			ccFnc.setIsVariadic(true);
		}
	}
	else
	{
		// TODO: ???
	}
}

void generateFunction(
		retdec::config::Config& config,
		std::map<tinfo_t, std::string>& structIdSet,
		func_t* fnc)
{
	qstring qFncName;
	get_func_name(&qFncName, fnc->start_ea);

	std::string fncName = qFncName.c_str();
	std::replace(fncName.begin(), fncName.end(), '.', '_');

	retdec::common::Function ccFnc(fncName);
	ccFnc.setStart(fnc->start_ea);
	ccFnc.setEnd(fnc->end_ea);
	// TODO: return type is always set to default: ugly, make it better.
	ccFnc.returnType.setLlvmIr(defaultTypeString());

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
	else if (isLinkedFunction(fnc))
	{
		ccFnc.setIsDynamicallyLinked();
	}
	else
	{
		ccFnc.setIsUserDefined();
	}

	// For IDA 6.x (don't know about IDA 7.x):
	// get_tinfo2() is preferred before guess_func_tinfo2()
	// for unknown reason, guess_func_tinfo2() sometimes mix up the
	// arguments (vawtrak sub_10021A76).
	//
	tinfo_t fncType;
	get_tinfo(&fncType, fnc->start_ea);
	if (!fncType.is_func())
	{
		// Guess type from first instruction address.
		//
		if (guess_tinfo(&fncType, fnc->start_ea) != GUESS_FUNC_OK)
		{
			// problem
		}
	}

	if (fncType.is_func())
	{
		generateFunctionType(config, structIdSet, fncType, ccFnc);
	}

	config.functions.insert(ccFnc);
}

void generateFunctions(
		retdec::config::Config& config,
		std::map<tinfo_t, std::string>& structIdSet)
{
	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		generateFunction(config, structIdSet, getn_func(i));
	}
}

void generateGlobals(
		retdec::config::Config& config,
		std::map<tinfo_t, std::string>& structIdSet)
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

			auto s = retdec::common::Storage::inMemory(
					retdec::common::Address(head));
			retdec::common::Object global(buff.c_str(), s);

			// Get type.
			//
			tinfo_t getType;
			get_tinfo(&getType, head);

			if (!getType.empty() && getType.present() && getType.is_func())
			{
				if (config.functions.getFunctionByStartAddress(head) != nullptr)
				{
					continue;
				}

				std::string fncName = buff.c_str();
				std::replace(fncName.begin(), fncName.end(), '.', '_');

				retdec::common::Function ccFnc(fncName);
				ccFnc.setStart(head);
				ccFnc.setEnd(head);
				ccFnc.setIsDynamicallyLinked();
				generateFunctionType(config, structIdSet, getType, ccFnc);

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
				global.type.setLlvmIr(type2string(config, structIdSet, getType));
			}
			else
			{
				global.type.setLlvmIr(addrType2string(head));
			}

			config.globals.insert(global);
		}
	}
}

bool fillConfig(retdec::config::Config& config, const std::string& out)
{
	std::map<tinfo_t, std::string> structIdSet;

	config.structures.clear();
	config.functions.clear();
	config.globals.clear();

	if (generateHeader(config, out))
	{
		return true;
	}
	generateFunctions(config, structIdSet);
	generateGlobals(config, structIdSet);

	return false;
}
