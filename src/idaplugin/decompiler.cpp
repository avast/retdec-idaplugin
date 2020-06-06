
#include <map>
#include <fstream>

#include <ida.hpp>
#include <fpro.h>

#include <retdec/retdec/retdec.h>
#include <retdec/utils/binary_path.h>

#include "config.h"
#include "context.h"
#include "decompiler.h"
#include "utils.h"

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

/**
 * Perform startup check that determines, if plugin can decompile IDA's input file.
 * @return True if plugin can decompile IDA's input, false otherwise.
 */
bool canDecompileInput()
{
	std::string procName = inf_get_procname();
	auto fileType = inf_get_filetype();

	// 32-bit binary -> is_32bit() == 1 && is_64bit() == 0.
	// 64-bit binary -> is_32bit() == 1 && is_64bit() == 1.
	// Allow 64-bit x86.
	if ((!inf_is_32bit() || inf_is_64bit()) && !isX86())
	{
		WARNING_GUI(Context::pluginName << " version " << Context::pluginVersion
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
			WARNING_GUI(Context::pluginName
					<< " version " << Context::pluginVersion
					<< " cannot decompile this input file (file type = "
					<< ft << ").\n"
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
	if (inf.filetype == f_BIN)
	{
		// Section VMA.
		//
		decompInfo.rawSectionVma = inf.min_ea;

		// Entry point.
		//
		if (inf.start_ea != BADADDR)
		{
			decompInfo.rawEntryPoint = inf.start_ea;
		}
		else
		{
			decompInfo.rawEntryPoint = decompInfo.rawSectionVma;
		}

		// Architecture + endian.
		//
		std::string procName = inf.procname;
		if (procName == "mipsr" || procName == "mipsb")
		{
			arch = "mips";
			decompInfo.endian = "big";
		}
		else if (procName == "mipsrl" || procName == "mipsl" || procName == "psp")
		{
			arch = "mips";
			decompInfo.endian = "little";
		}
		else if (procName == "ARM")
		{
			arch = "arm";
			decompInfo.endian = "little";
		}
		else if (procName == "ARMB")
		{
			arch = "arm";
			decompInfo.endian = "big";
		}
		else if (procName == "PPCL")
		{
			arch = "powerpc";
			decompInfo.endian = "little";
		}
		else if (procName == "PPC")
		{
			arch = "powerpc";
			decompInfo.endian = "big";
		}
		else if (isX86())
		{
			arch = inf_is_64bit() ? "x86-64" : "x86";
			decompInfo.endian = "little";
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

Function* Decompiler::decompile(ea_t ea)
{
	func_t* fnc = get_func(ea);
	if (fnc == nullptr)
	{
		WARNING_GUI("Function must be selected by the cursor.\n");
		return nullptr;
	}

	auto inFile = getInputPath();
	if (inFile.empty())
	{
		WARNING_GUI("Cannot decompile - there is no input file.");
		return nullptr;
	}
	if (!canDecompileInput())
	{
		return nullptr;
	}

	retdec::config::Config config;

	auto idaPath = retdec::utils::getThisBinaryDirectoryPath();
	auto configPath = idaPath;
	configPath.append("plugins");
	configPath.append("retdec");
	configPath.append("decompiler-config.json");
	if (configPath.exists())
	{
		config = retdec::config::Config::fromFile(configPath.getPath());
		config.parameters.fixRelativePaths(idaPath.getPath());
	}

	std::string tmp = qtmpnam(nullptr, 0);

	config.parameters.setInputFile(inFile);

	config.parameters.setOutputAsmFile(tmp + ".dsm");
	config.parameters.setOutputBitcodeFile(tmp + ".bc");
	config.parameters.setOutputLlvmirFile(tmp + ".ll");
	config.parameters.setOutputConfigFile(tmp + ".config.json");
	config.parameters.setOutputFile(tmp + ".c.json");
	config.parameters.setOutputUnpackedFile(tmp + "-unpacked");

	retdec::common::AddressRange r(fnc->start_ea, fnc->end_ea);
	config.parameters.selectedRanges.insert(r);
	config.parameters.setIsSelectedDecodeOnly(true);

	msg("===============> %s\n", tmp.c_str());

	fillConfig(config);

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
		return nullptr;
	}
	catch (...)
	{
		WARNING_GUI("Decompilation exception: unknown" << std::endl);
		return nullptr;
	}

	return nullptr;
}
