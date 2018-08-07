/**
 * @file idaplugin/decompiler.cpp
 * @brief Module contains classes/methods dealing with program decompilation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

#include "retdec/utils/os.h"
#include "code_viewer.h"
#include "decompiler.h"
#include "plugin_config.h"

using namespace retdec;

namespace idaplugin {

/**
 * Decompile locally on work station.
 * Working RetDec must be installed on the station.
 * @param di Plugin's global information.
 */
static void idaapi localDecompilation(RdGlobalInfo *di)
{
	auto tmp = di->decCmd;
	std::replace(tmp.begin(), tmp.end(), ' ', '\n');
	INFO_MSG("Decompilation command: %s\n", tmp.c_str());
	INFO_MSG("Running the decompilation command ...\n");

	// Do NOT use call_system() because it prevents us to kill the run program
	// by killing IDA. This is needed in, e.g., regression tests (timeout
	// handling). Instead, use std::system(), which works as expected.
	int decRet = std::system(di->decCmd.c_str());
	if (decRet != 0)
	{
		warning("std::system(%s) failed with error code %d\n",
				di->decCmd.c_str(),
				decRet);
		return;
	}

	// Get decompiled and colored file content.
	//
	std::ifstream decFile;
	std::string decName;

	if (!di->outputFile.empty())
	{
		decName = di->outputFile;
	}
	else
	{
		decName = di->inputPath + ".c";
	}
	decFile.open( decName.c_str() );

	if (!decFile.is_open())
	{
		warning("Loading of output C file FAILED.\n");
		di->decompSuccess = false;
		return;
	}

	INFO_MSG("Decompiled file: %s\n", decName.c_str());

	if (di->isSelectiveDecompilation())
	{
		std::string code(
				(std::istreambuf_iterator<char>(decFile)),
				std::istreambuf_iterator<char>());
		di->fnc2code[di->decompiledFunction].code = code;
	}

	decFile.close();
	di->decompSuccess = true;
}

/**
 * Thread function, it runs the decompilation and displays decompiled code.
 * @param ud Plugin's global information.
 */
static int idaapi threadFunc(void* ud)
{
	RdGlobalInfo* di = static_cast<RdGlobalInfo*>(ud);
	di->decompRunning = true;

	INFO_MSG("Local decompilation ...\n");
	localDecompilation(di);

	if (di->decompSuccess && di->isSelectiveDecompilation())
	{
		showDecompiledCode(di);
	}

	di->outputFile.clear();
	di->decompRunning = false;
	return 0;
}

/**
 * Create ranges to decompile from the provided function.
 * All functions called and all function calling the selected function
 * are added to selected ranges -> all of them are decoded and decompiled.
 * @param[out] decompInfo Plugin's global information.
 * @param      fnc        Function selected for decompilation.
 */
void createRangesFromSelectedFunction(RdGlobalInfo& decompInfo, func_t* fnc)
{
	std::set<ea_t> selectedFncs;
	std::stringstream ss;

	ss << "0x" << std::hex << fnc->start_ea << "-" << "0x" << std::hex << (fnc->end_ea-1);
	selectedFncs.insert(fnc->start_ea);

	// Experimental -- decompile all functions called from this one.
	//
	func_item_iterator_t fii;
	for (bool ok=fii.set(fnc); ok; ok=fii.next_code())
	{
		ea_t ea = fii.current();

		xrefblk_t xb;
		for ( bool ok=xb.first_from(ea, XREF_ALL); ok; ok=xb.next_from() )
		{
			if (xb.iscode == 0) // first data reference
				break;

			if (xb.type == fl_CF || xb.type == fl_CN)
			{
				func_t *called = get_func(xb.to);
				if (called && selectedFncs.find(called->start_ea) == selectedFncs.end())
				{
					selectedFncs.insert(called->start_ea);
					ss << ",0x" << std::hex << called->start_ea << "-"
							<< "0x" << std::hex << (called->end_ea-1);
				}
			}
		}
	}

	// Experimental -- decompile all functions calling this one.
	//
	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t *caller = getn_func(i);

		func_item_iterator_t fii;
		for ( bool ok=fii.set(caller); ok; ok=fii.next_code() )
		{
			ea_t ea = fii.current();

			xrefblk_t xb;
			for ( bool ok=xb.first_from(ea, XREF_ALL); ok; ok=xb.next_from() )
			{
				if (xb.iscode == 0) // first data reference
					break;

				if (xb.type == fl_CF || xb.type == fl_CN)
				{
					func_t *called = get_func(xb.to);
					if (called == fnc && selectedFncs.find(caller->start_ea) == selectedFncs.end())
					{
						selectedFncs.insert(caller->start_ea);
						ss << ",0x" << std::hex << caller->start_ea << "-"
								<< "0x" << std::hex << (caller->end_ea-1);
					}
				}
			}
		}
	}

	decompInfo.ranges = ss.str();
	decompInfo.decompiledFunction = fnc;
}

/**
 * Decompile IDA's input.
 * @param decompInfo Plugin's global information.
 */
void decompileInput(RdGlobalInfo &decompInfo)
{
	INFO_MSG("Decompile input ...\n");

	// Construct decompiler call command.
	//
	decompInfo.decCmd = decompInfo.pythonCmd + " ";
	decompInfo.decCmd += "'" + decompInfo.decompilationCmd + "' '" + decompInfo.inputPath;
	decompInfo.decCmd += "' --config='" + decompInfo.dbFile + "'";

	if (!decompInfo.mode.empty())
	{
		decompInfo.decCmd += " -m " + decompInfo.mode + " ";
	}
	if (!decompInfo.architecture.empty())
	{
		decompInfo.decCmd += " -a " + decompInfo.architecture + " ";
	}
	if (!decompInfo.endian.empty())
	{
		decompInfo.decCmd += " -e " + decompInfo.endian + " ";
	}
	if (decompInfo.rawEntryPoint.isDefined())
	{
		decompInfo.decCmd += " --raw-entry-point " + decompInfo.rawEntryPoint.toHexPrefixString() + " ";
	}
	if (decompInfo.rawSectionVma.isDefined())
	{
		decompInfo.decCmd += " --raw-section-vma " + decompInfo.rawSectionVma.toHexPrefixString() + " ";
	}

	if (decompInfo.isSelectiveDecompilation())
	{
		decompInfo.decCmd += " --color-for-ida";
		decompInfo.decCmd += " -o '" + decompInfo.inputPath + ".c'";
	}
	else
	{
		decompInfo.decCmd += " -o '" + decompInfo.outputFile + "'";
	}

	if ( !decompInfo.ranges.empty() )
	{
		decompInfo.decCmd += " --select-decode-only --select-ranges='" + decompInfo.ranges + "'";
	}

	// Create decompilation thread.
	//
	if (decompInfo.isUseThreads())
	{
		decompInfo.decompThread = qthread_create(threadFunc, static_cast<void*>(&decompInfo));
	}
	else
	{
		threadFunc(static_cast<void*>(&decompInfo));
	}
}

} // namespace idaplugin
