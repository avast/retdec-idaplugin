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

	runCommand(
			di->pythonInterpreter,
			di->pythonInterpreterArgs + di->decCmd,
			&di->decompPid,
			true);

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
 * @param[out] decompInfo Plugin's global information.
 * @param      fnc        Function selected for decompilation.
 */
void createRangesFromSelectedFunction(RdGlobalInfo& decompInfo, func_t* fnc)
{
	std::stringstream ss;
	ss << "0x" << std::hex << fnc->start_ea << "-" << "0x" << std::hex << (fnc->end_ea-1);

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
	decompInfo.decCmd = "\"" + decompInfo.decompilationCmd + "\"";
	decompInfo.decCmd += " \"" + decompInfo.inputPath + "\"";
	decompInfo.decCmd += " --config=\"" + decompInfo.dbFile + "\"";

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
		decompInfo.decCmd += " -o \"" + decompInfo.inputPath + ".c\"";
	}
	else
	{
		decompInfo.decCmd += " -o \"" + decompInfo.outputFile + "\"";
	}

	if ( !decompInfo.ranges.empty() )
	{
		decompInfo.decCmd += " --select-decode-only --select-ranges=\"" + decompInfo.ranges + "\"";
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
