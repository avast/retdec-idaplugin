/**
 * @file idaplugin/idaplugin.cpp
 * @brief Plugin entry point - definition of plugin's intarface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#if !defined(OS_WINDOWS) // Linux || macOS
	#include <signal.h>
#endif

#include "retdec/utils/file_io.h"
#include "retdec/utils/filesystem_path.h"
#include "code_viewer.h"
#include "config_generator.h"
#include "decompiler.h"
#include "defs.h"
#include "plugin_config.h"

namespace idaplugin {

/**
 * General info used by plugin.
 */
RdGlobalInfo decompInfo;

/**
 * Save IDA database before decompilation to protect it if something goes wrong.
 * @param inSitu If true, DB is saved with the same name as IDA default database.
 * @param suffix If @p inSitu is false, use this suffix to distinguish DBs.
 */
void saveIdaDatabase(bool inSitu = false, const std::string &suffix = ".dec-backup")
{
	INFO_MSG("Saving IDA database ...\n");

	std::string workIdb = decompInfo.workIdb;

	auto dotPos = workIdb.find_last_of(".");
	if (dotPos != std::string::npos)
	{
		workIdb.erase(dotPos, std::string::npos);
	}

	if (!inSitu)
	{
		workIdb += suffix;
	}

	workIdb += std::string(".") + IDB_EXT;

	save_database(workIdb.c_str(), DBFL_COMP);

	INFO_MSG("IDA database saved into :  " << workIdb << "\n");
}

/**
 * Generate retargetable decompiler database from IDA database.
 */
void generatePluginDatabase()
{
	INFO_MSG("Generating retargetable decompilation DB ...\n");

	ConfigGenerator jg(decompInfo);
	decompInfo.dbFile = jg.generate();
}

/**
 * Decompile only provided function or if nothing provided then the current function under focus.
 * @param fnc2decomp Function to decompile.
 * @param force      If @c true, decompilation is always performed.
 */
void runSelectiveDecompilation(func_t *fnc2decomp = nullptr, bool force = false)
{
	if (isRelocatable() && inf.min_ea != 0)
	{
		WARNING_GUI(decompInfo.pluginName << " version " << decompInfo.pluginVersion
				<< " can selectively decompile only relocatable objects loaded at 0x0.\n"
				"Rebase the program to 0x0 or use full decompilation or our web interface at: "
				<< decompInfo.pluginURL);
		return;
	}

	// Decompilation triggered by double click.
	//
	if (fnc2decomp)
	{
		decompInfo.navigationList.erase(
				++decompInfo.navigationActual,
				decompInfo.navigationList.end());
		decompInfo.navigationList.push_back(fnc2decomp);
		decompInfo.navigationActual = decompInfo.navigationList.end();
		decompInfo.navigationActual--;

		// Show existing function.
		//
		auto fit = decompInfo.fnc2code.find(fnc2decomp);
		if (!force && fit != decompInfo.fnc2code.end())
		{
			decompInfo.decompiledFunction = fnc2decomp;

			qstring fncName;
			get_func_name(&fncName, fnc2decomp->start_ea);
			INFO_MSG("Show already decompiled function: " << fncName.c_str()
					<< " @ " << std::hex << fnc2decomp->start_ea << "\n");

			ShowOutput show(&decompInfo);
			show.execute();

			return;
		}
		// Decompile new function.
		//
		else
		{
			createRangesFromSelectedFunction(decompInfo, fnc2decomp);
		}
	}
	// Decompilation run from our viewer.
	//
	else if (get_current_viewer() == decompInfo.custViewer
			|| get_current_viewer() == decompInfo.codeViewer)
	{
		// Re-decompile current function.
		//
		if (decompInfo.decompiledFunction)
		{
			createRangesFromSelectedFunction(
					decompInfo,
					decompInfo.decompiledFunction);

			decompInfo.navigationList.erase(
					decompInfo.navigationActual,
					decompInfo.navigationList.end());
			decompInfo.navigationList.push_back(decompInfo.decompiledFunction);
			decompInfo.navigationActual = decompInfo.navigationList.end();
			decompInfo.navigationActual--;
		}
		// No current function -> something went wrong.
		//
		else
		{
			return;
		}
	}
	// Decompilation run from some other window.
	//
	else
	{
		ea_t addr = get_screen_ea();
		func_t *fnc = get_func(addr);

		// Decompilation run from IDA disasm window (or some other window that allows it).
		//
		if (fnc)
		{
			createRangesFromSelectedFunction(decompInfo, fnc);
			decompInfo.decompiledFunction = fnc;

			decompInfo.navigationList.clear();
			decompInfo.navigationList.push_back( decompInfo.decompiledFunction );
			decompInfo.navigationActual = decompInfo.navigationList.end();
			decompInfo.navigationActual--;
		}
		// Bad window or bad position in disasm code.
		//
		else
		{
			WARNING_GUI("Function must be selected by the cursor.\n");
			return;
		}
	}

	INFO_MSG("Running retargetable decompiler plugin:\n");

	saveIdaDatabase();
	generatePluginDatabase();
	decompileInput(decompInfo);
}

/**
 * Decompile everything, but do not show it in viewer, instead dump it into file.
 */
void runAllDecompilation()
{
	std::string defaultOut = decompInfo.inputPath + ".c";

	char *tmp = ask_file(                ///< Returns: file name
			true,                        ///< bool for_saving
			defaultOut.data(),           ///< const char *default_answer
			"%s",                        ///< const char *format
			"Save decompiled file"
	);

	if (tmp == nullptr) ///< canceled
	{
		return;
	}

	decompInfo.outputFile = tmp;
	decompInfo.ranges.clear();
	decompInfo.decompiledFunction = nullptr;

	INFO_MSG("Selected file: " << decompInfo.outputFile << "\n");

	saveIdaDatabase();
	generatePluginDatabase();
	decompileInput(decompInfo);
}

} // namespace idaplugin

using namespace idaplugin;

/**
 * Plugin run function.
 * The plugin can be passed an integer argument from plugins.cfg file.
 * This can be useful when we want the one plugin to do something
 * different depending on the hot-key pressed or menu item selected.
 * IDA is searching for this function.
 * @param arg Argument set to value according plugins.cfg based on invocation hotkey.
 */
bool idaapi run(size_t arg)
{
	// ordinary selective decompilation
	//
	if (arg == 0)
	{
		runSelectiveDecompilation();
	}
	// ordinary full decompilation
	//
	else if (arg == 1)
	{
		runAllDecompilation();
	}
	// selective decompilation used in plugin's regression tests
	// forced local decompilation + disabled threads
	// function to decompile is selected by "<retdec_select>" string in function's comment
	//
	else if (arg == 4)
	{
		for (unsigned i = 0; i < get_func_qty(); ++i)
		{
			qstring qCmt;
			func_t *fnc = getn_func(i);
			if (get_func_cmt(&qCmt, fnc, false) <= 0)
			{
				continue;
			}

			std::string cmt = qCmt.c_str();;
			if (cmt.find("<retdec_select>") != std::string::npos)
			{
				decompInfo.outputFile = decompInfo.inputPath + ".c";
				decompInfo.setIsUseThreads(false);
				runSelectiveDecompilation(fnc);
				break;
			}
		}
		return true;
	}
	// full decompilation used in plugin's regression tests
	// forced local decompilation + disabled threads
	//
	else if (arg == 5)
	{
		decompInfo.setIsUseThreads(false);
		runAllDecompilation();
		return true;
	}
	else
	{
		WARNING_GUI(decompInfo.pluginName << " version " << decompInfo.pluginVersion
				<< " cannot handle argument '" << arg << "'.\n");
		return false;
	}

	return true;
}

/**
 * Plugin initialization function.
 * IDA is searching for this function.
 */
int idaapi init()
{
	static bool inited = false;
	if (inited)
	{
		return PLUGIN_KEEP;
	}

	decompInfo.pluginRegNumber = register_addon(&decompInfo.pluginInfo);
	if (decompInfo.pluginRegNumber < 0)
	{
		WARNING_GUI(decompInfo.pluginName << " version " << decompInfo.pluginVersion
				<< " failed to register.\n");
		return PLUGIN_SKIP;
	}
	else
	{
		INFO_MSG(decompInfo.pluginName << " version "
				<< decompInfo.pluginVersion << " registered OK\n");
	}

	INFO_MSG(decompInfo.pluginName << " version " << decompInfo.pluginVersion
			<< " loaded OK\n");

	hook_to_notification_point(HT_UI, ui_callback, &decompInfo);
	registerPermanentActions();

	inited = true;
	return PLUGIN_KEEP;
}

/**
 * Plugin termination function.
 * IDA is searching for this function.
 */
void idaapi term()
{
	if (decompInfo.custViewer) {
		close_widget(decompInfo.custViewer, 0);
		decompInfo.custViewer = nullptr;
	}
	if (decompInfo.codeViewer) {
		close_widget(decompInfo.codeViewer, 0);
		decompInfo.codeViewer = nullptr;
	}
	unregister_action("retdec:ActionJumpToAsm");
	unregister_action("retdec:ActionChangeFncGlobName");
	unregister_action("retdec:ActionOpenXrefs");
	unregister_action("retdec:ActionOpenCalls");
	unregister_action("retdec:ActionChangeFncType");
	unregister_action("retdec:ActionChangeFncComment");
	unregister_action("retdec:ActionMoveForward");
	unregister_action("retdec:ActionMoveBackward");
	unhook_from_notification_point(HT_UI, ui_callback);
}
