/**
 * @file idaplugin/idaplugin.cpp
 * @brief Plugin entry point - definition of plugin's intarface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#include "tl-cpputils/file_io.h"
#include "tl-cpputils/filesystem_path.h"
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
 * Kill old thread if still running.
 * TODO: Killing is not good enough, thread dies but process created by 'call_system()' lives.
 * This might be solved by usage of Petr's API library, so no need to fix it now.
 */
void killDecompilation()
{
	if (decompInfo.decompRunning)
	{
		INFO_MSG("Unfinished decompilation was KILLED !!!\n");
		qthread_kill(decompInfo.decompThread);
		qthread_join(decompInfo.decompThread);
		qthread_free(decompInfo.decompThread);
		decompInfo.decompRunning = false;
	}
}

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
	workIdb += ".idb";

	save_database_ex(workIdb.c_str(), DBFL_COMP);

	INFO_MSG("IDA database saved into :  %s\n", workIdb.c_str());
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
 * Find out if input file is relocatable -- object file.
 * @return @c True if file relocatable, @c false otherwise.
 */
bool isRelocatable()
{
	if (inf.filetype == f_COFF && inf.beginEA == BADADDR)
	{
		return true;
	}
	else if (inf.filetype == f_ELF)
	{
		std::ifstream infile(decompInfo.inputPath, std::ios::binary);
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
 * Decompile only provided function or if nothing provided then the current function under focus.
 * @param fnc2decomp Function to decompile.
 * @param force      If @c true, decompilation is always performed.
 */
void runSelectiveDecompilation(func_t *fnc2decomp = nullptr, bool force = false)
{
	if (isRelocatable() && inf.minEA != 0)
	{
		warning("%s version %s can selectively decompile only relocatable objects loaded at 0x0.\n"
				"Rebase the program to 0x0 or use full decompilation or our web interface at: %s",
				decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str(), decompInfo.pluginURL.c_str());
		return;
	}

	// Decompilation triggered by double click.
	//
	if (fnc2decomp)
	{
		decompInfo.navigationList.erase(++decompInfo.navigationActual, decompInfo.navigationList.end());
		decompInfo.navigationList.push_back( fnc2decomp );
		decompInfo.navigationActual = decompInfo.navigationList.end();
		decompInfo.navigationActual--;

		// Show existing function.
		//
		auto fit = decompInfo.fnc2code.find(fnc2decomp);
		if (!force && fit != decompInfo.fnc2code.end())
		{
			decompInfo.decompiledFunction = fnc2decomp;

			char fncName[MAXSTR];
			get_func_name(fnc2decomp->startEA, fncName, sizeof(fncName));
			INFO_MSG("Show already decompiled function: %s @ %a\n", fncName, fnc2decomp->startEA);

			qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));

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
	else if (get_current_viewer() == decompInfo.viewer && get_current_tform() == decompInfo.form)
	{
		// Re-decompile current function.
		//
		if (decompInfo.decompiledFunction)
		{
			createRangesFromSelectedFunction(decompInfo, decompInfo.decompiledFunction);

			decompInfo.navigationList.erase(decompInfo.navigationActual, decompInfo.navigationList.end());
			decompInfo.navigationList.push_back( decompInfo.decompiledFunction );
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
			warning("Function must be selected by the cursor.\n");
			return;
		}
	}

	INFO_MSG("Running retargetable decompiler plugin:\n");

	killDecompilation();
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

	char *tmp = askfile_cv(         ///< Returns: file name
			true,                   ///< int savefile
			defaultOut.data(),      ///< const char *default_answer
			"Save decompiled file", ///< const char *format
			nullptr                 ///< va_list va
	);

	if (!tmp) ///< canceled
	{
		return;
	}

	decompInfo.outputFile = tmp;
	decompInfo.ranges.clear();
	decompInfo.decompiledFunction = nullptr;

	INFO_MSG("Selected file: %s\n", decompInfo.outputFile.c_str());

	killDecompilation();
	saveIdaDatabase();
	generatePluginDatabase();
	decompileInput(decompInfo);
}

/**
 * Only generate config database.
 */
void runDatabasegeneration()
{
	generatePluginDatabase();
}

/**
 *
 */
bool setInputPath()
{
	char buff[MAXSTR];

	get_root_filename(buff, sizeof(buff));
	std::string inName = buff;

	get_input_file_path(buff, sizeof(buff));
	std::string inPath = buff;

	std::string idb = database_idb;
	std::string id0 = database_id0;
	std::string workDir;
	std::string workIdb;
	if (!idb.empty())
	{
		tl_cpputils::FilesystemPath fsIdb(idb);
		workDir = fsIdb.getParentPath();
		workIdb = idb;
	}
	else if (!id0.empty())
	{
		tl_cpputils::FilesystemPath fsId0(id0);
		workDir = fsId0.getParentPath();
		workIdb = id0;
	}
	if (workIdb.empty() || workDir.empty())
	{
		warning("Cannot decompile this input file, IDB and ID0 are not set.\n");
		return false;
	}

#ifdef OS_WINDOWS
	workDir += "\\";
#else // Linux
	workDir += "/";
#endif

	if (!tl_cpputils::fileExists(inPath))
	{
		INFO_MSG("Input \"%s\" does not exist, trying to recover ...\n", inPath.c_str());

		inPath = workDir + inName;
		if (!tl_cpputils::fileExists(inPath))
		{
			INFO_MSG("Input \"%s\" does not exist, asking user to specify the input file ...\n", inPath.c_str());

			char *tmp = askfile_cv(              ///< Returns: file name
					false,                       ///< int savefile
					nullptr,                     ///< const char *default_answer
					"Input binary to decompile", ///< const char *format
					nullptr                      ///< va_list va
			);

			if (!tmp)
			{
				return false;
			}
			else if (!tl_cpputils::fileExists(std::string(tmp)))
			{
				warning("Cannot decompile this input file, there is no such file: %s\n", tmp);
				return false;
			}

			inPath = tmp;

			INFO_MSG("Successfully recovered, using user selected file \"%s\".\n", inPath.c_str());
		}
		else
		{
			INFO_MSG("Successfully recovered, using input file \"%s\".\n", inPath.c_str());
		}
	}
	else
	{
		INFO_MSG("Working on input file \"%s\".\n", inPath.c_str());
	}

	decompInfo.inputName = inName;
	decompInfo.inputPath = inPath;
	decompInfo.workDir = workDir;
	decompInfo.workIdb = workIdb;

	DBG_MSG("Input Path : %s\n", decompInfo.inputPath.c_str());
	DBG_MSG("Input Name : %s\n", decompInfo.inputName.c_str());
	DBG_MSG("Work dir   : %s\n", decompInfo.workDir.c_str());
	DBG_MSG("Work IDB   : %s\n", decompInfo.workIdb.c_str());

	return true;
}

/**
 * Perform startup check that determines, if plugin can decompile IDA's input file.
 * @return True if plugin can decompile IDA's input, false otherwise.
 * TODO: do some more checking (architecture, ...).
 */
bool canDecompileInput()
{
	if (!inf.is_32bit())
	{
		warning("%s version %s can decompile only 32-bit input files.\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str());
		return false;
	}

	if (!(inf.filetype == f_BIN || inf.filetype == f_PE || inf.filetype == f_ELF || inf.filetype == f_COFF || inf.filetype == f_HEX))
	{
		warning("%s version %s cannot decompile this input file.\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str());
		return false;
	}

	if (!setInputPath())
	{
		return false;
	}

	decompInfo.mode.clear();
	decompInfo.architecture.clear();
	decompInfo.endian.clear();
	decompInfo.rawEntryPoint = tl_cpputils::Address();
	decompInfo.rawSectionVma = tl_cpputils::Address();

	// Check Intel HEX.
	//
	if (inf.filetype == f_HEX)
	{
		std::string procName = inf.procName;
		if (procName == "mipsr" || procName == "mipsb")
		{
			decompInfo.architecture = "mips";
			decompInfo.endian = "big";
		}
		else if (procName == "mipsrl" || procName == "mipsl" || procName == "psp")
		{
			decompInfo.architecture = "mips";
			decompInfo.endian = "little";
		}
		else
		{
			warning("Intel HEX input file can be decompiled only for one of these {mipsr, mipsb, mipsrl, mipsl, psp} processors, not \"%s\".\n", procName.c_str());
			return false;
		}
	}

	// Check BIN (RAW).
	//
	if (inf.filetype == f_BIN)
	{
		decompInfo.mode = "raw";

		// Section VMA.
		//
		decompInfo.rawSectionVma = inf.minEA;

		// Entry point.
		//
		if (inf.beginEA != BADADDR)
		{
			decompInfo.rawEntryPoint = inf.beginEA;
		}
		else
		{
			decompInfo.rawEntryPoint = decompInfo.rawSectionVma;
		}

		// Architecture + endian.
		//
		std::string procName = inf.procName;
		if (procName == "mipsr" || procName == "mipsb")
		{
			decompInfo.architecture = "mips";
			decompInfo.endian = "big";
		}
		else if (procName == "mipsrl" || procName == "mipsl" || procName == "psp")
		{
			decompInfo.architecture = "mips";
			decompInfo.endian = "little";
		}
		else if (procName == "ARM")
		{
			decompInfo.architecture = "arm";
			decompInfo.endian = "little";
		}
		else if (procName == "ARMB")
		{
			decompInfo.architecture = "arm";
			decompInfo.endian = "big";
		}
		else if (procName == "PPCL")
		{
			decompInfo.architecture = "powerpc";
			decompInfo.endian = "little";
		}
		else if (procName == "PPC")
		{
			decompInfo.architecture = "powerpc";
			decompInfo.endian = "big";
		}
		else if (procName == "80386p"
				|| procName == "80386r"
				|| procName == "80486p"
				|| procName == "80486r"
				|| procName == "80586p"
				|| procName == "80586r"
				|| procName == "80686p"
				|| procName == "p2"
				|| procName == "p3"
				|| procName == "p4"
				|| procName == "metapc")
		{
			decompInfo.architecture = "x86";
			decompInfo.endian = "little";
		}
		else
		{
			warning("Binary input file can be decompiled only for one of these "
					"{mipsr, mipsb, mipsrl, mipsl, psp, ARM, ARMB, PPCL, PPC, 80386p, "
					"80386r, 80486p, 80486r, 80586p, 80586r, 80686p, p2, p3, p4} "
					"processors, not \"%s\".\n", procName.c_str());
			return false;
		}
	}

	return true;
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
void idaapi run(int arg)
{
	if (!autoIsOk())
	{
		INFO_MSG("RetDec plugin cannot run because the initial autoanalysis has not been finished.\n");
		return;
	}

	if (!canDecompileInput())
	{
		return;
	}

	// Special modes for regression tests -> force local decompilation.
	//
	auto oldFlagVal = decompInfo.isLocalDecompilation();
	if (arg == 4 || arg == 5)
	{
		decompInfo.setIsLocalDecompilation(true);
	}

	if (decompInfo.configureDecompilation())
	{
		return;
	}

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
	// only plugin configuration
	//
	else if (arg == 2)
	{
		pluginConfigurationMenu(decompInfo);
		return;
	}
	// only run database generation
	//
	else if (arg == 3)
	{
		runDatabasegeneration();
		return;
	}
	// selective decompilation used in plugin's regression tests
	// forced local decompilation + disabled threads
	// function to decompile is selected by "<retdec_select>" string in function's comment
	//
	else if (arg == 4)
	{
		for (unsigned i = 0; i < get_func_qty(); ++i)
		{
			func_t *fnc = getn_func(i);
			auto* c = get_func_cmt(fnc, false);
			if (c == nullptr)
			{
				continue;
			}
			std::string cmt = c;
			qfree(static_cast<void*>(c));

			if (cmt.find("<retdec_select>") != std::string::npos)
			{
				decompInfo.outputFile = decompInfo.inputPath + ".c";
				decompInfo.setIsUseThreads(false);
				runSelectiveDecompilation(fnc);
				decompInfo.setIsLocalDecompilation(oldFlagVal);
				break;
			}
		}
		return;
	}
	// full decompilation used in plugin's regression tests
	// forced local decompilation + disabled threads
	//
	else if (arg == 5)
	{
		decompInfo.setIsUseThreads(false);
		runAllDecompilation();
		decompInfo.setIsLocalDecompilation(oldFlagVal);
		return;
	}
	else
	{
		warning("%s version %s cannot handle argument '%d'.\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str(), arg);
		return;
	}
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
	if (decompInfo.pluginRegNumber == -1)
	{
		warning("%s version %s failed to register.\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str());
		return PLUGIN_SKIP;
	}
	else
	{
		INFO_MSG("%s version %s registered OK\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str());
	}

	readConfigFile(decompInfo);

	add_menu_item(
			"Options/BinaryPaths",
			"RetDec plugin options...",
			nullptr,
			SETMENU_APP,
			pluginConfigurationMenuCallBack,
			&decompInfo);
	add_menu_item(
			"Options/RetDecPluginOptions",
			"-",
			nullptr,
			SETMENU_INS,
			nullptr,
			nullptr);

	INFO_MSG("%s version %s loaded OK\n", decompInfo.pluginName.c_str(), decompInfo.pluginVersion.c_str());

	inited = true;
	return PLUGIN_KEEP;
}

/**
 * Plugin termination function.
 * IDA is searching for this function.
 */
void idaapi term()
{
	killDecompilation();
}

/**
 * Plugin interface definition.
 * IDA is searching for this structure.
 */
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,             // Constant version.
	0,                                 // Plugin flags.
	init,                              // Initialize.
	term,                              // Terminate. this pointer may be nullptr.
	run,                               // Invoke plugin.
	decompInfo.pluginCopyright.data(), // Long comment about the plugin.
	decompInfo.pluginURL.data(),       // Multiline help about the plugin.
	decompInfo.pluginName.data(),      // The preferred short name of the plugin.
	decompInfo.pluginHotkey.data()     // The preferred hotkey to run the plugin.
};
