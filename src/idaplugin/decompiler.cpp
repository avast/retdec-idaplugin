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

#include "boost/network/protocol/http/client.hpp"
#include "retdec/utils/os.h"
#include "code_viewer.h"
#include "decompiler.h"
#include "plugin_config.h"
#include "retdec/retdec.h"

using namespace retdec;

namespace {

/**
 * @brief Check if the provided version is valid.
 *
 * @param version Version string.
 *
 * @return @c true if the version is valid, @c false otherwise.
 */
bool isValidVersion(const std::string &version)
{
	return std::regex_match(version, std::regex(R"(\d+(\.\d+)*)"));
}

} // anonymous namespace

namespace idaplugin {

// The default client setting:
//using http = boost::network::http::client;
// used in cpp-netlib examples causes IDA to crash.
// It crashed when used here in the decompilation thread, but also if used in IDA's main thread.
// However, standalone testing implementation of simple wget works with it.
// We tried to debug it with dbg and run it in valgrind, but we were not able to find and fix the problem.
//
// When keepalive setting is used, IDA does not crash.
// However, this is not perfect, since we do not really need to keep connection alive to check version.
//
using http = boost::network::http::basic_client<
	boost::network::http::tags::http_keepalive_8bit_tcp_resolve, 1, 1
>;

/**
 * Download the lastest plugin version from our web site.
 * @return @c False if download successful and version valid -- the latest version was updated.
 *         @c True otherwise -- the latest version was not updated.
 */
bool getLatestPluginVersion(RdGlobalInfo *di)
{
	try
	{
		http client;
		http::request request("https://retdec.com/idaplugin/latest-version/");
		request << boost::network::header("Connection", "close");
		http::response response = client.get(request);

		std::string v = body(response);
		if (isValidVersion(v))
		{
			di->pluginLatestVersion = v;
			return false;
		}
	}
	catch (std::exception & e)
	{
		warning("Version check FAILED: %s\nDecompilation will be performed, but problems might occur.\n", e.what());
	}

	return true;
}

/**
 * @return @c True if version is bad and decompilation cannot continue.
 *         @c False otherwise.
 */
bool checkPluginVersion(RdGlobalInfo *di)
{
	if (di->pluginVersionCheckDate != retdec::utils::getCurrentDate())
	{
		INFO_MSG("Download the latest available plugin version ...\n");
		getLatestPluginVersion(di);
		di->pluginVersionCheckDate = retdec::utils::getCurrentDate(); // TODO: setter for this which auto saves to config?
		saveConfigTofile(*di);
	}
	else
	{
		INFO_MSG("Using the cached latest available plugin version ...\n");
	}

	if (di->pluginLatestVersion.empty())
	{
		INFO_MSG("Unable to get the latest available plugin version: decompilation allowed, but there might be problems.\n");
		return false;
	}
	else if(di->pluginLatestVersion != di->pluginVersion)
	{
		INFO_MSG("There is a newer plugin version available: download it in order to use the plugin.\n");
		showVersionCheckForm(di);
		return true;
	}
	else
	{
		INFO_MSG("Version check: OK\n");
		return false;
	}
}

/**
 * This callback is called every time decompilation progress is actualized.
 * @param d Decompilation.
 */
static void idaapi progressCallback(const Decompilation &d)
{
	INFO_MSG( "Currently completed: %d %%\n", d.getCompletion() );
}

/**
 * Decompile through RetDec's API.
 * @param di Plugin's global information.
 */
static void idaapi apiDecompilation(RdGlobalInfo *di)
{
	if (checkPluginVersion(di))
	{
		INFO_MSG("Decompilation aborted, your RetDec plugin version %s is old.\n", di->pluginVersion.c_str() );
		di->decompSuccess = false;
		return;
	}

	try
	{
		Decompiler decompiler(
			Settings()
				.apiUrl(di->apiUrl)
				.apiKey(di->apiKey)
				.userAgent(di->apiUserAgent)
		);

		DecompilationArguments args;

		if (di->mode.empty())
		{
			args.mode("bin");
		}
		else
		{
			args.mode(di->mode);
		}

		if (di->isSelectiveDecompilation())
		{
			args.argument("ida_color_c", "1");
		}

		if (!di->architecture.empty())
		{
			args.argument("architecture", di->architecture);
		}
		if (!di->endian.empty())
		{
			args.argument("endian", di->endian);
		}
		if (di->rawEntryPoint.isDefined())
		{
			args.argument("raw_entry_point", di->rawEntryPoint.toHexPrefixString());
		}
		if (di->rawSectionVma.isDefined())
		{
			args.argument("raw_section_vma", di->rawSectionVma.toHexPrefixString());
		}

		//args.argument("decomp_optimizations", "limited"); // normal, none, limited
		args.inputFile( File::fromFilesystem(di->inputPath) );
		args.file("ida_config", File::fromFilesystem(di->dbFile));

		if (!di->ranges.empty())
		{
			args.selDecompRanges(di->ranges);
			args.selDecompDecoding("only");
		}

		auto decompilation = decompiler.runDecompilation( args );
		INFO_MSG("Decompilation started, ID = %s\n", decompilation->getId().c_str() );
		decompilation->waitUntilFinished( progressCallback );
		INFO_MSG("Decompilation finished, ID = %s\n", decompilation->getId().c_str() );

		if (di->isSelectiveDecompilation())
		{
			di->fnc2code[di->decompiledFunction].code = decompilation->getOutputHll();
		}
		else
		{
			std::ofstream outFile(di->outputFile);
			outFile << decompilation->getOutputHll();
		}

		di->decompSuccess = true;
	}
	catch (const Error &ex)
	{
		warning( "Decompilation FAILED: %s\n", ex.what() );
		di->decompSuccess = false;
		return;
	}
}

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
		warning("std::system(%s) failed with error code %d\n", di->decCmd.c_str(), decRet);
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
		std::string code((std::istreambuf_iterator<char>(decFile)),std::istreambuf_iterator<char>());
		di->fnc2code[di->decompiledFunction].code = code;
	}

	decFile.close();
	di->decompSuccess = true;
}

/**
 * Thread function, it runs the decompilation and displays decompiled code.
 * @param ud Plugin's global information.
 */
static int idaapi threadFunc(void *ud)
{
	RdGlobalInfo *di = static_cast<RdGlobalInfo*>(ud);
	di->decompRunning = true;

	if (di->isLocalDecompilation())
	{
		INFO_MSG("Local decompilation ...\n");
		localDecompilation(di);
	}
	else
	{
		INFO_MSG("API decompilation ...\n");
		apiDecompilation(di);
	}

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
void createRangesFromSelectedFunction(RdGlobalInfo &decompInfo, func_t *fnc)
{
	std::set<ea_t> selectedFncs;
	std::stringstream ss;

	ss << "0x" << std::hex << fnc->startEA << "-" << "0x" << std::hex << (fnc->endEA-1);
	selectedFncs.insert(fnc->startEA);

	// Experimental -- decompile all functions called from this one.
	//
	func_item_iterator_t fii;
	for ( bool ok=fii.set(fnc); ok; ok=fii.next_code() )
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
				if (called && selectedFncs.find(called->startEA) == selectedFncs.end())
				{
					selectedFncs.insert(called->startEA);
					ss << ",0x" << std::hex << called->startEA << "-" << "0x" << std::hex << (called->endEA-1);
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
					if (called == fnc && selectedFncs.find(caller->startEA) == selectedFncs.end())
					{
						selectedFncs.insert(caller->startEA);
						ss << ",0x" << std::hex << caller->startEA << "-" << "0x" << std::hex << (caller->endEA-1);
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
	decompInfo.decCmd = "";
#ifdef OS_WINDOWS
	// On Windows, shell scripts have to be run through 'sh'; otherwise, they
	// are not run through Bash, which causes us problems.
	decompInfo.decCmd += "sh ";
#endif
	decompInfo.decCmd += "'" + decompInfo.decompilationShCmd + "' '" + decompInfo.inputPath;
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
