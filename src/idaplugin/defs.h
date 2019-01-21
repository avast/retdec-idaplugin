/**
 * @file idaplugin/defs.h
 * @brief Plugin-global definitions and includes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_DEFS_H
#define IDAPLUGIN_DEFS_H

#include <iostream>
#include <list>
#include <map>
#include <sstream>

// IDA SDK includes.
//
#include <ida.hpp> // this must be included before other idasdk headers
#include <auto.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <diskio.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

// RetDec includes.
//
#include "retdec/config/config.h"
#include "retdec/utils/address.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/os.h"
#include "retdec/utils/time.h"

namespace idaplugin {

// idaapi is defined by IDA SDK, but if we do this, eclipse won't complain
// even if it do not find the definition.
//
#ifndef idaapi
	#define idaapi
#endif

// General print msg macros.
//
#define PRINT_DEBUG   false
#define PRINT_ERROR   false
#define PRINT_WARNING true
#define PRINT_INFO    true

#define DBG_MSG(body)     if (PRINT_DEBUG)   { std::stringstream ss; ss << std::showbase << body; msg("%s", ss.str().c_str()); }
/// Use this only for non-critical error messages.
#define ERROR_MSG(body)   if (PRINT_ERROR)   { std::stringstream ss; ss << std::showbase << "[RetDec error]  :\t" << body; msg("%s", ss.str().c_str()); }
/// Use this only for user info warnings.
#define WARNING_MSG(body) if (PRINT_WARNING) { std::stringstream ss; ss << std::showbase << "[RetDec warning]:\t" << body; msg("%s", ss.str().c_str()); }
/// Use this to inform user.
#define INFO_MSG(body)    if (PRINT_INFO)    { std::stringstream ss; ss << std::showbase << "[RetDec info]   :\t" << body; msg("%s", ss.str().c_str()); }

/// Use instead of IDA SDK's warning() function.
#define WARNING_GUI(body) { std::stringstream ss; ss << std::showbase << body; warning("%s", ss.str().c_str()); }

class FunctionInfo
{
	public:
		std::string code;
		strvec_t idaCode;
};

// Helper functions.
//
int runCommand(
		const std::string& cmd,
		const std::string& args,
		intptr_t* pid = nullptr,
		bool showWarnings = false);

/**
 * General information used by this plugin.
 */
class RdGlobalInfo
{
	public:
		RdGlobalInfo();

	// General plugin information.
	//
	public:
		std::string pluginName             = "Retargetable Decompiler";
		std::string pluginID               = "avast.retdec";
		std::string pluginProducer         = "Avast Software";
		std::string pluginCopyright        = "Copyright 2017 " + pluginProducer;
		std::string pluginEmail            = "support@retdec.com";
		std::string pluginURL              = "https://retdec.com/";
		std::string pluginContact          = pluginURL + "\nEMAIL: " + pluginEmail;
		std::string pluginVersion          = RELEASE_VERSION;
		std::string pluginHotkey           = "Ctrl-d";
		std::string pluginBuildDate        = retdec::utils::getCurrentDate();
		addon_info_t pluginInfo; ///< Plugin (addon) information showed in the About box.
		int pluginRegNumber         = -1;

	// General information common for all decompilations or viewers.
	//
	public:
		std::string workDir;
		std::string workIdb;
		std::string inputPath;
		std::string inputName;
		/// Retargetable decompilation DB file name.
		std::string dbFile;
		retdec::config::Config configDB;
		std::string mode;
		std::string architecture;
		std::string endian;
		retdec::utils::Address rawEntryPoint;
		retdec::utils::Address rawSectionVma;

		std::map<func_t*, FunctionInfo> fnc2code;
		std::list<func_t*> navigationList;
		std::list<func_t*>::iterator navigationActual;

	// One viewer information.
	//
	public:
		const std::string viewerName = "RetDec";
		TWidget* custViewer = nullptr;
		TWidget* codeViewer = nullptr;

	// One decompilation information.
	//
	public:
		bool isAllDecompilation();
		bool isSelectiveDecompilation();

	public:
		std::string decCmd;
		std::string ranges;
		std::string outputFile;
		bool decompRunning          = false;
		bool decompSuccess          = false;
		bool decompiledAll          = false;
		qthread_t decompThread      = nullptr;
		func_t *decompiledFunction  = nullptr;
		// PID/Handle of launched decompilation process.
		intptr_t decompPid = 0;

	// Plugin configuration information.
	//
	public:
		bool isDecompilerInSpecifiedPath() const;
		bool isDecompilerInSystemPath();
		bool initPythonCommand();
		bool checkPythonCommand();

		bool configureDecompilation();

		bool isUseThreads() const;
		void setIsUseThreads(bool f);

	public:
		const std::string decompilerPyName = "retdec-decompiler.py";
		const std::string pluginConfigFileName = "retdec-config.json";
		retdec::utils::FilesystemPath pluginConfigFile;
		/// Command used to execute python interpreter.
		std::string pythonInterpreter;
		/// Arguments used to execute python interpreter.
		std::string pythonInterpreterArgs;
		/// Path to the decompilation script set by user in configuration menu.
		std::string decompilerPyPath;
		/// Path to the decompilation script which will be used in local decompilation.
		std::string decompilationCmd;

	private:
		/// Only for debugging during development.
		bool useThreads = true;
};

} // namespace idaplugin

#endif
