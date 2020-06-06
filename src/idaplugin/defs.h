
#ifndef IDAPLUGIN_DEFS_H
#define IDAPLUGIN_DEFS_H

#include <iostream>
#include <list>
#include <map>
#include <sstream>

// RetDec includes.
//
#include "retdec/config/config.h"
#include "retdec/common/address.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/os.h"
#include "retdec/utils/time.h"

namespace idaplugin {

class FunctionInfo
{
	public:
		std::string code;
		strvec_t idaCode;
};

/**
 * General information used by this plugin.
 */
class RdGlobalInfo
{
	public:
		RdGlobalInfo();

	// General information common for all decompilations or viewers.
	//
	public:
		std::string workDir;
		std::string workIdb;
		std::string inputPath;
		/// Retargetable decompilation DB file name.
		std::string dbFile;
		retdec::config::Config configDB;
		std::string mode;
		std::string architecture;
		std::string endian;
		retdec::common::Address rawEntryPoint;
		retdec::common::Address rawSectionVma;

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
		intptr_t decompPid          = 0;
		void* hDecomp               = nullptr;

	// Plugin configuration information.
	//
	public:
		bool isUseThreads() const;
		void setIsUseThreads(bool f);

	public:
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
