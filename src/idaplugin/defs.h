/**
 * @file idaplugin/defs.h
 * @brief Plugin-global definitions and includes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_DEFS_H
#define IDAPLUGIN_DEFS_H

#include <list>
#include <map>

#include <idasdk/include/ida.hpp> // this must be included before other idasdk headers
#include <idasdk/include/auto.hpp>
#include <idasdk/include/bytes.hpp>
#include <idasdk/include/demangle.hpp>
#include <idasdk/include/diskio.hpp>
#include <idasdk/include/frame.hpp>
#include <idasdk/include/funcs.hpp>
#include <idasdk/include/idp.hpp>
#include <idasdk/include/kernwin.hpp>
#include <idasdk/include/lines.hpp>
#include <idasdk/include/loader.hpp>
#include <idasdk/include/segment.hpp>
#include <idasdk/include/strlist.hpp>
#include <idasdk/include/struct.hpp>
#include <idasdk/include/typeinf.hpp>
#include <idasdk/include/ua.hpp>
#include <idasdk/include/xref.hpp>

#include "retdec-config/config.h"
#include "tl-cpputils/address.h"
#include "tl-cpputils/os.h"
#include "tl-cpputils/time.h"

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

#define DBG_MSG( ... )     if (PRINT_DEBUG)   msg( __VA_ARGS__ )
#define ERROR_MSG( ... )   if (PRINT_ERROR)   msg("[RetDec error]  :\t" __VA_ARGS__ ) ///< use this only for non-critical error messages.
#define WARNING_MSG( ... ) if (PRINT_WARNING) msg("[RetDec warning]:\t" __VA_ARGS__ ) ///< use this only for user info warnings.
#define INFO_MSG( ... )    if (PRINT_INFO)    msg("[RetDec info]   :\t" __VA_ARGS__ ) ///< use this to inform user.

// Msg macros for events.
//
extern int eventCntr;

#define PRINT_IDP_EVENTS false
#define PRINT_IDB_EVENTS false
#define PRINT_UI_EVENTS  false

#define IDP_MSG( ... )   if (PRINT_IDP_EVENTS) { msg("IDP [%d] :  ", eventCntr++); msg( __VA_ARGS__ ); }
#define IDB_MSG( ... )   if (PRINT_IDB_EVENTS) { msg("IDB [%d] :  ", eventCntr++); msg( __VA_ARGS__ ); }
#define UI_MSG( ... )    if (PRINT_UI_EVENTS)  { msg("UI  [%d] :  ", eventCntr++); msg( __VA_ARGS__ ); }

#define NO_MSG( ... )    ;

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
		std::string pluginVersion          = "0.3.1";
		std::string pluginVersionCheckDate = "";
		std::string pluginLatestVersion    = "";
		std::string pluginHotkey           = "Ctrl-d";
		std::string pluginBuildDate        = tl_cpputils::getCurrentDate();
#ifdef OS_WINDOWS
		std::string pluginBuildSystem      = "Windows";
#else
		std::string pluginBuildSystem      = "Linux";
#endif
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
		retdec_config::Config configDB;
		std::string mode;
		std::string architecture;
		std::string endian;
		tl_cpputils::Address rawEntryPoint;
		tl_cpputils::Address rawSectionVma;

		std::map<func_t*, FunctionInfo> fnc2code;
		std::list<func_t*> navigationList;
		std::list<func_t*>::iterator navigationActual;

	// One viewer information.
	//
	public:
		const std::string formName  = "RetDec";
		TForm *form                 = nullptr;
		TCustomControl *viewer      = nullptr;

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

	// Plugin configuration information.
	//
	public:
		bool isDecompileShInSystemPath() const;
		bool isDecompileShInSpecifiedPath() const;
		bool isApiKeyOk() const;
		bool isApiUrlOk() const;

		bool configureDecompilation();

		bool isUseThreads() const;
		void setIsUseThreads(bool f);

		bool isApiDecompilation() const;
		bool isLocalDecompilation() const;
		void setIsApiDecompilation(bool f);
		void setIsLocalDecompilation(bool f);

	public:
		const std::string pluginConfigFileName = "retdec-config.json";
		std::string pluginConfigFile;
		std::string apiUserAgent = "RetDec IDA Plugin (v" + pluginVersion + ", " + pluginBuildDate + ", " + pluginBuildSystem + ")";
		const std::string apiUrl = "https://retdec.com/service/api";
		std::string apiKey;
		/// Path to decompile.sh set by used in configuration menu.
		std::string decompileShPath;
		/// Path to decompile.sh which will be used in local decompilation.
		std::string decompilationShCmd;

	private:
		/// Only for debugging during development.
		bool useThreads = true;
		bool locaDecomp = false;
};

} // namespace idaplugin

#endif
