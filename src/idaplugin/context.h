
#ifndef HEXRAYS_DEMO_CONTEXT_H
#define HEXRAYS_DEMO_CONTEXT_H

#include <iostream>
#include <iomanip>
#include <list>
#include <map>
#include <set>
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
#include <moves.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <retdec/utils/filesystem_path.h>
#include <retdec/utils/time.h>

#include "function.h"
#include "ui.h"

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

/**
 * Plugin's info messages.
 */
int demo_msg(const char *format, ...);

/**
 * Plugin's global data.
 */
class Context : public plugmod_t, public event_listener_t
{
	// Inherited.
	//
	public:
		virtual bool idaapi run(size_t) override;
		virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

		Context();
		virtual ~Context();

	// Actions.
	//
	public:
		function_ctx_ah_t function_ctx_ah;
		const action_desc_t function_ctx_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				function_ctx_ah_t::actionName,
				function_ctx_ah_t::actionLabel,
				&function_ctx_ah,
				this,
				function_ctx_ah_t::actionHotkey,
				nullptr,
				-1
		);

		variable_ctx_ah_t variable_ctx_ah;
		const action_desc_t variable_ctx_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				variable_ctx_ah_t::actionName,
				variable_ctx_ah_t::actionLabel,
				&variable_ctx_ah,
				this,
				variable_ctx_ah_t::actionHotkey,
				nullptr,
				-1
		);

		copy2asm_ah_t copy2asm_ah = copy2asm_ah_t(*this);
		const action_desc_t copy2asm_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				copy2asm_ah_t::actionName,
				copy2asm_ah_t::actionLabel,
				&copy2asm_ah,
				this,
				copy2asm_ah_t::actionHotkey,
				nullptr,
				-1
		);

	// Context data.
	//
	public:
		TWidget* custViewer = nullptr;
		TWidget* codeViewer = nullptr;
		/// Currently displayed function.
		Function* fnc = nullptr;
		// Color used by view synchronization.
		bgcolor_t syncColor = 0x90ee90;

	// Plugin information.
	public:
		inline static const std::string pluginName         = "RetDec";
		inline static const std::string pluginID           = "avast.retdec";
		inline static const std::string pluginProducer     = "Avast Software";
		inline static const std::string pluginCopyright    = "Copyright 2020 " + pluginProducer;
		inline static const std::string pluginEmail        = "support@retdec.com";
		inline static const std::string pluginURL          = "https://retdec.com/";
		inline static const std::string pluginRetDecGithub = "https://github.com/avast/retdec";
		inline static const std::string pluginGithub       = "https://github.com/avast/retdec-idaplugin";
		inline static const std::string pluginContact      = pluginURL + "\nEMAIL: " + pluginEmail;
		inline static const std::string pluginVersion      = RELEASE_VERSION;
		inline static const std::string pluginHotkey       = "Ctrl-d";
		inline static const std::string pluginBuildDate    = retdec::utils::getCurrentDate();
		/// Plugin (addon) information showed in the About box.
		addon_info_t pluginInfo;
		int pluginRegNumber = -1;

	public:
		retdec::utils::FilesystemPath idaPath;
		std::string workDir;
		std::string workIdb;
		std::string inputPath;
		std::string inputName;
};

#endif