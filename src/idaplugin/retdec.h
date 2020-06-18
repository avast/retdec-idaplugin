
#ifndef RETDEC_RETDEC_H
#define RETDEC_RETDEC_H

#include <iostream>
#include <iomanip>
#include <list>
#include <map>
#include <set>
#include <sstream>

#include <retdec/utils/filesystem_path.h>
#include <retdec/utils/time.h>

#include "function.h"
#include "ui.h"
#include "utils.h"

/**
 * Plugin's global data.
 */
class Context : public plugmod_t, public event_listener_t
{
	// Inherited.
	//
	public:
		virtual bool idaapi run(size_t) override;
		bool runSelectiveDecompilation(ea_t ea);
		bool runFullDecompilation();

		virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

		Context();
		virtual ~Context();

	// Context data.
	//
	public:
		TWidget* custViewer = nullptr;
		TWidget* codeViewer = nullptr;
		/// Currently displayed function.
		Function* fnc = nullptr;
		// Color used by view synchronization.
		bgcolor_t syncColor = 0x90ee90;
		// Should the triggered decompilations run in their own threads?
		bool useThreads = true;

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
		/// Plugin information showed in the About box.
		addon_info_t pluginInfo;
		int pluginRegNumber = -1;

	public:
		retdec::utils::FilesystemPath idaPath;
		std::string workDir;
		std::string workIdb;
		std::string inputPath;
		std::string inputName;

	// Actions.
	//
	public:
		fullDecompilation_ah_t fullDecompilation_ah = fullDecompilation_ah_t(*this);
		const action_desc_t fullDecompilation_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				fullDecompilation_ah_t::actionName,
				fullDecompilation_ah_t::actionLabel,
				&fullDecompilation_ah,
				this,
				fullDecompilation_ah_t::actionHotkey,
				nullptr,
				-1
		);

		jump2asm_ah_t jump2asm_ah = jump2asm_ah_t(*this);
		const action_desc_t jump2asm_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				jump2asm_ah_t::actionName,
				jump2asm_ah_t::actionLabel,
				&jump2asm_ah,
				this,
				jump2asm_ah_t::actionHotkey,
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

		funcComment_ah_t funcComment_ah = funcComment_ah_t(*this);
		const action_desc_t funcComment_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				funcComment_ah_t::actionName,
				funcComment_ah_t::actionLabel,
				&funcComment_ah,
				this,
				funcComment_ah_t::actionHotkey,
				nullptr,
				-1
		);

		renameGlobalObj_ah_t renameGlobalObj_ah = renameGlobalObj_ah_t(*this);
		const action_desc_t renameGlobalObj_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				renameGlobalObj_ah_t::actionName,
				renameGlobalObj_ah_t::actionLabel,
				&renameGlobalObj_ah,
				this,
				renameGlobalObj_ah_t::actionHotkey,
				nullptr,
				-1
		);

		openXrefs_ah_t openXrefs_ah = openXrefs_ah_t(*this);
		const action_desc_t openXrefs_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				openXrefs_ah_t::actionName,
				openXrefs_ah_t::actionLabel,
				&openXrefs_ah,
				this,
				openXrefs_ah_t::actionHotkey,
				nullptr,
				-1
		);

		openCalls_ah_t openCalls_ah = openCalls_ah_t(*this);
		const action_desc_t openCalls_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				openCalls_ah_t::actionName,
				openCalls_ah_t::actionLabel,
				&openCalls_ah,
				this,
				openCalls_ah_t::actionHotkey,
				nullptr,
				-1
		);

		changeFuncType_ah_t changeFuncType_ah = changeFuncType_ah_t(*this);
		const action_desc_t changeFuncType_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
				changeFuncType_ah_t::actionName,
				changeFuncType_ah_t::actionLabel,
				&changeFuncType_ah,
				this,
				changeFuncType_ah_t::actionHotkey,
				nullptr,
				-1
		);
};

#endif