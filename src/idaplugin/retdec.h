
#ifndef RETDEC_RETDEC_H
#define RETDEC_RETDEC_H

#include <iostream>
#include <iomanip>
#include <list>
#include <map>
#include <set>
#include <sstream>

#include <retdec/config/config.h>
#include <retdec/utils/filesystem_path.h>
#include <retdec/utils/time.h>

#include "function.h"
#include "ui.h"
#include "utils.h"

/**
 * Plugin's global data.
 */
class RetDec : public plugmod_t, public event_listener_t
{
	// Inherited.
	//
	public:
		RetDec();
		virtual ~RetDec();

		virtual bool idaapi run(size_t) override;
		virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

	// Plugin information.
	//
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

	// Decompilation.
	//
	public:
		static bool fullDecompilation();
		static Function* selectiveDecompilation(ea_t ea, bool redecompile);

		Function* selectiveDecompilationAndDisplay(ea_t ea, bool redecompile);
		void displayFunction(Function* f, ea_t ea);

		void modifyFunctions(
				Token::Kind k,
				const std::string& oldVal,
				const std::string& newVal
		);
		void modifyFunction(
				func_t* f,
				Token::Kind k,
				const std::string& oldVal,
				const std::string& newVal
		);

		ea_t getFunctionEa(const std::string& name);
		func_t* getIdaFunction(const std::string& name);
		ea_t getGlobalVarEa(const std::string& name);

		/// Currently displayed function.
		Function* fnc = nullptr;

		/// All the decompiled functions.
		static std::map<func_t*, Function> fnc2fnc;

		/// Decompilation config.
		static retdec::config::Config config;

	// UI.
	//
	public:
		TWidget* custViewer = nullptr;
		TWidget* codeViewer = nullptr;

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