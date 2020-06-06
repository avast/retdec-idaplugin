/**
 * @file idaplugin/code_viewer.h
 * @brief Module contains classes/methods dealing with decompiled code visualization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_CODE_VIEWER_H
#define IDAPLUGIN_CODE_VIEWER_H

#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

#include "retdec/utils/string.h"
#include "defs.h"

namespace idaplugin {

/// @name Callbacks reacting on custom viewer.
/// @{
bool idaapi ct_keyboard(TWidget* cv, int key, int shift, void* ud);
bool idaapi ct_double(TWidget* cv, int shift, void* ud);
void idaapi ct_close(TWidget* cv, void* ud);
/// @}

void registerPermanentActions();
ssize_t idaapi ui_callback(void* ud, int notification_code, va_list va);

/// @name Functions working with GUI from threads.
/// @{
int idaapi showDecompiledCode(void *ud);
/// @}

/**
 * All the handlers for our custom view.
 */
static const custom_viewer_handlers_t handlers(
		ct_keyboard, // keyboard
		nullptr,     // popup
		nullptr,     // mouse_moved
		nullptr,     // click
		ct_double,   // dblclick
		nullptr,     // current position change
		ct_close,     // close
		nullptr,     // help
		nullptr,     // adjust_place
		nullptr,
		nullptr,
		nullptr
);

/**
 * This is a structure defining execute() method which will be executed
 * by master thread throught 'execute_sync()' call.
 * Its purpose is to display decompiled code in custom viewer.
 *
 * It sets plugin's tform and viewer.
 *
 * It uses current 'decompiledFunction' to get associated code from 'fnc2code'.
 *
 * @note For some unknown reason, it works only from threads,
 *       if it is called from main thread, if crashes IDA.
 */
struct ShowOutput : public exec_request_t
{
	RdGlobalInfo *di;

	ShowOutput(RdGlobalInfo *i) : di(i) {}
	virtual ~ShowOutput() override {}

	virtual int idaapi execute() override
	{
		if (di->codeViewer)
		{
			close_widget(di->codeViewer, 0);
			di->custViewer = nullptr;
			di->codeViewer = nullptr;
		}

		func_t* fnc = di->decompiledFunction;
		auto& contents = di->fnc2code[fnc].idaCode;
		auto& code = di->fnc2code[fnc].code;
		std::istringstream f(code);
		std::string line;
		contents.clear();
		while (std::getline(f, line))
		{
			contents.push_back( simpleline_t(line.c_str()) );
		}

		simpleline_place_t minPlace;
		simpleline_place_t curPlace = minPlace;
		simpleline_place_t maxPlace(contents.size()-1);

		di->custViewer = create_custom_viewer(
				di->viewerName.c_str(), // name of viewer
				&minPlace,              // first location of the viewer
				&maxPlace,              // last location of the viewer
				&curPlace,              // set current location
				nullptr,                // renderer information (can be NULL)
				&contents,              // contents of viewer
				&handlers,              // handlers for the viewer (can be NULL)
				di,                     // handlers' user data
				nullptr                 // widget to hold viewer
		);

		di->codeViewer = create_code_viewer(di->custViewer);

		set_code_viewer_is_source(di->codeViewer);

		// This is useful for two reasons:
		// 1. Sync disasm IDA view to the function which is about to be
		//    displayed.
		// 2. Make sure there is a disasm IDA view next to which the decomp
		//    view can be displayed.
		//    - If focus was changed, it is restored to disasm IDA view.
		//    - If disasm IDA view was closed, it is opened again.
		jumpto(fnc->start_ea, -1, UIJMP_ACTIVATE | UIJMP_IDAVIEW);

		display_widget(
				di->codeViewer,
#if IDA_SDK_VERSION < 730
				WOPN_TAB |
#else
				WOPN_DP_TAB |
#endif

#if !defined(IDA_SDK_VERSION) || IDA_SDK_VERSION < 720
				WOPN_MENU |
#endif
				/// we want to catch ESC and use it for navigation
				WOPN_NOT_CLOSED_BY_ESC
		);

		return 0;
	}
};

} // namespace idaplugin

#endif
