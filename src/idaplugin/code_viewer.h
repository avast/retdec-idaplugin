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
bool idaapi ct_keyboard(TCustomControl *, int key, int shift, void *ud);
void idaapi ct_popup(TCustomControl *v, void *ud);
bool idaapi ct_double(TCustomControl *cv, int shift, void *ud);
void idaapi ct_curpos(TCustomControl *v, void *);
void idaapi ct_close(TCustomControl *cv, void *ud);
/// @}

/// @name Functions working with GUI from threads.
/// @{
int idaapi showDecompiledCode(void *ud);
/// @}

bool addCommentToFunctionCode(func_t* fnc);

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
		bool exists = false;
		if ((di->form = find_tform(di->formName.c_str())))
		{
			exists = true;
		}
		else
		{
			// Get new or existing form.
			// If form existed, handle will be nullptr.
			//
			HWND hwnd = nullptr;
			di->form = create_tform(di->formName.c_str(), &hwnd);
		}

		if (di->viewer && exists)
		{
			destroy_custom_viewer(di->viewer);
			di->viewer = nullptr;
		}

		addCommentToFunctionCode();

		func_t* fnc = di->decompiledFunction;
		auto& contents = di->fnc2code[fnc].idaCode;
		auto& code = di->fnc2code[fnc].code;
		std::istringstream f( code );
		std::string line;
		contents.clear();
		while (std::getline(f, line))
		{
			contents.push_back( simpleline_t(line.c_str()) );
		}

		simpleline_place_t minPlace;
		simpleline_place_t curPlace = minPlace;
		simpleline_place_t maxPlace(contents.size()-1);

		di->viewer = create_custom_viewer(
				"", // title
				// TODO: reinterpret_cast is dangerous, but this is how
				// it is used in IDA SDK examples (other plugins).
				// TWinControl and TForm classes are not defined in IDA SDK headers
				// -> I have no idea how are they realated.
				reinterpret_cast<TWinControl*>(di->form),
				&minPlace,
				&maxPlace,
				&curPlace,
				0, // y?
				&contents // user data
		);

		set_custom_viewer_handlers(
				di->viewer,
				ct_keyboard,
				ct_popup,
				ct_double,
				ct_curpos,
				ct_close,
				di
		);

		if (!exists)
		{
			open_tform(                    ///< this will show form in IDA.
					di->form,
					FORM_TAB |             ///< TAB -> function window :-(, attached to form - not floating :-D
					FORM_MENU |
					FORM_RESTORE |
					FORM_QWIDGET |
					FORM_PERSIST |         ///< ???
					FORM_NOT_CLOSED_BY_ESC ///< we want to catch ESC in ct_keyboard() and use it for navigation.

			);
		}
		else
		{
			switchto_tform(di->form, true);
		}

		return 0;
	}

	void idaapi addCommentToFunctionCode()
	{
		func_t* fnc = di->decompiledFunction;
		auto fit = di->fnc2code.find(fnc);
		if (fit == di->fnc2code.end())
		{
			return;
		}
		auto* fncCmt = get_func_cmt(fnc, false);
		if (fncCmt == nullptr)
		{
			return;
		}

		auto& code = fit->second.code;
		std::istringstream f(code);
		std::string line;
		std::list<std::string> lines;
		while (std::getline(f, line))
		{
			lines.push_back(line.c_str());
		}
		bool active = false;
		for (auto it = lines.begin(); it!= lines.end(); ++it)
		{
			std::string l = *it;

			std::regex e1( std::string(SCOLOR_ON) + SCOLOR_AUTOCMT + "// -* Functions -*" + SCOLOR_OFF + SCOLOR_AUTOCMT );
			if (std::regex_match(l, e1))
			{
				active = true;
				continue;
			}

			if (!active)
			{
				continue;
			}

			std::regex e2( std::string(SCOLOR_ON) + SCOLOR_AUTOCMT + "// Comment:.*" + SCOLOR_OFF + SCOLOR_AUTOCMT );
			if (std::regex_match(l, e2))
			{
				std::regex e3( std::string(SCOLOR_ON) + SCOLOR_AUTOCMT + "// .*" + SCOLOR_OFF + SCOLOR_AUTOCMT );
				while (std::regex_match(l, e3))
				{
					it = lines.erase(it);
					if (it == lines.end())
						break;
					l = *it;
				}
			}
			if (it == lines.end())
				break;

			char cFncName[MAXSTR];
			get_func_name(fnc->startEA, cFncName, sizeof(cFncName));
			std::string tmpFncName = cFncName;
			std::string tmpFncNameTrim = retdec::utils::removeLeadingCharacter(tmpFncName, '_');

			std::regex e4( ".*" + std::string(SCOLOR_ON) + SCOLOR_DEFAULT + tmpFncName + SCOLOR_OFF + SCOLOR_DEFAULT + ".*" );
			std::regex e5( ".*" + std::string(SCOLOR_ON) + SCOLOR_DEFAULT + tmpFncNameTrim + SCOLOR_OFF + SCOLOR_DEFAULT + ".*" );
			if (std::regex_match(l, e4) || std::regex_match(l, e5))
			{
				bool first = true;
				std::istringstream ff(fncCmt);
				std::string cLine;
				while (std::getline(ff, cLine))
				{
					if (first)
					{
						std::string prolog = std::string(SCOLOR_ON) + SCOLOR_AUTOCMT + "// Comment:" + SCOLOR_OFF + SCOLOR_AUTOCMT;
						lines.insert(it, prolog);
						first = false;
					}

					cLine = std::string(SCOLOR_ON) + SCOLOR_AUTOCMT + "//     " + cLine + SCOLOR_OFF + SCOLOR_AUTOCMT;
					lines.insert(it, cLine);
				}

				break;
			}
		}

		fit->second.code.clear();
		for (auto& l : lines)
			fit->second.code += l + "\n";

		qfree(static_cast<void*>(fncCmt));
	}
};

} // namespace idaplugin

#endif
