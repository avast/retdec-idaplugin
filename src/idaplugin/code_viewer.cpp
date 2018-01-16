/**
 * @file idaplugin/code_viewer.cpp
 * @brief Module contains classes/methods dealing with decompiled code visualization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>

#include "code_viewer.h"
#include "config_generator.h"
#include "idaplugin.h"

namespace idaplugin {

extern RdGlobalInfo decompInfo;

ea_t globalAddress = 0;

//
//======================================================================
//

/**
 * @brief Get tagged line on current position.
 * @param v     Control.
 * @param mouse Current for mouse pointer?
 * @param[out] line Current line.
 * @param x     This is horizontal position in line string *WITHOUT* tags.
 * @param y     This is vertical position (line number) in viewer.
 * @param rx    This is horizontal position in line string *WITH* tags.
 * @return False if OK, true otherwise.
 */
static bool get_current_line_with_tags(TCustomControl *v, bool mouse, std::string &line, int &x, int &y, unsigned &rx)
{
	if ( get_custom_viewer_place(v, mouse, &x, &y) == nullptr )
	{
		return true;
	}

	line = get_custom_viewer_curline(v, mouse);

	rx = x;
	for (unsigned i = 0; i <= rx && i<line.size(); ++i)
	{
		unsigned char c = line[i];
		if (c == COLOR_ON || c == COLOR_OFF)
		{
			rx += 2; // {ON,OFF} + COLOR = 1 + 1 = 2
			++i;
		}
		if (c == COLOR_ESC || c == COLOR_INV)
		{
			rx += 1;
		}
	}

	return false;
}

/**
 * @brief Get line without tags on current position.
 * @param v     Control.
 * @param mouse Current for mouse pointer?
 * @param[out] line Current line.
 * @param x     This is horizontal position in line string *WITHOUT* tags.
 * @param y     This is vertical position (line number) in viewer.
 * @return False if OK, true otherwise.
 */
bool get_current_line_without_tags(TCustomControl *v, bool mouse, std::string &line, int &x, int &y)
{
	unsigned rx_unused;
	if (get_current_line_with_tags(v, mouse, line, x, y, rx_unused))
	{
		return true;
	}

	char buf[MAXSTR];
	tag_remove(line.c_str(), buf, sizeof(buf));
	if ( x >= static_cast<int>(strlen(buf)) )
	{
		return true;
	}

	line = buf;
	return false;
}

/**
 * @brief Get current word
 * @param v Control
 * @param mouse bool mouse (current for mouse pointer?)
 * @param[out] word result
 * @param[out] color resulted word color
 * @return False if OK, true otherwise.
 */
static bool get_current_word(TCustomControl *v, bool mouse, std::string &word, int& color)
{
	// Use SDK function to get highlighted ID.
	//
	char buf[MAXSTR];
	if (!get_highlighted_identifier(buf, sizeof(buf), 0))
	{
		return true;
	}

	int x, y;
	unsigned rx;
	std::string taggedLine;
	if (get_current_line_with_tags(v, mouse, taggedLine, x, y, rx))
	{
		return true;
	}

	int prevColor = -1;
	int nextColor = -1;

	auto onColor = taggedLine.find_last_of(COLOR_ON, rx);
	if (onColor != std::string::npos && onColor > 0 && taggedLine[onColor-1] == COLOR_ON)
		prevColor = taggedLine[onColor];
	else if (onColor != std::string::npos && (onColor+1) < taggedLine.length())
		prevColor = taggedLine[onColor+1];

	auto offColor = taggedLine.find_first_of(COLOR_OFF, rx);
	if (offColor != std::string::npos && (offColor+1) < taggedLine.length())
		nextColor = taggedLine[offColor+1];

	if (prevColor == -1 || prevColor != nextColor)
	{
		return false;
	}

	word = buf;
	color = nextColor;
	return false;
}

bool isWordGlobal(const std::string& word, int color)
{
	return color == COLOR_DEFAULT && decompInfo.configDB.globals.getObjectByNameOrRealName(word) != nullptr;
}

const retdec::config::Object* getWordGlobal(const std::string& word, int color)
{
	return color == COLOR_DEFAULT ? decompInfo.configDB.globals.getObjectByNameOrRealName(word) : nullptr;
}

bool isWordFunction(const std::string& word, int color)
{
	return color == COLOR_DEFAULT && decompInfo.configDB.functions.hasFunction(word);
}

bool isWordIdentifier(const std::string& word, int color)
{
	return color == COLOR_DREF;
}

const retdec::config::Function* getWordFunction(const std::string& word, int color)
{
	return color == COLOR_DEFAULT ? decompInfo.configDB.functions.getFunctionByName(word) : nullptr;
}

func_t* getIdaFunction(const std::string& word, int color)
{
	if (!isWordFunction(word, color))
		return nullptr;

	auto* cfgFnc = decompInfo.configDB.functions.getFunctionByName( word );
	if (cfgFnc == nullptr)
		return nullptr;

	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t *fnc = getn_func(i);
		if (fnc->startEA == cfgFnc->getStart())
		{
			return fnc;
		}
	}

	return nullptr;
}

bool isCurrentFunction(func_t* fnc)
{
	return decompInfo.navigationActual != decompInfo.navigationList.end()
			&& fnc == *decompInfo.navigationActual;
}

func_t* getCurrentFunction()
{
	return decompInfo.navigationActual != decompInfo.navigationList.end() ?
			*decompInfo.navigationActual :
			nullptr;
}

bool isWordCurrentParameter(const std::string& word, int color)
{
	if (!isWordIdentifier(word, color))
	{
		return false;
	}

	auto* idaCurrentFnc = getCurrentFunction();
	if (idaCurrentFnc == nullptr)
	{
		return false;
	}
	char cFncName[MAXSTR];
	get_func_name(idaCurrentFnc->startEA, cFncName, sizeof(cFncName));

	auto* confCurrentFnc = decompInfo.configDB.functions.getFunctionByName(cFncName);
	if (confCurrentFnc == nullptr)
	{
		return false;
	}

	for (auto& p : confCurrentFnc->parameters)
	{
		auto realName = p.getRealName();
		if ((!realName.empty() && realName == word) || p.getName() == word)
		{
			return true;
		}
	}

	return false;
}

//
//======================================================================
//

/**
 * Decompile or just show function.
 * @param cv        Current custom control.
 * @param calledFnc Called function name.
 * @param force     If function to decompile/show is the same as current function,
 *                  decompile/show it again only if this is set to @c true.
 * @param forceDec  Force new decompilation.
 */
void decompileFunction(TCustomControl *cv, const std::string &calledFnc, bool force = false, bool forceDec = false)
{
	auto* globVar = decompInfo.configDB.globals.getObjectByNameOrRealName(calledFnc);
	if (globVar && globVar->getStorage().isMemory())
	{
		INFO_MSG("Global variable -> jump to ASM.\n");
		jumpto( globVar->getStorage().getAddress() );
		return;
	}

	auto* cfgFnc = decompInfo.configDB.functions.getFunctionByName( calledFnc );

	if (!cfgFnc)
	{
		INFO_MSG("Unknown function to decompile \"%s\" -> do nothing.\n", calledFnc.c_str());
		return;
	}

	if (cfgFnc->isUserDefined())
	{
		for (unsigned i = 0; i < get_func_qty(); ++i)
		{
			func_t *fnc = getn_func(i);

			if (fnc->startEA != cfgFnc->getStart())
			{
				continue;
			}
			if (!force && isCurrentFunction(fnc))
			{
				INFO_MSG("The current function is not decompiled/shown again.\n");
				return;
			}

			// Decompile found function.
			//
			runSelectiveDecompilation(fnc, forceDec);
			return;
		}
	}

	// Such function exists in config file, but not in IDA functions.
	// This is import/export or something similar -> jump to IDA disassembler view.
	//
	INFO_MSG("Not a user-defined function -> jump to ASM.\n");
	jumpto( cfgFnc->getStart() );
}

//
//======================================================================
//

bool idaapi moveToPrevious(void *)
{
	DBG_MSG("\t ESC : [ ");
	for (auto& fnc : decompInfo.navigationList)
	{
		DBG_MSG("%a ", fnc->startEA);
	}
	DBG_MSG("] (#%d) : from %a => BACK\n", decompInfo.navigationList.size(), (*decompInfo.navigationActual)->startEA);

	if (decompInfo.navigationList.size() <= 1)
	{
		return false;
	}

	if (decompInfo.navigationActual != decompInfo.navigationList.begin())
	{
		decompInfo.navigationActual--;

		DBG_MSG("\t\t=> %a\n", (*decompInfo.navigationActual)->startEA );

		auto fit = decompInfo.fnc2code.find( *decompInfo.navigationActual );
		if (fit == decompInfo.fnc2code.end())
		{
			return false;
		}

		decompInfo.decompiledFunction = fit->first;
		qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));
	}
	else
	{
		DBG_MSG("\t\t=> FIRST : cannot move to the previous\n");
	}

	return false;
}

bool idaapi moveToNext(void*)
{
	DBG_MSG("\t CTRL + F : [ ");
	for (auto& fnc : decompInfo.navigationList)
	{
		DBG_MSG("%a ", fnc->startEA);
	}
	DBG_MSG("] (#%d) : from %a => FORWARD\n", decompInfo.navigationList.size(), (*decompInfo.navigationActual)->startEA);

	if (decompInfo.navigationList.size() <= 1)
	{
		return false;
	}

	auto last = decompInfo.navigationList.end();
	last--;
	if (decompInfo.navigationActual != last)
	{
		decompInfo.navigationActual++;

		DBG_MSG("\t\t=> %a\n", (*decompInfo.navigationActual)->startEA );

		auto fit = decompInfo.fnc2code.find( *decompInfo.navigationActual );
		if (fit != decompInfo.fnc2code.end())
		{
			decompInfo.decompiledFunction = fit->first;
			qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));

			return false;
		}
	}
	else
	{
		DBG_MSG("\t\t=> LAST : cannot move to the next\n");
	}

	return false;
}

//
//======================================================================
//

bool idaapi insertCurrentFunctionComment(void*)
{
	auto* fnc = getCurrentFunction();
	if (fnc == nullptr)
	{
		return false;
	}
	char cFncName[MAXSTR];
	get_func_name(fnc->startEA, cFncName, sizeof(cFncName));
	std::string word = cFncName;

	auto* fncCmt = get_func_cmt(fnc, false);
	char buff[MAXSTR];
	if (asktext(
			sizeof(buff),
			buff,
			fncCmt,
			"Please enter function comment (max %d characters)", (sizeof(buff)-1)))
	{
		set_func_cmt(fnc, buff, false);
		decompInfo.decompiledFunction = fnc;
		qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));
	}

	qfree(static_cast<void*>(fncCmt));
	return false;
}

//
//======================================================================
//

bool idaapi changeFunctionGlobalName(void *ud)
{
	TCustomControl *cv = static_cast<TCustomControl*>(ud);

	std::string word;
	int color = -1;
	if (get_current_word(cv, false, word, color))
	{
		return false;
	}

	std::string askString;
	ea_t address;
	const retdec::config::Function* fnc = nullptr;
	const retdec::config::Object* gv = nullptr;
	if ((fnc = getWordFunction(word, color)))
	{
		askString = "Please enter function name";
		address = fnc->getStart();
	}
	else if ((gv = getWordGlobal(word, color)))
	{
		askString = "Please enter global variable name";
		address = gv->getStorage().getAddress();
	}
	else
	{
		return false;
	}

	char* newName = askstr(HIST_IDENT, word.c_str(), askString.c_str());
	if (newName == nullptr)
	{
		return false;
	}
	std::string newTmp = newName;
	if (newTmp == word)
	{
		return false;
	}
	auto fit = decompInfo.fnc2code.find( *decompInfo.navigationActual );
	if (fit == decompInfo.fnc2code.end())
	{
		return false;
	}

	std::regex e( std::string(SCOLOR_ON) + "." + newName + SCOLOR_OFF + "." );
	if (decompInfo.configDB.globals.getObjectByNameOrRealName(newName) != nullptr
			|| decompInfo.configDB.functions.hasFunction(newName)
			|| std::regex_search(fit->second.code, e))
	{
		warning("Name \"%s\" is not unique\n", newName);
		return false;
	}

	if (set_name(address, newName) == false)
	{
		return false;
	}

	std::string oldName = std::string(SCOLOR_ON) + SCOLOR_DEFAULT + word + SCOLOR_OFF + SCOLOR_DEFAULT;
	std::string replace = std::string(SCOLOR_ON) + SCOLOR_DEFAULT + newName + SCOLOR_OFF + SCOLOR_DEFAULT;
	for (auto& fncItem : decompInfo.fnc2code)
	{
		auto& code = fncItem.second.code;
		std::string::size_type n = 0;
		while ( ( n = code.find( oldName, n ) ) != std::string::npos )
		{
			code.replace( n, oldName.size(), replace );
			n += replace.size();
		}
	}

	// TODO: just setting a new name to function/global would be faster.
	//
	ConfigGenerator jg(decompInfo);
	decompInfo.dbFile = jg.generate();

	decompInfo.decompiledFunction = fit->first;
	qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));

	return false;
}

//
//======================================================================
//

bool idaapi openXrefsWindow(void *ud)
{
	func_t* fnc = static_cast<func_t*>(ud);
	open_xrefs_window(fnc->startEA);
	return false;
}

bool idaapi openCallsWindow(void *ud)
{
	func_t* fnc = static_cast<func_t*>(ud);
	open_calls_window(fnc->startEA);
	return false;
}

//
//======================================================================
//

bool idaapi changeTypeDeclaration(void *ud)
{
	TCustomControl *cv = static_cast<TCustomControl*>(ud);

	std::string word;
	int color = -1;
	if (get_current_word(cv, false, word, color))
	{
		return false;
	}
	auto* idaFnc= getIdaFunction(word, color);
	auto* cFnc = getWordFunction(word, color);
	auto* cGv = getWordGlobal(word, color);

	ea_t addr = 0;
	if (cFnc && idaFnc && isCurrentFunction(idaFnc) && cFnc->getName() != "main")
	{
		addr = cFnc->getStart();
	}
	else if (cGv && cGv->getStorage().isMemory())
	{
		WARNING_MSG("Setting type for global variable is not supported at the moment.\n");
		return false;
	}
	else
	{
		return false;
	}

	char buf[MAXSTR];
	int flags = PRTYPE_1LINE | PRTYPE_SEMI;
	if (print_type2(addr, buf, sizeof(buf), flags))
	{
		std::string askString = "Please enter type declaration:";
		char* newDeclr = askstr(HIST_TYPE, buf, askString.c_str());
		if (newDeclr == nullptr)
		{
			return false;
		}

		if (apply_cdecl2(idati, addr, newDeclr))
		{
			decompileFunction(cv, word, true, true);
		}
		else
		{
			WARNING_MSG("Cannot change declaration to: %s\n", newDeclr);
		}
	}
	else
	{
		WARNING_MSG("Cannot change declaration for: %s\n", cFnc->getName().c_str());
	}

	return false;
}

//
//======================================================================
//

/**
 * Jump to specified address in IDA's disassembly.
 * @param ud Address to jump to.
 */
bool idaapi jumpToASM(void *ud)
{
	ea_t* addr = static_cast<ea_t*>(ud);
	jumpto( *addr );
	return false;
}

//
//======================================================================
//

/**
 * Callback for keybord action in custom viewer.
 */
bool idaapi ct_keyboard(TCustomControl *cv, int key, int shift, void *ud)
{
	// ESC : move to the previous saved position.
	//
	if (key == 27 && shift == 0)
	{
		return moveToPrevious(static_cast<void*>(cv));
	}
	// CTRL + F : move to the next saved position.
	// 70 = 'F'
	//
	else if (key == 70 && shift == 4)
	{
		return moveToNext(static_cast<void*>(cv));
	}

	// Get word, function, global, ...
	//
	std::string word;
	int color = -1;
	if (get_current_word(cv, false, word, color))
	{
		return false;
	}
	auto* idaFnc = getIdaFunction(word, color);
	const retdec::config::Function* cFnc = getWordFunction(word, color);
	const retdec::config::Object* cGv = getWordGlobal(word, color);

	// 45 = INSERT
	// 186 = ';'
	//
	if ((key == 45 && shift == 0) || (key == 186 && shift == 0))
	{
		return insertCurrentFunctionComment(static_cast<void*>(cv));
	}
	// 78 = N
	//
	else if (key == 78 && shift == 0)
	{
		if (decompInfo.navigationActual == decompInfo.navigationList.end())
		{
			return false;
		}

		if (cFnc || cGv)
		{
			return changeFunctionGlobalName(static_cast<void*>(cv));
		}
		else
		{
			if (isWordCurrentParameter(word, color))
			{
				// TODO
			}

			return false;
		}
	}
	// 88 = X
	//
	else if (key == 88 && shift == 0)
	{
		if (idaFnc == nullptr)
		{
			return false;
		}
		openXrefsWindow(idaFnc);
	}
	// 67 = C
	//
	else if (key == 67 && shift == 0)
	{
		if (idaFnc == nullptr)
		{
			return false;
		}
		openCallsWindow(idaFnc);
	}
	// 89 = Y
	//
	else if (key == 89 && shift == 0)
	{
		return changeTypeDeclaration(static_cast<void*>(cv));
	}
	// 65 = A
	//
	else if (key == 65 && shift == 0)
	{
		ea_t addr = 0;
		if (idaFnc)
		{
			addr = idaFnc->startEA;
		}
		else if (cGv)
		{
			addr = cGv->getStorage().getAddress();
		}
		else
		{
			return false;
		}
		jumpToASM(&addr);
	}
	// Anything else : ignored.
	//
	else
	{
		//msg("\tkey(%d) + shift(%d)\n", key, shift);
	}

	return false;
}

bool dummyAction(void *ud)
{
	return false;
}

/**
 * Callback for right click in custom viewer.
 */
void idaapi ct_popup(TCustomControl *cv, void *ud)
{
	std::string word;
	int color = -1;
	if (get_current_word(cv, false, word, color))
	{
		return;
	}

	auto* idaFnc = getIdaFunction(word, color);
	const retdec::config::Function* cFnc = getWordFunction(word, color);
	const retdec::config::Object* cGv = getWordGlobal(word, color);

	set_custom_viewer_popup_menu(cv, nullptr);

	// Function context.
	//
	if (idaFnc && cFnc)
	{
		add_custom_viewer_popup_item(cv, "Jump to ASM", "A", jumpToASM, &idaFnc->startEA);
		add_custom_viewer_popup_item(cv, "Rename function", "N", changeFunctionGlobalName, cv);
		if (isCurrentFunction(idaFnc))
		{
			add_custom_viewer_popup_item(cv, "Change type declaration", "Y", changeTypeDeclaration, cv);
		}
		add_custom_viewer_popup_item(cv, "Open xrefs window", "X", openXrefsWindow, idaFnc);
		add_custom_viewer_popup_item(cv, "Open calls window", "C", openCallsWindow, idaFnc);
	}
	// Global var context.
	//
	else if (cGv)
	{
		globalAddress = cGv->getStorage().getAddress();
		add_custom_viewer_popup_item(cv, "Jump to ASM", "A", jumpToASM, &globalAddress);
		add_custom_viewer_popup_item(cv, "Rename global variable", "N", changeFunctionGlobalName, cv);
	}

	// Common for all contexts.
	//
	add_custom_viewer_popup_item(cv, "-", "", nullptr, nullptr);
	add_custom_viewer_popup_item(cv, "Edit func comment", ";", insertCurrentFunctionComment, cv);
	add_custom_viewer_popup_item(cv, "Move backward", "ESC", moveToPrevious, cv);
	add_custom_viewer_popup_item(cv, "Move forward", "CTRL+F", moveToNext, cv);
}

/**
 * Callback for double click in custom viewer.
 */
bool idaapi ct_double(TCustomControl *cv, int shift, void *ud)
{
	std::string word;
	int color = -1;

	if (get_current_word(cv, false, word, color))
	{
		return false;
	}

	if (color == COLOR_DEFAULT || color == COLOR_IMPNAME)
	{
		decompileFunction(cv, word);
		return false;
	}

	return false;
}

/**
 * Callback for current position change in custom viewer.
 */
void idaapi ct_curpos(TCustomControl *v, void *)
{

}

/**
 * Callback for closing of custom viewer.
 */
void idaapi ct_close(TCustomControl *cv, void *ud)
{

}

//
//======================================================================
//

/**
 * Use @c ShowOutput structure to show decompiled code from thread.
 */
int idaapi showDecompiledCode(void *ud)
{
	RdGlobalInfo *di = static_cast<RdGlobalInfo*>(ud);
	ShowOutput show(di);
	execute_sync(show, MFF_FAST);
	return 0;
}

/**
 * Use @c ShowVersionCheckForm structure to show new version info form.
 */
int idaapi showVersionCheckForm(RdGlobalInfo *di)
{
	ShowVersionCheckForm show(di);
	return execute_sync(show, MFF_FAST);
}

} // namespace idaplugin
