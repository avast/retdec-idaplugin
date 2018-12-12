/**
 * @file idaplugin/code_viewer.cpp
 * @brief Module contains classes/methods dealing with decompiled code
 *        visualization.
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
//==============================================================================
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
static bool get_current_line_with_tags(
		TWidget* v,
		bool mouse,
		std::string& line,
		int& x,
		int& y,
		unsigned& rx)
{
	if (get_custom_viewer_place(v, mouse, &x, &y) == nullptr)
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
bool get_current_line_without_tags(
		TWidget* v,
		bool mouse,
		std::string &line,
		int& x,
		int& y)
{
	unsigned rx_unused;
	if (get_current_line_with_tags(v, mouse, line, x, y, rx_unused))
	{
		return true;
	}

	qstring buf;
	tag_remove(&buf, line.c_str());
	if (x >= static_cast<int>(buf.length()))
	{
		return true;
	}

	line = buf.c_str();
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
static bool get_current_word(
		TWidget* v,
		bool mouse,
		std::string& word,
		int& color)
{
	// Use SDK function to get highlighted ID.
	//
	qstring buf;
	if (!get_highlight(&buf, v, nullptr))
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
	if (onColor != std::string::npos && onColor > 0
			&& taggedLine[onColor-1] == COLOR_ON)
	{
		prevColor = taggedLine[onColor];
	}
	else if (onColor != std::string::npos && (onColor+1) < taggedLine.length())
	{
		prevColor = taggedLine[onColor+1];
	}

	auto offColor = taggedLine.find_first_of(COLOR_OFF, rx);
	if (offColor != std::string::npos && (offColor+1) < taggedLine.length())
	{
		nextColor = taggedLine[offColor+1];
	}

	if (prevColor == -1 || prevColor != nextColor)
	{
		return false;
	}

	word = buf.c_str();
	color = nextColor;
	return false;
}

bool isWordGlobal(const std::string& word, int color)
{
	return color == COLOR_DEFAULT
			&& decompInfo.configDB.globals.getObjectByNameOrRealName(word)
					!= nullptr;
}

const retdec::config::Object* getWordGlobal(const std::string& word, int color)
{
	return !word.empty() && color == COLOR_DEFAULT
			? decompInfo.configDB.globals.getObjectByNameOrRealName(word)
			: nullptr;
}

bool isWordFunction(const std::string& word, int color)
{
	return color == COLOR_DEFAULT
			&& decompInfo.configDB.functions.hasFunction(word);
}

bool isWordIdentifier(const std::string& word, int color)
{
	return color == COLOR_DREF;
}

const retdec::config::Function* getWordFunction(
		const std::string& word,
		int color)
{
	return !word.empty() && color == COLOR_DEFAULT
			? decompInfo.configDB.functions.getFunctionByName(word)
			: nullptr;
}

func_t* getIdaFunction(const std::string& word, int color)
{
	if (word.empty())
	{
		return nullptr;
	}
	if (!isWordFunction(word, color))
	{
		return nullptr;
	}

	auto* cfgFnc = decompInfo.configDB.functions.getFunctionByName(word);
	if (cfgFnc == nullptr)
	{
		return nullptr;
	}

	return get_func(cfgFnc->getStart());
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
	qstring name;
	get_func_name(&name, idaCurrentFnc->start_ea);

	auto* ccFnc = decompInfo.configDB.functions.getFunctionByName(name.c_str());
	if (ccFnc == nullptr)
	{
		return false;
	}

	for (auto& p : ccFnc->parameters)
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
//==============================================================================
//

/**
 * Decompile or just show function.
 * @param cv        Current custom control.
 * @param calledFnc Called function name.
 * @param force     If function to decompile/show is the same as current function,
 *                  decompile/show it again only if this is set to @c true.
 * @param forceDec  Force new decompilation.
 */
void decompileFunction(
		TWidget* cv,
		const std::string& calledFnc,
		bool force = false,
		bool forceDec = false)
{
	auto* globVar = decompInfo.configDB.globals.getObjectByNameOrRealName(
			calledFnc);

	if (globVar && globVar->getStorage().isMemory())
	{
		INFO_MSG("Global variable -> jump to ASM.\n");
		jumpto( globVar->getStorage().getAddress() );
		return;
	}

	auto* cfgFnc = decompInfo.configDB.functions.getFunctionByName(calledFnc);

	if (!cfgFnc)
	{
		INFO_MSG("Unknown function to decompile \"%s\" -> do nothing.\n",
				calledFnc.c_str());
		return;
	}

	if (cfgFnc->isUserDefined())
	{
		for (unsigned i = 0; i < get_func_qty(); ++i)
		{
			func_t *fnc = getn_func(i);

			if (fnc->start_ea != cfgFnc->getStart())
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
	// This is import/export or something similar -> jump to IDA disasm view.
	//
	INFO_MSG("Not a user-defined function -> jump to ASM.\n");
	jumpto( cfgFnc->getStart() );
}

//
//==============================================================================
//

bool idaapi moveToPrevious()
{
	DBG_MSG("\t ESC : [ ");
	for (auto& fnc : decompInfo.navigationList)
	{
		DBG_MSG("%" RetDecUInt " ", fnc->start_ea);
	}
	DBG_MSG("] (#%zx) : from %" RetDecUInt " => BACK\n",
			decompInfo.navigationList.size(),
			(*decompInfo.navigationActual)->start_ea);

	if (decompInfo.navigationList.size() <= 1)
	{
		return false;
	}

	if (decompInfo.navigationActual != decompInfo.navigationList.begin())
	{
		decompInfo.navigationActual--;

		DBG_MSG("\t\t=> %" RetDecUInt "\n", (*decompInfo.navigationActual)->start_ea);

		auto fit = decompInfo.fnc2code.find(*decompInfo.navigationActual);
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

struct move_backward_ah_t : public action_handler_t
{
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		moveToPrevious();
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}
};

const char* move_backward_ah_t::actionName   = "retdec:ActionMoveBackward";
const char* move_backward_ah_t::actionLabel  = "Move backward";
const char* move_backward_ah_t::actionHotkey = "ESC";

static move_backward_ah_t move_backward_ah;
static const action_desc_t move_backward_ah_desc = ACTION_DESC_LITERAL(
		move_backward_ah_t::actionName,
		move_backward_ah_t::actionLabel,
		&move_backward_ah,
		nullptr,
		move_backward_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi moveToNext()
{
	DBG_MSG("\t CTRL + F : [ ");
	for (auto& fnc : decompInfo.navigationList)
	{
		DBG_MSG("%" RetDecUInt " ", fnc->start_ea);
	}
	DBG_MSG("] (#%zx) : from %" RetDecUInt " => FORWARD\n",
			decompInfo.navigationList.size(),
			(*decompInfo.navigationActual)->start_ea);

	if (decompInfo.navigationList.size() <= 1)
	{
		return false;
	}

	auto last = decompInfo.navigationList.end();
	last--;
	if (decompInfo.navigationActual != last)
	{
		decompInfo.navigationActual++;

		DBG_MSG("\t\t=> %" RetDecUInt "\n", (*decompInfo.navigationActual)->start_ea);

		auto fit = decompInfo.fnc2code.find(*decompInfo.navigationActual);
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

struct move_forward_ah_t : public action_handler_t
{
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		moveToNext();
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}
};

const char* move_forward_ah_t::actionName   = "retdec:ActionMoveForward";
const char* move_forward_ah_t::actionLabel  = "Move forward";
const char* move_forward_ah_t::actionHotkey = "Ctrl+F";

static move_forward_ah_t move_forward_ah;
static const action_desc_t move_forward_ah_desc = ACTION_DESC_LITERAL(
		move_forward_ah_t::actionName,
		move_forward_ah_t::actionLabel,
		&move_forward_ah,
		nullptr,
		move_forward_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi insertCurrentFunctionComment()
{
	auto* fnc = getCurrentFunction();
	if (fnc == nullptr)
	{
		return false;
	}

	qstring qCmt;
	get_func_cmt(&qCmt, fnc, false);

	qstring buff;
	if (ask_text(
			&buff,
			MAXSTR,
			qCmt.c_str(),
			"Please enter function comment (max %d characters)",
			MAXSTR))
	{
		set_func_cmt(fnc, buff.c_str(), false);
		decompInfo.decompiledFunction = fnc;
		qthread_create(showDecompiledCode, static_cast<void*>(&decompInfo));
	}

	return false;
}

struct change_fnc_comment_ah_t : public action_handler_t
{
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		insertCurrentFunctionComment();
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}
};

const char* change_fnc_comment_ah_t::actionName   = "retdec:ActionChangeFncComment";
const char* change_fnc_comment_ah_t::actionLabel  = "Edit func comment";
const char* change_fnc_comment_ah_t::actionHotkey = ";";

static change_fnc_comment_ah_t change_fnc_comment_ah;
static const action_desc_t change_fnc_comment_ah_desc = ACTION_DESC_LITERAL(
		change_fnc_comment_ah_t::actionName,
		change_fnc_comment_ah_t::actionLabel,
		&change_fnc_comment_ah,
		nullptr,
		change_fnc_comment_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi changeFunctionGlobalName(TWidget* cv)
{
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

	qstring qNewName = word.c_str();
	if (!ask_str(&qNewName, HIST_IDENT, "%s", askString.c_str())
			|| qNewName.empty())
	{
		return false;
	}
	std::string newName = qNewName.c_str();
	if (newName == word)
	{
		return false;
	}
	auto fit = decompInfo.fnc2code.find(*decompInfo.navigationActual);
	if (fit == decompInfo.fnc2code.end())
	{
		return false;
	}

	std::regex e(std::string(SCOLOR_ON)
			+ "."
			+ newName
			+ SCOLOR_OFF
			+ ".");

	if (decompInfo.configDB.globals.getObjectByNameOrRealName(newName) != nullptr
			|| decompInfo.configDB.functions.hasFunction(newName)
			|| std::regex_search(fit->second.code, e))
	{
		warning("Name \"%s\" is not unique\n", newName.c_str());
		return false;
	}

	if (set_name(address, newName.c_str()) == false)
	{
		return false;
	}

	std::string oldName = std::string(SCOLOR_ON)
			+ SCOLOR_DEFAULT
			+ word
			+ SCOLOR_OFF
			+ SCOLOR_DEFAULT;

	std::string replace = std::string(SCOLOR_ON)
			+ SCOLOR_DEFAULT
			+ newName
			+ SCOLOR_OFF
			+ SCOLOR_DEFAULT;

	for (auto& fncItem : decompInfo.fnc2code)
	{
		auto& code = fncItem.second.code;
		std::string::size_type n = 0;
		while (( n = code.find(oldName, n)) != std::string::npos)
		{
			code.replace(n, oldName.size(), replace);
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

struct change_fnc_global_name_ah_t : public action_handler_t
{
	TWidget* view = nullptr;
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		changeFunctionGlobalName(view);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}

	void setView(TWidget* v)
	{
		view = v;
	}
};

const char* change_fnc_global_name_ah_t::actionName  = "retdec:ActionChangeFncGlobName";
const char* change_fnc_global_name_ah_t::actionLabel = "Rename";
const char* change_fnc_global_name_ah_t::actionHotkey = "N";

static change_fnc_global_name_ah_t change_fnc_global_name_ah;
static const action_desc_t change_fnc_global_name_ah_desc = ACTION_DESC_LITERAL(
		change_fnc_global_name_ah_t::actionName,
		change_fnc_global_name_ah_t::actionLabel,
		&change_fnc_global_name_ah,
		nullptr,
		change_fnc_global_name_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi openXrefsWindow(func_t* fnc)
{
	open_xrefs_window(fnc->start_ea);
	return false;
}

struct open_xrefs_ah_t : public action_handler_t
{
	func_t* fnc = nullptr;
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		openXrefsWindow(fnc);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}

	void setFunction(func_t* f)
	{
		fnc = f;
	}
};

const char* open_xrefs_ah_t::actionName   = "retdec:ActionOpenXrefs";
const char* open_xrefs_ah_t::actionLabel  = "Open xrefs window";
const char* open_xrefs_ah_t::actionHotkey = "X";

static open_xrefs_ah_t open_xrefs_ah;
static const action_desc_t open_xrefs_ah_desc = ACTION_DESC_LITERAL(
		open_xrefs_ah_t::actionName,
		open_xrefs_ah_t::actionLabel,
		&open_xrefs_ah,
		nullptr,
		open_xrefs_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi openCallsWindow(func_t* fnc)
{
	open_calls_window(fnc->start_ea);
	return false;
}

struct open_calls_ah_t : public action_handler_t
{
	func_t* fnc = nullptr;
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		openCallsWindow(fnc);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}

	void setFunction(func_t* f)
	{
		fnc = f;
	}
};

const char* open_calls_ah_t::actionName   = "retdec:ActionOpenCalls";
const char* open_calls_ah_t::actionLabel  = "Open calls window";
const char* open_calls_ah_t::actionHotkey = "C";

static open_calls_ah_t open_calls_ah;
static const action_desc_t open_calls_ah_desc = ACTION_DESC_LITERAL(
		open_calls_ah_t::actionName,
		open_calls_ah_t::actionLabel,
		&open_calls_ah,
		nullptr,
		open_calls_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

bool idaapi changeTypeDeclaration(TWidget* cv)
{
	std::string word;
	int color = -1;
	if (get_current_word(cv, false, word, color))
	{
		return false;
	}
	auto* idaFnc = getIdaFunction(word, color);
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

	qstring buf;
	int flags = PRTYPE_1LINE | PRTYPE_SEMI;
	if (print_type(&buf, addr, flags))
	{
		std::string askString = "Please enter type declaration:";

		qstring qNewDeclr = buf;
		if (!ask_str(&qNewDeclr, HIST_IDENT, "%s", askString.c_str())
				|| qNewDeclr.empty())
		{
			return false;
		}

		if (apply_cdecl(nullptr, addr, qNewDeclr.c_str()))
		{
			decompileFunction(cv, word, true, true);
		}
		else
		{
			WARNING_MSG("Cannot change declaration to: %s\n", qNewDeclr.c_str());
		}
	}
	else
	{
		WARNING_MSG("Cannot change declaration for: %s\n", cFnc->getName().c_str());
	}

	return false;
}

struct change_fnc_type_ah_t : public action_handler_t
{
	TWidget* view = nullptr;
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		changeTypeDeclaration(view);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}

	void setView(TWidget* v)
	{
		view = v;
	}
};

const char* change_fnc_type_ah_t::actionName   = "retdec:ActionChangeFncType";
const char* change_fnc_type_ah_t::actionLabel  = "Change type declaration";
const char* change_fnc_type_ah_t::actionHotkey = "Y";

static change_fnc_type_ah_t change_fnc_type_ah;
static const action_desc_t change_fnc_type_ah_desc = ACTION_DESC_LITERAL(
		change_fnc_type_ah_t::actionName,
		change_fnc_type_ah_t::actionLabel,
		&change_fnc_type_ah,
		nullptr,
		change_fnc_type_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

/**
 * Jump to specified address in IDA's disassembly.
 * @param ud Address to jump to.
 */
bool idaapi jumpToASM(ea_t ea)
{
	jumpto(ea);
	return false;
}

struct jump_to_asm_ah_t : public action_handler_t
{
	ea_t addr;
	static const char* actionName;
	static const char* actionLabel;
	static const char* actionHotkey;

	virtual int idaapi activate(action_activation_ctx_t*)
	{
		jumpToASM(addr);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}

	void setAddress(ea_t a)
	{
		addr = a;
	}
};

const char* jump_to_asm_ah_t::actionName  = "retdec:ActionJumpToAsm";
const char* jump_to_asm_ah_t::actionLabel = "Jump to ASM";
const char* jump_to_asm_ah_t::actionHotkey = "A";

static jump_to_asm_ah_t jump_to_asm_ah;
static const action_desc_t jump_to_asm_ah_desc = ACTION_DESC_LITERAL(
		jump_to_asm_ah_t::actionName,
		jump_to_asm_ah_t::actionLabel,
		&jump_to_asm_ah,
		nullptr,
		jump_to_asm_ah_t::actionHotkey,
		-1);

//
//==============================================================================
//

/**
 * Callback for keybord action in custom viewer.
 */
bool idaapi ct_keyboard(TWidget* cv, int key, int shift, void* ud)
{
	// ESC : move to the previous saved position.
	//
	if (key == 27 && shift == 0)
	{
		return moveToPrevious();
	}
	// CTRL + F : move to the next saved position.
	// 70 = 'F'
	//
	else if (key == 70 && shift == 4)
	{
		return moveToNext();
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
		return insertCurrentFunctionComment();
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
			return changeFunctionGlobalName(cv);
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
		return changeTypeDeclaration(cv);
	}
	// 65 = A
	//
	else if (key == 65 && shift == 0)
	{
		ea_t addr = 0;
		if (idaFnc)
		{
			addr = idaFnc->start_ea;
		}
		else if (cGv)
		{
			addr = cGv->getStorage().getAddress();
		}
		else
		{
			return false;
		}
		jumpToASM(addr);
	}
	// Anything else : ignored.
	//
	else
	{
		//msg("\tkey(%d) + shift(%d)\n", key, shift);
	}

	return false;
}

//
//==============================================================================
//

ssize_t idaapi ui_callback(void* ud, int notification_code, va_list va)
{
	RdGlobalInfo* di = static_cast<RdGlobalInfo*>(ud);

	switch (notification_code)
	{
		// called when IDA is preparing a context menu for a view
		// Here dynamic context-depending user menu items can be added.
		case ui_populating_widget_popup:
		{
			TWidget* view = va_arg(va, TWidget*);
			if (view != di->custViewer && view != di->codeViewer)
			{
				return false;
			}

			std::string word;
			int color = -1;
			if (get_current_word(view, false, word, color))
			{
				// fail -> nothing
			}

			auto* idaFnc = getIdaFunction(word, color);
			const retdec::config::Function* cFnc = getWordFunction(word, color);
			const retdec::config::Object* cGv = getWordGlobal(word, color);

			TPopupMenu* p = va_arg(va, TPopupMenu*);

			// Function context.
			//
			if (idaFnc && cFnc)
			{
				attach_action_to_popup(view, p, "-");

				jump_to_asm_ah.setAddress(idaFnc->start_ea);
				attach_action_to_popup(view, p, jump_to_asm_ah_t::actionName);

				change_fnc_global_name_ah.setView(view);
				attach_action_to_popup(view, p, change_fnc_global_name_ah_t::actionName);

				if (isCurrentFunction(idaFnc))
				{
					change_fnc_type_ah.setView(view);
					attach_action_to_popup(view, p, change_fnc_type_ah_t::actionName);
				}

				open_xrefs_ah.setFunction(idaFnc);
				attach_action_to_popup(view, p, open_xrefs_ah_t::actionName);

				open_calls_ah.setFunction(idaFnc);
				attach_action_to_popup(view, p, open_calls_ah_t::actionName);
			}
			// Global var context.
			//
			else if (cGv)
			{
				globalAddress = cGv->getStorage().getAddress();

				attach_action_to_popup(view, p, "-");

				jump_to_asm_ah.setAddress(globalAddress);
				attach_action_to_popup(view, p, jump_to_asm_ah_t::actionName);

				change_fnc_global_name_ah.setView(view);
				attach_action_to_popup(view, p, change_fnc_global_name_ah_t::actionName);
			}

			// Common for all contexts.
			//
			attach_action_to_popup(view, p, "-");
			attach_action_to_popup(view, p, change_fnc_comment_ah_t::actionName);
			attach_action_to_popup(view, p, move_backward_ah_t::actionName);
			attach_action_to_popup(view, p, move_forward_ah_t::actionName);
			attach_action_to_popup(view, p, "-");
			break;
		}
	}

	return false;
}

void registerPermanentActions()
{
	register_action(jump_to_asm_ah_desc);
	register_action(change_fnc_global_name_ah_desc);
	register_action(open_xrefs_ah_desc);
	register_action(open_calls_ah_desc);
	register_action(change_fnc_type_ah_desc);
	register_action(change_fnc_comment_ah_desc);
	register_action(move_forward_ah_desc);
	register_action(move_backward_ah_desc);
}

//
//==============================================================================
//

/**
 * Callback for double click in custom viewer.
 */
bool idaapi ct_double(TWidget* cv, int shift, void* ud)
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

//
//==============================================================================
//

void idaapi ct_close(TWidget* cv, void* ud)
{
	RdGlobalInfo* di = static_cast<RdGlobalInfo*>(ud);

	di->custViewer = nullptr;
	di->codeViewer = nullptr;
}

//
//==============================================================================
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

} // namespace idaplugin
