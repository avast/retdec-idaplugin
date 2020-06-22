
#ifndef RETDEC_UI_H
#define RETDEC_UI_H

#include "utils.h"

class RetDec;

struct fullDecompilation_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:ActionFullDecompilation";
	inline static const char* actionLabel = "Create C file RetDec...";
	inline static const char* actionHotkey = "Ctrl+Shift+D";

	RetDec& plg;
	fullDecompilation_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct jump2asm_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:ActionJump2Asm";
	inline static const char* actionLabel = "Jump to assembly";
	inline static const char* actionHotkey = "A";

	RetDec& plg;
	jump2asm_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct copy2asm_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:ActionCopy2Asm";
	inline static const char* actionLabel = "Copy to assembly";
	inline static const char* actionHotkey = "";

	RetDec& plg;
	copy2asm_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct funcComment_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:ActionFunctionComment";
	inline static const char* actionLabel = "Edit func comment";
	inline static const char* actionHotkey = ";";

	RetDec& plg;
	funcComment_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct renameGlobalObj_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:RenameGlobalObj";
	inline static const char* actionLabel = "Rename global object";
	inline static const char* actionHotkey = "R";

	RetDec& plg;
	renameGlobalObj_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct openXrefs_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:OpenXrefs";
	inline static const char* actionLabel = "Open xrefs";
	inline static const char* actionHotkey = "X";

	RetDec& plg;
	openXrefs_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct openCalls_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:OpenCalls";
	inline static const char* actionLabel = "Open calls";
	inline static const char* actionHotkey = "C";

	RetDec& plg;
	openCalls_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct changeFuncType_ah_t : public action_handler_t
{
	inline static const char* actionName = "retdec:ChangeFuncType";
	inline static const char* actionLabel = "Change function type";
	inline static const char* actionHotkey = "T";

	RetDec& plg;
	changeFuncType_ah_t(RetDec& p);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

bool idaapi cv_double(TWidget* cv, int shift, void* ud);
void idaapi cv_adjust_place(TWidget* v, lochist_entry_t* loc, void* ud);
int idaapi cv_get_place_xcoord(
		TWidget* v,
		const place_t* pline,
		const place_t* pitem,
		void* ud
);
void idaapi cv_location_changed(
        TWidget *v,
        const lochist_entry_t* was,
        const lochist_entry_t* now,
        const locchange_md_t& md,
        void* ud
);

static const custom_viewer_handlers_t ui_handlers(
		nullptr,             // keyboard
		nullptr,             // popup
		nullptr,             // mouse_moved
		nullptr,             // click
		cv_double,           // dblclick
		nullptr,             // current position change
		nullptr,             // close
		nullptr,             // help
		cv_adjust_place,     // adjust_place
		cv_get_place_xcoord, // get_place_xcoord
		cv_location_changed, // location_changed
		nullptr              // can_navigate
);

#endif
