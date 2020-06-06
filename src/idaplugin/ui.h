
#ifndef HEXRAYS_DEMO_UI_H
#define HEXRAYS_DEMO_UI_H

class Context;

struct function_ctx_ah_t : public action_handler_t
{
	inline static const char* actionName = "demo:ActionFunctionCtx";
	inline static const char* actionLabel = "Function context";
	inline static const char* actionHotkey = "F";

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct variable_ctx_ah_t : public action_handler_t
{
	inline static const char* actionName = "demo:ActionVariableCtx";
	inline static const char* actionLabel = "Variable context";
	inline static const char* actionHotkey = "V";

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

struct copy2asm_ah_t : public action_handler_t
{
	inline static const char* actionName = "demo:ActionCopy2Asm";
	inline static const char* actionLabel = "Copy to assembly";
	inline static const char* actionHotkey = "C";

	Context& ctx;
	copy2asm_ah_t(Context& c);

	virtual int idaapi activate(action_activation_ctx_t*) override;
	virtual action_state_t idaapi update(action_update_ctx_t*) override;
};

bool idaapi cv_keyboard(TWidget *cv, int vk_key, int shift, void *ud);
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
int idaapi cv_can_navigate(
        TWidget *v,
        const lochist_entry_t *now,
        const locchange_md_t &md,
        void *ud
);

static const custom_viewer_handlers_t ui_handlers(
		cv_keyboard,         // keyboard
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
		cv_can_navigate      // can_navigate
);

#endif
