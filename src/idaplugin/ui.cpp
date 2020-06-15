
#include "context.h"
#include "decompiler.h"
#include "place.h"
#include "ui.h"

int idaapi function_ctx_ah_t::activate(action_activation_ctx_t*)
{
	info("function context action");
	return false;
}

action_state_t idaapi function_ctx_ah_t::update(action_update_ctx_t*)
{
	return AST_ENABLE_ALWAYS;
}

int idaapi variable_ctx_ah_t::activate(action_activation_ctx_t*)
{
	info("variable context action");
	return false;
}

action_state_t idaapi variable_ctx_ah_t::update(action_update_ctx_t*)
{
	return AST_ENABLE_ALWAYS;
}

copy2asm_ah_t::copy2asm_ah_t(Context& c)
		: ctx(c)
{

}

int idaapi copy2asm_ah_t::activate(action_activation_ctx_t*)
{
	static const char* text = "Copying pseudocode to disassembly"
			" will destroy existing comments.\n"
			"Do you want to continue?";
	if (ask_yn(ASKBTN_NO, text) == ASKBTN_YES)
	{
		for (auto& p : ctx.fnc->toLines())
		{
			ea_t addr = p.second;
			auto& line = p.first;

			delete_extra_cmts(addr, E_PREV);
			bool anteriorCmt = true;
			add_extra_cmt(addr, anteriorCmt, "%s", line.c_str());
		}

		// Focus to IDA view.
		auto* place = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
				ctx.custViewer,
				false, // mouse
				nullptr, // x
				nullptr // y
		));
		if (place != nullptr)
		{
			jumpto(place->toea(), 0, UIJMP_ACTIVATE | UIJMP_IDAVIEW);
		}
	}
	return false;
}

action_state_t idaapi copy2asm_ah_t::update(action_update_ctx_t*)
{
	return AST_ENABLE_ALWAYS;
}

/**
 * User interface hook.
 */
ssize_t idaapi Context::on_event(ssize_t code, va_list va)
{
	switch (code)
	{
		// IDA is populating the context menu (right-click menu) for a widget.
		// We can attach action to popup - i.e. create menu on the fly.
		case ui_populating_widget_popup:
		{
			// Continue only if event was triggered in our widget.
			TWidget* view = va_arg(va, TWidget*);
			TPopupMenu* popup = va_arg(va, TPopupMenu*);
			if (view != custViewer && view != codeViewer)
			{
				return false;
			}

			auto* place = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
					view,
					false, // mouse
					nullptr, // x
					nullptr // y
			));
			if (place == nullptr)
			{
				return false;
			}

			auto* token = place->token();
			if (token == nullptr)
			{
				return false;
			}

			if (token->kind == Token::Kind::ID_FNC)
			{
				attach_action_to_popup(
						view,
						popup,
						function_ctx_ah_t::actionName
				);
			}
			else if (token->kind == Token::Kind::ID_VAR)
			{
				attach_action_to_popup(
						view,
						popup,
						variable_ctx_ah_t::actionName
				);
			}

			attach_action_to_popup(
					view,
					popup,
					copy2asm_ah_t::actionName
			);

			break;
		}


		case ui_get_lines_rendering_info:
		{
			auto* demoSyncGroup = get_synced_group(custViewer);
			if (demoSyncGroup == nullptr)
			{
				return false;
			}

			auto* demoPlace = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
					custViewer,
					false, // mouse
					nullptr, // x
					nullptr // y
			));
			if (demoPlace == nullptr)
			{
				return false;
			}
			auto eas = demoPlace->fnc()->yx_2_eas(demoPlace->yx());

			lines_rendering_output_t* out = va_arg(va, lines_rendering_output_t*);
			TWidget* view = va_arg(va, TWidget*);
			lines_rendering_input_t* info = va_arg(va, lines_rendering_input_t*);

			if (view == nullptr || info->sync_group != demoSyncGroup)
			{
				return false;
			}

			for (auto& sl : info->sections_lines)
			for (auto& l : sl)
			{
				if (eas.count(l->at->toea()))
				{
					out->entries.push_back(new line_rendering_output_entry_t(
						l,
						LROEF_FULL_LINE,
						0xff000000 + syncColor
					));
				}
			}

			break;
		}

		// TWidget is being closed.
		case ui_widget_invisible:
		{
			TWidget* view = va_arg(va, TWidget*);
			if (view != custViewer && view != codeViewer)
			{
				return false;
			}

			unhook_event_listener(HT_UI, this);
			custViewer = nullptr;
			codeViewer = nullptr;
			break;
		}
	}

	return false;
}

/**
 * Called whenever the user moves the cursor around (mouse, keyboard).
 * Fine-tune 'loc->place()' according to the X position.
 *
 * Without this, demo_place_t's X position would not change when cursor moves
 * around.
 * Changing the position triggers some actions. E.g. demo_place_t::print().
 *
 * custom_viewer_adjust_place_t
 */
void idaapi cv_adjust_place(TWidget* v, lochist_entry_t* loc, void* ud)
{
	auto* plc = static_cast<demo_place_t*>(loc->place());
	auto* fnc = plc->fnc();

	demo_place_t nplc(
			fnc,
			fnc->adjust_yx(YX(
					plc->y(),
					loc->renderer_info().pos.cx
	)));

	if (plc->compare(&nplc) != 0) // not equal
	{
		loc->set_place(nplc);
	}
}

bool idaapi cv_keyboard(TWidget *cv, int vk_key, int shift, void *ud)
{
	// A
	if (vk_key == 65 && shift == 0)
	{
		auto* place = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
				cv,
				false, // mouse
				nullptr, // x
				nullptr // y
		));
		if (place == nullptr)
		{
			return false;
		}

		// Jump to IDA view.
		jumpto(place->toea(), 0, UIJMP_ACTIVATE | UIJMP_IDAVIEW);
	}

	return true;
}

bool idaapi cv_double(TWidget* cv, int shift, void* ud)
{
	auto* place = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
			cv,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	if (place == nullptr)
	{
		return false;
	}

	auto* token = place->token();
	if (token == nullptr || token->kind != Token::Kind::ID_FNC)
	{
		return false;
	}
	auto fncName = token->value;

	func_t* fnc = nullptr;
	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t* f = getn_func(i);
		qstring qFncName;
		get_func_name(&qFncName, f->start_ea);
		if (qFncName.c_str() == fncName)
		{
			fnc = f;
			break;
		}
	}

	if (fnc == nullptr)
	{
		INFO_MSG("function \"" << fncName << "\" not found in IDA functions\n");
		return false;
	}

	jumpto(fnc->start_ea, -1, UIJMP_ACTIVATE);

	return true;
}

/**
 * custom_viewer_location_changed_t
 */
void idaapi cv_location_changed(
        TWidget* v,
        const lochist_entry_t* was,
        const lochist_entry_t* now,
        const locchange_md_t& md,
        void* ud)
{
	Context* ctx = static_cast<Context*>(ud);

	auto* oldp = dynamic_cast<const demo_place_t*>(was->place());
	auto* newp = dynamic_cast<const demo_place_t*>(now->place());
	if (oldp->compare(newp) == 0) // equal
	{
		return;
	}

	std::string reason;
	switch (md.reason())
	{
		case lcr_goto: reason = "lcr_goto"; break;
		case lcr_user_switch: reason = "lcr_user_switch"; break;
		case lcr_auto_switch: reason = "lcr_auto_switch"; break;
		case lcr_jump: reason = "lcr_jump"; break;
		case lcr_navigate: reason = "lcr_navigate"; break;
		case lcr_scroll: reason = "lcr_scroll"; break;
		case lcr_internal: reason = "lcr_internal"; break;
		default: reason = "lcr_unknown"; break;
	}

	if (oldp->fnc() != newp->fnc())
	{
		demo_place_t min(newp->fnc(), newp->fnc()->min_yx());
		demo_place_t max(newp->fnc(), newp->fnc()->max_yx());
		set_custom_viewer_range(ctx->custViewer, &min, &max);
		ctx->fnc = newp->fnc();
	}
}

/**
 * custom_viewer_get_place_xcoord_t
 */
int idaapi cv_get_place_xcoord(
		TWidget* v,
		const place_t* pline,
		const place_t* pitem,
		void* ud)
{
	auto* mpline = static_cast<const demo_place_t*>(pline);
	auto* mpitem = static_cast<const demo_place_t*>(pitem);

	if (mpline->y() != mpitem->y())
	{
		return -1; // not included
	}
	// i.e. mpline->y() == mpitem->y()
	else if (mpitem->x() == 0)
	{
		return -2; // points to entire line
	}
	else
	{
		return mpitem->x(); // included at coordinate
	}
}

/**
 * custom_viewer_can_navigate_t
 *
 * I can't seem to trigger this.
 */
int idaapi cv_can_navigate(
        TWidget *v,
        const lochist_entry_t *now,
        const locchange_md_t &md,
        void *ud)
{
	return 0;
}