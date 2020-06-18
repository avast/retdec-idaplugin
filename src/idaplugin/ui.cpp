
#include "decompiler.h"
#include "place.h"
#include "retdec.h"
#include "ui.h"

//
//==============================================================================
// fullDecompilation_ah_t
//==============================================================================
//

fullDecompilation_ah_t::fullDecompilation_ah_t(Context& p)
		: plg(p)
{

}

int idaapi fullDecompilation_ah_t::activate(action_activation_ctx_t*)
{
	plg.runFullDecompilation();
	return false;
}

action_state_t idaapi fullDecompilation_ah_t::update(action_update_ctx_t*)
{
	return AST_ENABLE_ALWAYS;
}

//
//==============================================================================
// jump2asm_ah_t
//==============================================================================
//

jump2asm_ah_t::jump2asm_ah_t(Context& p)
		: plg(p)
{

}

int idaapi jump2asm_ah_t::activate(action_activation_ctx_t* ctx)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
			ctx->widget,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	if (place == nullptr)
	{
		return false;
	}

	jumpto(place->toea(), 0, UIJMP_ACTIVATE | UIJMP_IDAVIEW);
	return false;
}

action_state_t idaapi jump2asm_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// copy2asm_ah_t
//==============================================================================
//

copy2asm_ah_t::copy2asm_ah_t(Context& p)
		: plg(p)
{

}

int idaapi copy2asm_ah_t::activate(action_activation_ctx_t*)
{
	static const char* text = "Copying pseudocode to disassembly"
			" will destroy existing comments.\n"
			"Do you want to continue?";
	if (ask_yn(ASKBTN_NO, text) == ASKBTN_YES)
	{
		for (auto& p : plg.fnc->toLines())
		{
			ea_t addr = p.second;
			auto& line = p.first;

			delete_extra_cmts(addr, E_PREV);
			bool anteriorCmt = true;
			add_extra_cmt(addr, anteriorCmt, "%s", line.c_str());
		}

		// Focus to IDA view.
		auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
				plg.custViewer,
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

action_state_t idaapi copy2asm_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// funcComment_ah_t
//==============================================================================
//

funcComment_ah_t::funcComment_ah_t(Context& p)
		: plg(p)
{

}

int idaapi funcComment_ah_t::activate(action_activation_ctx_t*)
{
	auto* fnc = plg.fnc ? plg.fnc->fnc() : nullptr;
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
		plg.runSelectiveDecompilation(fnc->start_ea);
	}

	return false;
}

action_state_t idaapi funcComment_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// renameGlobalObj_ah_t
//==============================================================================
//

renameGlobalObj_ah_t::renameGlobalObj_ah_t(Context& p)
		: plg(p)
{

}

int idaapi renameGlobalObj_ah_t::activate(action_activation_ctx_t* ctx)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
			ctx->widget,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	auto* token = place ? place->token() : nullptr;
	if (token == nullptr)
	{
		return false;
	}

	std::string askString;
	ea_t addr = BADADDR;
	if (token->kind == Token::Kind::ID_FNC)
	{
		askString = "Please enter function name";
		addr = getIdaFuncEa(token->value);
	}
	else if (token->kind == Token::Kind::ID_GVAR)
	{
		askString = "Please enter global variable name";
		addr = getIdaGlobalEa(token->value);
	}
	if (addr == BADADDR)
	{
		return false;
	}

	qstring qNewName = token->value.c_str();
	if (!ask_str(&qNewName, HIST_IDENT, "%s", askString.c_str())
			|| qNewName.empty())
	{
		return false;
	}
	std::string newName = qNewName.c_str();
	if (newName == token->value)
	{
		return false;
	}

	if (set_name(addr, newName.c_str()) == false)
	{
		return false;
	}

	// TODO: set new name accross all decompiled code.

	return false;
}

action_state_t idaapi renameGlobalObj_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// openXrefs_ah_t
//==============================================================================
//

openXrefs_ah_t::openXrefs_ah_t(Context& p)
		: plg(p)
{

}

int idaapi openXrefs_ah_t::activate(action_activation_ctx_t* ctx)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
			ctx->widget,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	auto* token = place ? place->token() : nullptr;
	if (token == nullptr)
	{
		return false;
	}

	ea_t ea = BADADDR;
	if (token->kind == Token::Kind::ID_FNC)
	{
		ea = getIdaFuncEa(token->value);
	}
	else if (token->kind == Token::Kind::ID_GVAR)
	{
		ea = getIdaGlobalEa(token->value);
	}
	if (ea == BADADDR)
	{
		return false;
	}

	open_xrefs_window(ea);
	return false;
}

action_state_t idaapi openXrefs_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// openCalls_ah_t
//==============================================================================
//

openCalls_ah_t::openCalls_ah_t(Context& p)
		: plg(p)
{

}

int idaapi openCalls_ah_t::activate(action_activation_ctx_t* ctx)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
			ctx->widget,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	auto* token = place ? place->token() : nullptr;
	if (token == nullptr)
	{
		return false;
	}

	ea_t ea = BADADDR;
	if (token->kind == Token::Kind::ID_FNC)
	{
		ea = getIdaFuncEa(token->value);
	}
	else if (token->kind == Token::Kind::ID_GVAR)
	{
		ea = getIdaGlobalEa(token->value);
	}
	if (ea == BADADDR)
	{
		return false;
	}

	open_calls_window(ea);
	return false;
}

action_state_t idaapi openCalls_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// changeFuncType_ah_t
//==============================================================================
//

changeFuncType_ah_t::changeFuncType_ah_t(Context& p)
		: plg(p)
{

}

int idaapi changeFuncType_ah_t::activate(action_activation_ctx_t* ctx)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
			ctx->widget,
			false, // mouse
			nullptr, // x
			nullptr // y
	));
	auto* token = place ? place->token() : nullptr;
	if (token == nullptr)
	{
		return false;
	}

	func_t* fnc = nullptr;
	if (token->kind == Token::Kind::ID_FNC)
	{
		fnc = getIdaFunc(token->value);
	}
	if (fnc == nullptr)
	{
		return false;
	}

	qstring buf;
	int flags = PRTYPE_1LINE | PRTYPE_SEMI;
	if (!print_type(&buf, fnc->start_ea, flags))
	{
		qstring qFncName;
		get_func_name(&qFncName, fnc->start_ea);;
		WARNING_GUI("Cannot change declaration for: "
			<< qFncName.c_str() << "\n"
		);
	}

	std::string askString = "Please enter type declaration:";

	qstring qNewDeclr = buf;
	if (!ask_str(&qNewDeclr, HIST_IDENT, "%s", askString.c_str())
			|| qNewDeclr.empty())
	{
		return false;
	}

	if (apply_cdecl(nullptr, fnc->start_ea, qNewDeclr.c_str()))
	{
		plg.runSelectiveDecompilation(fnc->start_ea);
	}
	else
	{
		WARNING_GUI("Cannot change declaration to: "
			<< qNewDeclr.c_str() << "\n"
		);
	}

	return false;
}

action_state_t idaapi changeFuncType_ah_t::update(action_update_ctx_t* ctx)
{
	return ctx->widget == plg.custViewer
			? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

//
//==============================================================================
// on_event
//==============================================================================
//

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

			auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
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

			func_t* tfnc = nullptr;
			if (token->kind == Token::Kind::ID_FNC
					&& (tfnc = getIdaFunc(token->value)))
			{
				attach_action_to_popup(
						view,
						popup,
						renameGlobalObj_ah_t::actionName
				);
				attach_action_to_popup(
						view,
						popup,
						openXrefs_ah_t::actionName
				);
				attach_action_to_popup(
						view,
						popup,
						openCalls_ah_t::actionName
				);

				if (fnc->fnc() == tfnc)
				{
					attach_action_to_popup(
							view,
							popup,
							changeFuncType_ah_t::actionName
					);
				}

				attach_action_to_popup(view, popup, "-");
			}
			else if (token->kind == Token::Kind::ID_GVAR)
			{
				attach_action_to_popup(
						view,
						popup,
						renameGlobalObj_ah_t::actionName
				);
				attach_action_to_popup(
						view,
						popup,
						openXrefs_ah_t::actionName
				);
				attach_action_to_popup(view, popup, "-");
			}

			attach_action_to_popup(
					view,
					popup,
					jump2asm_ah_t::actionName
			);
			attach_action_to_popup(
					view,
					popup,
					copy2asm_ah_t::actionName
			);
			attach_action_to_popup(
					view,
					popup,
					funcComment_ah_t::actionName
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

			auto* demoPlace = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
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

//
//==============================================================================
// cv handlers
//==============================================================================
//

/**
 * Called whenever the user moves the cursor around (mouse, keyboard).
 * Fine-tune 'loc->place()' according to the X position.
 *
 * Without this, retdec_place_t's X position would not change when cursor moves
 * around.
 * Changing the position triggers some actions. E.g. retdec_place_t::print().
 *
 * custom_viewer_adjust_place_t
 */
void idaapi cv_adjust_place(TWidget* v, lochist_entry_t* loc, void* ud)
{
	auto* plc = static_cast<retdec_place_t*>(loc->place());
	auto* fnc = plc->fnc();

	retdec_place_t nplc(
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

bool idaapi cv_double(TWidget* cv, int shift, void* ud)
{
	auto* place = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(
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

	auto* fnc = getIdaFunc(fncName);
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

	auto* oldp = dynamic_cast<const retdec_place_t*>(was->place());
	auto* newp = dynamic_cast<const retdec_place_t*>(now->place());
	if (oldp->compare(newp) == 0) // equal
	{
		return;
	}

	if (oldp->fnc() != newp->fnc())
	{
		retdec_place_t min(newp->fnc(), newp->fnc()->min_yx());
		retdec_place_t max(newp->fnc(), newp->fnc()->max_yx());
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
	auto* mpline = static_cast<const retdec_place_t*>(pline);
	auto* mpitem = static_cast<const retdec_place_t*>(pitem);

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
