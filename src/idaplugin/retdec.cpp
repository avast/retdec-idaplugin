
#include <retdec/utils/binary_path.h>

#include "decompiler.h"
#include "function.h"
#include "place.h"
#include "retdec.h"
#include "ui.h"

plugmod_t* idaapi init(void)
{
	auto* ctx = new Context();
	if (ctx->pluginRegNumber < 0)
	{
		return nullptr;
	}
	INFO_MSG(ctx->pluginName << " version "
			<< ctx->pluginVersion << " loaded OK\n");
	return ctx;
}

/**
 * Plugin interface definition.
 * IDA is searching for this structure.
 */
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,   // plugin flags
	init,           // initialize fnc
	nullptr,        // terminate fnc
	nullptr,        // invoke fnc
	Context::pluginCopyright.data(), // long plugin comment
	Context::pluginURL.data(), // multiline plugin help
	Context::pluginName.data(), // the preferred plugin short name
	Context::pluginHotkey.data()  // the preferred plugin hotkey
};

Context::Context()
		: idaPath(retdec::utils::getThisBinaryDirectoryPath())
{
	pluginInfo.id = pluginID.data();
	pluginInfo.name = pluginName.data();
	pluginInfo.producer = pluginProducer.data();
	pluginInfo.version = pluginVersion.data();
	pluginInfo.url = pluginContact.data();
	pluginInfo.freeform = pluginCopyright.data();
	pluginRegNumber = register_addon(&pluginInfo);
	if (pluginRegNumber < 0)
	{
		WARNING_GUI(pluginName << " version " << pluginVersion
				<< " failed to register.\n");
		return;
	}

	if (!register_action(fullDecompilation_ah_desc)
			|| !attach_action_to_menu(
					"File/Produce file/Create DIF file",
					fullDecompilation_ah_t::actionName,
					SETMENU_APP))
	{
		ERROR_MSG("Failed to register: " << fullDecompilation_ah_t::actionName);
	}
	register_action(jump2asm_ah_desc);
	register_action(copy2asm_ah_desc);
	register_action(funcComment_ah_desc);
	register_action(renameGlobalObj_ah_desc);
	register_action(openCalls_ah_desc);
	register_action(openXrefs_ah_desc);
	register_action(changeFuncType_ah_desc);
}

bool Context::runSelectiveDecompilation(ea_t ea)
{
	auto* cv = get_current_viewer();
	bool redecompile = cv == custViewer || cv == codeViewer;

	fnc = Decompiler::decompile(ea, redecompile);
	if (fnc == nullptr)
	{
		return false;
	}

	retdec_place_t min(fnc, fnc->min_yx());
	retdec_place_t max(fnc, fnc->max_yx());
	retdec_place_t cur(fnc, fnc->ea_2_yx(ea));

	TWidget* widget = find_widget(Context::pluginName.c_str());
	if (widget != nullptr)
	{
		set_custom_viewer_range(custViewer, &min, &max);
		jumpto(custViewer, &cur, cur.x(), cur.y());
		bool take_focus = true;
		activate_widget(custViewer, take_focus);
		return true;
	}

	// Without setting both x and y in render info, the current line gets
	// displayed as the first line in the viewer. Which is not nice because we
	// don't see the context before it. It is better if it is somewhere in the
	// middle of the viewer.
	renderer_info_t rinfo;
	rinfo.rtype = TCCRT_FLAT;
	rinfo.pos.cx = cur.x();
	rinfo.pos.cy = cur.y();

	custViewer = create_custom_viewer(
			Context::pluginName.c_str(),        // title
			&min,         // minplace
			&max,         // maxplace
			&cur,         // curplace
			&rinfo,       // rinfo
			this,         // ud
			&ui_handlers, // handlers
			this,         // cvhandlers_ud
			nullptr       // parent widget
	);
	set_view_renderer_type(custViewer, TCCRT_FLAT);

	codeViewer = create_code_viewer(custViewer);
	set_code_viewer_is_source(codeViewer);
	display_widget(codeViewer, WOPN_DP_TAB | WOPN_RESTORE);

	return true;
}

bool Context::runFullDecompilation()
{
	std::string defaultOut = getInputPath() + ".c";

	char *tmp = ask_file(                ///< Returns: file name
			true,                        ///< bool for_saving
			defaultOut.data(),           ///< const char *default_answer
			"%s",                        ///< const char *format
			"Save decompiled file"
	);
	if (tmp == nullptr) ///< canceled
	{
		return false;
	}

	INFO_MSG("Selected file: " << tmp << "\n");

	Decompiler::decompile(tmp);

	return true;
}

bool idaapi Context::run(size_t arg)
{
	if (!auto_is_ok())
	{
		INFO_MSG("RetDec plugin cannot run because the initial autoanalysis"
				" has not been finished.\n");
		return false;
	}

	retdec_place_t::registerPlace(PLUGIN);

	// ordinary selective decompilation
	//
	if (arg == 0)
	{
		return runSelectiveDecompilation(get_screen_ea());
	}
	// ordinary full decompilation
	//
	else if (arg == 1)
	{
		return runFullDecompilation();
	}
	// Selective decompilation used in plugin's regression tests
	// forced local decompilation + disabled threads
	// function to decompile is selected by "<retdec_select>" string in function's comment
	//
	else if (arg == 4)
	{
		for (unsigned i = 0; i < get_func_qty(); ++i)
		{
			qstring qCmt;
			func_t *fnc = getn_func(i);
			if (get_func_cmt(&qCmt, fnc, false) <= 0)
			{
				continue;
			}

			std::string cmt = qCmt.c_str();;
			if (cmt.find("<retdec_select>") != std::string::npos)
			{
				useThreads = false;
				return runSelectiveDecompilation(fnc->start_ea);
			}
		}
		return true;
	}
	// Full decompilation + disabled threads = used in regression tests:
	//
	else if (arg == 5)
	{
		useThreads = false;
		return runFullDecompilation();
	}
	else
	{
		WARNING_GUI(pluginName << " version " << pluginVersion
				<< " cannot handle argument '" << arg << "'.\n"
		);
		return false;
	}

	return true;
}

Context::~Context()
{
	unhook_event_listener(HT_UI, this);
}
