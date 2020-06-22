
#include <retdec/retdec/retdec.h>
#include <retdec/utils/binary_path.h>

#include "function.h"
#include "config.h"
#include "place.h"
#include "retdec.h"
#include "ui.h"

plugmod_t* idaapi init(void)
{
	auto* ctx = new RetDec();
	return ctx->pluginRegNumber < 0 ? nullptr : ctx;
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,                    // plugin flags
	init,                            // initialize fnc
	nullptr,                         // terminate fnc
	nullptr,                         // invoke fnc
	RetDec::pluginCopyright.data(), // long plugin comment
	RetDec::pluginURL.data(),       // multiline plugin help
	RetDec::pluginName.data(),      // the preferred plugin short name
	RetDec::pluginHotkey.data()     // the preferred plugin hotkey
};

std::map<func_t*, Function> RetDec::fnc2fnc;
retdec::config::Config RetDec::config;

RetDec::RetDec()
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

	retdec_place_t::registerPlace(PLUGIN);

	hook_event_listener(HT_UI, this);

	INFO_MSG(pluginName << " version " << pluginVersion << " loaded OK\n");
}

bool runDecompilation(
		retdec::config::Config& config,
		std::string* output = nullptr)
{
	try
	{
		auto rc = retdec::decompile(config, output);
		if (rc != 0)
		{
			throw std::runtime_error(
					"decompilation error code = " + std::to_string(rc)
			);
		}
	}
	catch (const std::runtime_error& e)
	{
		WARNING_GUI("Decompilation exception: " << e.what() << std::endl);
		return true;
	}
	catch (...)
	{
		WARNING_GUI("Decompilation exception: unknown" << std::endl);
		return true;
	}

	return false;
}

Function* RetDec::selectiveDecompilation(ea_t ea, bool redecompile)
{
	if (isRelocatable() && inf_get_min_ea() != 0)
	{
		WARNING_GUI("RetDec plugin can selectively decompile only "
				"relocatable objects loaded at 0x0.\n"
				"Rebase the program to 0x0 or use full decompilation."
		);
		return nullptr;
	}

	func_t* f = get_func(ea);
	if (f == nullptr)
	{
		WARNING_GUI("Function must be selected by the cursor.\n");
		return nullptr;
	}

	if (!redecompile)
	{
		auto it = fnc2fnc.find(f);
		if (it != fnc2fnc.end())
		{
			return &it->second;
		}
	}

	if (fillConfig(config))
	{
		return nullptr;
	}

	std::set<ea_t> selectedFncs;

	config.parameters.setOutputFormat("json");
	retdec::common::AddressRange r(f->start_ea, f->end_ea);
	config.parameters.selectedRanges.insert(r);
	selectedFncs.insert(f->start_ea);
	config.parameters.setIsSelectedDecodeOnly(true);

	show_wait_box("Decompiling...");
	std::string output;
	if (runDecompilation(config, &output))
	{
		hide_wait_box();
		return nullptr;
	}
	hide_wait_box();

	auto ts = parseTokens(output, f->start_ea);
	if (ts.empty())
	{
		return nullptr;
	}
	return &(fnc2fnc[f] = Function(f, ts));
}

Function* RetDec::selectiveDecompilationAndDisplay(ea_t ea, bool redecompile)
{
	auto* f = selectiveDecompilation(ea, redecompile);
	if (f)
	{
		displayFunction(f, ea);
	}
	return f;
}

void RetDec::displayFunction(Function* f, ea_t ea)
{
	fnc = f;

	retdec_place_t min(fnc, fnc->min_yx());
	retdec_place_t max(fnc, fnc->max_yx());
	retdec_place_t cur(fnc, fnc->ea_2_yx(ea));

	TWidget* widget = find_widget(RetDec::pluginName.c_str());
	if (widget != nullptr)
	{
		set_custom_viewer_range(custViewer, &min, &max);
		jumpto(custViewer, &cur, cur.x(), cur.y());
		bool take_focus = true;
		activate_widget(custViewer, take_focus);
		return;
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
			RetDec::pluginName.c_str(),        // title
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

	return;
}

bool RetDec::fullDecompilation()
{
	std::string defaultOut = getInputPath() + ".c";

	char *tmp = ask_file(                // Returns: file name
			true,                        // bool for_saving
			defaultOut.data(),           // const char *default_answer
			"%s",                        // const char *format
			"Save decompiled file"
	);
	if (tmp == nullptr) // canceled
	{
		return false;
	}
	std::string out = tmp;

	INFO_MSG("Selected file: " << out << "\n");

	if (fillConfig(config, out))
	{
		return false;
	}
	config.parameters.setOutputFormat("c");

	show_wait_box("Decompiling...");
	runDecompilation(config);
	hide_wait_box();

	return true;
}

bool idaapi RetDec::run(size_t arg)
{
	if (!auto_is_ok())
	{
		INFO_MSG("RetDec plugin cannot run because the initial autoanalysis"
				" has not been finished.\n");
		return false;
	}

	// ordinary selective decompilation
	//
	if (arg == 0)
	{
		auto* cv = get_current_viewer();
		bool redecompile = cv == custViewer || cv == codeViewer;
		return selectiveDecompilationAndDisplay(get_screen_ea(), redecompile);
	}
	// ordinary full decompilation
	//
	else if (arg == 1)
	{
		return fullDecompilation();
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

RetDec::~RetDec()
{
	unhook_event_listener(HT_UI, this);
}

void RetDec::modifyFunctions(
		Token::Kind k,
		const std::string& oldVal,
		const std::string& newVal)
{
	for (auto& p : fnc2fnc)
	{
		modifyFunction(p.first, k, oldVal, newVal);
	}
}

void RetDec::modifyFunction(
		func_t* f,
		Token::Kind k,
		const std::string& oldVal,
		const std::string& newVal)
{
	auto fIt = fnc2fnc.find(f);
	if (fIt == fnc2fnc.end())
	{
		return;
	}
	Function& F = fIt->second;

	std::vector<Token> newTokens;

	for (auto& t : F.getTokens())
	{
		if (t.second.kind == k && t.second.value == oldVal)
		{
			newTokens.emplace_back(Token(k, t.second.ea, newVal));
		}
		else
		{
			newTokens.emplace_back(t.second);
		}
	}

	fIt->second = Function(f, newTokens);
}

ea_t RetDec::getFunctionEa(const std::string& name)
{
	// USe config.
	auto* f = config.functions.getFunctionByName(name);
	if (f && f->getStart().isDefined())
	{
		return f->getStart();
	}

	// Use IDA.
	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t* f = getn_func(i);
		qstring qFncName;
		get_func_name(&qFncName, f->start_ea);
		if (qFncName.c_str() == name)
		{
			return f->start_ea;
		}
	}

	return BADADDR;
}

func_t* RetDec::getIdaFunction(const std::string& name)
{
	auto ea = getFunctionEa(name);
	return ea != BADADDR ? get_func(ea) : nullptr;
}

ea_t RetDec::getGlobalVarEa(const std::string& name)
{
	auto* g = config.globals.getObjectByName(name);
	if (g && g->getStorage().getAddress())
	{
		return g->getStorage().getAddress();
	}
	return BADADDR;
}
