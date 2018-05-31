/**
 * @file idaplugin/plugin_config.h
 * @brief Module deals with RetDec plugin configuration.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_PLUGIN_CONFIG_H
#define IDAPLUGIN_PLUGIN_CONFIG_H

#include "defs.h"

namespace idaplugin {

bool pluginConfigurationMenu(RdGlobalInfo& rdgi);

struct show_options_ah_t : public action_handler_t
{
	show_options_ah_t(RdGlobalInfo* i) : rdgi(i) {}

	virtual int idaapi activate(action_activation_ctx_t *)
	{
		pluginConfigurationMenu(*rdgi);
		return false;
	}

	virtual action_state_t idaapi update(action_update_ctx_t *)
	{
		return AST_ENABLE_ALWAYS;
	}

	RdGlobalInfo* rdgi = nullptr;
};

bool addConfigurationMenuOption(RdGlobalInfo& rdgi);

bool readConfigFile(RdGlobalInfo& rdgi);
void saveConfigTofile(RdGlobalInfo& rdgi);

} // namespace idaplugin

#endif
