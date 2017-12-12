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
bool idaapi pluginConfigurationMenuCallBack(void* ud);

bool readConfigFile(RdGlobalInfo& rdgi);
void saveConfigTofile(RdGlobalInfo& rdgi);

} // namespace idaplugin

#endif
