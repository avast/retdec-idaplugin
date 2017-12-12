/**
 * @file idaplugin/decompiler.h
 * @brief Module contains classes/methods dealing with program decompilation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_DECOMPILER_H
#define IDAPLUGIN_DECOMPILER_H

#include <string>

#include "defs.h"

namespace idaplugin {

void createRangesFromSelectedFunction(RdGlobalInfo &decompInfo, func_t *fnc);
void decompileInput(RdGlobalInfo &decompInfo);

} // namespace idaplugin

#endif
