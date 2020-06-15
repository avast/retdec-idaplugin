
#ifndef HEXRAYS_DEMO_CONFIG_H
#define HEXRAYS_DEMO_CONFIG_H

#include <retdec/config/config.h>

/**
 * Returns \c true if something went wrong.
 */
bool fillConfig(retdec::config::Config& config, const std::string& out = "");

#endif
