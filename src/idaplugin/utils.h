#ifndef HEXRAYS_DEMO_UTILS_H
#define HEXRAYS_DEMO_UTILS_H

#include <string>

/**
 * Is the file currently loaded to IDA some x86 flavour?
 */
bool isX86();

/**
 * Get full path to the file currently loaded to IDA.
 * Returns empty string if it is unable to get the file.
 * May ask user to specify the file in a GUI dialog.
 */
std::string getInputPath();

#endif