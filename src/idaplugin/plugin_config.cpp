/**
 * @file idaplugin/plugin_config.cpp
 * @brief Module deals with RetDec plugin configuration.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#include <json/json.h>

#include "retdec/utils/file_io.h"
#include "retdec/utils/string.h"
#include "plugin_config.h"

namespace {

const std::string JSON_decompileShPath = "decompileShPath";

} // anonymous namespace

namespace idaplugin {

/**
 * Get root value from the provided JSON string.
 * @param[in]  json String containing entire JSON file.
 * @param[out] root JSON root value to get from config.
 * @param[in]  silent Should the function throw warning at user if
 *                    something goes wrong?
 * @return @c False is @a root value read ok, @c true otherwise.
 */
bool getConfigRootFromString(
		const std::string& json,
		Json::Value& root,
		bool silent = true)
{
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(json, root);
	if (!parsingSuccessful || root.isNull() || !root.isObject())
	{
		std::string errMsg = "Failed to parse configuration";
		std::size_t line = 0;
		std::size_t column = 0;

		auto errs = reader.getStructuredErrors();
		if (!errs.empty())
		{
			errMsg = errs.front().message;
			auto loc = retdec::utils::getLineAndColumnFromPosition(
					json,
					errs.front().offset_start
			);
			line = loc.first;
			column = loc.second;
		}

		if (!silent)
		{
			warning("Failed to parse JSON content.\n"
					"Line: %d, Column: %d, Error: %s\n",
					line, column, errMsg.c_str());
		}
		return true;
	}

	return false;
}

/**
 * Get root value from the provided JSON file.
 * @param[in]  file   JSON file.
 * @param[out] root   JSON root value to get from config.
 * @return @c False is @a root value read ok, @c true otherwise.
 */
bool getConfigRootFromFile(
		const std::string& file,
		Json::Value& root)
{
	std::ifstream jsonFile(file, std::ios::in | std::ios::binary);
	if (!jsonFile)
	{
		return true;
	}

	std::string jsonContent;
	jsonFile.seekg(0, std::ios::end);
	jsonContent.resize(jsonFile.tellg());
	jsonFile.seekg(0, std::ios::beg);
	jsonFile.read(&jsonContent[0], jsonContent.size());
	jsonFile.close();

	return getConfigRootFromString(jsonContent, root);
}

/**
 * Read provided JSON file into plugins's global information.
 * @param rdgi Plugin's global information.
 * @return @c False is @a config read ok, @c true otherwise.
 */
bool readConfigFile(RdGlobalInfo& rdgi)
{
	Json::Value root;

	if (getConfigRootFromFile(rdgi.pluginConfigFile, root))
	{
		return true;
	}

	rdgi.decompileShPath = root.get(JSON_decompileShPath, "").asString();

	return false;
}

/**
 * Save plugin's configuration into provided JSON file.
 * File content is rewritten.
 * @param rdgi Plugin's global information.
 */
void saveConfigTofile(RdGlobalInfo& rdgi)
{
	Json::Value root;

	if (getConfigRootFromFile(rdgi.pluginConfigFile, root))
	{
		// Problem when reading config -- does not matter, we use empty root.
	}

	root[JSON_decompileShPath] = rdgi.decompileShPath;

	Json::StyledWriter writer;
	std::ofstream jsonFile(rdgi.pluginConfigFile.c_str());
	jsonFile << writer.write(root);
}

/**
 * Present plugin configuration form to developer.
 * @param rdgi Plugin's global information.
 * @return @c True if cancelled, @c false otherwise.
 */
bool askUserToConfigurePlugin(RdGlobalInfo& rdgi)
{
	static const char format[] =
		"RetDec Plugin Settings\n"
		"\n"
		"\n"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"Path to retdec-decompiler.sh (unnecessary if it is in the system PATH):\n"
		"<:f3:1:64::>\n"
		"\n";

	char cDecompileSh[QMAXPATH] = {};

	if (rdgi.decompileShPath.empty())
	{
		std::string pattern = "retdec-decompiler.sh";
		std::copy(pattern.begin(), pattern.begin() + QMAXPATH, cDecompileSh);
	}
	else
	{
		std::copy(rdgi.decompileShPath.begin(), rdgi.decompileShPath.begin() + QMAXPATH, cDecompileSh);
	}

	if (AskUsingForm_c(format, cDecompileSh) == 0)
	{
		// ESC or CANCEL
		return true;
	}
	else
	{
		rdgi.decompileShPath = cDecompileSh;
	}

	return false;
}

/**
 * @return @c True if cancelled, @c false otherwise.
 */
bool pluginConfigurationMenu(RdGlobalInfo& rdgi)
{
	bool canceled = askUserToConfigurePlugin(rdgi);
	if (!canceled)
	{
		saveConfigTofile(rdgi);
	}
	return canceled;
}

/**
 * Callback wrapper for pluginConfigurationMenu() function.
 */
bool idaapi pluginConfigurationMenuCallBack(void* ud)
{
	RdGlobalInfo* rdgi = static_cast<RdGlobalInfo*>(ud);
	pluginConfigurationMenu(*rdgi);
	return false;
}

} // namespace idaplugin
