/**
 * @file idaplugin/plugin_config.cpp
 * @brief Module deals with RetDec plugin configuration.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#include <json/json.h>

#include "tl-cpputils/file_io.h"
#include "tl-cpputils/string.h"
#include "plugin_config.h"

namespace {

//const std::string JSON_apiUrl               = "apiUrl";
const std::string JSON_apiKey               = "apiKey";
const std::string JSON_decompileShPath      = "decompileShPath";
const std::string JSON_versionCheckDate     = "versionCheckDate";
const std::string JSON_pluginLatestVersion  = "pluginLatestVersion";
const std::string JSON_localDecomp          = "localDecompilation";

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
			auto loc = tl_cpputils::getLineAndColumnFromPosition(
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

	rdgi.pluginVersionCheckDate = root.get(JSON_versionCheckDate, "").asString();
	rdgi.pluginLatestVersion = root.get(JSON_pluginLatestVersion, "").asString();
	rdgi.apiKey = root.get(JSON_apiKey, "").asString();
//	rdgi.apiUrl = root.get(JSON_apiUrl, "").asString();
	rdgi.decompileShPath = root.get(JSON_decompileShPath, "").asString();
	rdgi.setIsLocalDecompilation(root.get(JSON_localDecomp, rdgi.isLocalDecompilation()).asBool());

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

	root[JSON_versionCheckDate] = rdgi.pluginVersionCheckDate;
	root[JSON_pluginLatestVersion] = rdgi.pluginLatestVersion;
	root[JSON_apiKey] = rdgi.apiKey;
//	root[JSON_apiUrl] = rdgi.apiUrl;
	root[JSON_decompileShPath] = rdgi.decompileShPath;
	root[JSON_localDecomp] = rdgi.isLocalDecompilation();

	Json::StyledWriter writer;
	std::ofstream jsonFile(rdgi.pluginConfigFile.c_str());
	jsonFile << writer.write(root);
}

int idaapi modcb(int fid, form_actions_t &fa)
{
	ushort isLocalActivated = 0;
	ushort isApiActivated = 0;

	switch (fid)
	{
		// Form is going to be displayed.
		case -1:
			fa.get_checkbox_value(1, &isLocalActivated);
			fa.get_checkbox_value(2, &isApiActivated);
			if (isLocalActivated)
			{
				fa.enable_field(3, true);
				fa.enable_field(4, false);
			}
			else if (isApiActivated)
			{
				fa.enable_field(3, false);
				fa.enable_field(4, true);
			}
			else
			{
				fa.enable_field(3, false);
				fa.enable_field(4, false);
			}
			break;
		// Form is going to be closed with OK.
		case -2:
			break;
		// Local decompilation checkbox changed.
		case 1:
			fa.get_checkbox_value(fid, &isLocalActivated);
			fa.enable_field(3, isLocalActivated);
			fa.enable_field(4, !isLocalActivated);
			break;
		// API decompilation checkbox changed.
		case 2:
			fa.get_checkbox_value(fid, &isApiActivated);
			fa.enable_field(3, !isApiActivated);
			fa.enable_field(4, isApiActivated);
			break;
		default:
			break;
	}

	return 1;
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
		"%/"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"<##Select the decompilation mode to use##Local decompilation (RetDec must be installed):R1>\n"
		"<Remote API decompilation (your data are sent to the RetDec server):R2>>\n"
		"\n"
		"Path to decompile.sh (unnecessary if it is in the system PATH):\n"
		"<:f3:1:64::>\n"
		"\n"
		"API URL   %A\n"
		"<API key:A4::50::>\n"
		"\n";

	int decMode = rdgi.isApiDecompilation() ? 1 : 0;
	char cApiKey[MAXSTR] = {};
	char cDecompileSh[QMAXPATH] = {};

	if (rdgi.decompileShPath.empty())
	{
		std::string pattern = "decompile.sh";
		std::copy(pattern.begin(), pattern.begin() + QMAXPATH, cDecompileSh);
	}
	else
	{
		std::copy(rdgi.decompileShPath.begin(), rdgi.decompileShPath.begin() + QMAXPATH, cDecompileSh);
	}
	std::copy(rdgi.apiKey.begin(), rdgi.apiKey.begin() + MAXSTR, cApiKey);

	if (AskUsingForm_c(format, modcb, &decMode, cDecompileSh, rdgi.apiUrl.c_str(), cApiKey) == 0)
	{
		// ESC or CANCEL
		return true;
	}
	else
	{
		rdgi.apiKey = cApiKey;
		rdgi.decompileShPath = cDecompileSh;
		rdgi.setIsLocalDecompilation(decMode == 0);
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
