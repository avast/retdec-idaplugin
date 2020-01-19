/**
 * @file idaplugin/plugin_config.cpp
 * @brief Module deals with RetDec plugin configuration.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#include <rapidjson/document.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/writer.h>

#include "retdec/utils/file_io.h"
#include "retdec/utils/string.h"
#include "plugin_config.h"

namespace {

const std::string JSON_decompilerPyPath = "decompilerPyPath";
const std::string JSON_pythonInterpreterPath = "pythonInterpreterPath";
const std::string JSON_pythonInterpreterArgs = "pythonInterpreterArgs";

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
		rapidjson::Document& root,
		bool silent = true)
{
	rapidjson::ParseResult success = root.Parse(json);
	if (!success)
	{
		return false;
	}

	return true;
}

/**
 * Get root value from the provided JSON file.
 * @param[in]  file   JSON file.
 * @param[out] root   JSON root value to get from config.
 * @return @c False is @a root value read ok, @c true otherwise.
 */
bool getConfigRootFromFile(
		const std::string& file,
		rapidjson::Document& root)
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
	rapidjson::Document root;

	if (getConfigRootFromFile(rdgi.pluginConfigFile.getPath(), root))
	{
		return true;
	}

	rdgi.decompilerPyPath = root.HasMember(JSON_decompilerPyPath) ? root[JSON_decompilerPyPath].GetString() : "";
	rdgi.pythonInterpreter = root.HasMember(JSON_pythonInterpreterPath) ? root[JSON_pythonInterpreterPath].GetString() : "";
	rdgi.pythonInterpreterArgs = root.HasMember(JSON_pythonInterpreterArgs) ? root[JSON_pythonInterpreterArgs].GetString() : "";

	return false;
}

/**
 * Save plugin's configuration into provided JSON file.
 * File content is rewritten.
 * @param rdgi Plugin's global information.
 */
void saveConfigTofile(RdGlobalInfo& rdgi)
{
	rapidjson::Document root;

	if (getConfigRootFromFile(rdgi.pluginConfigFile.getPath(), root))
	{
		// Problem when reading config -- does not matter, we use empty root.
	}

	rapidjson::Value decPath(JSON_decompilerPyPath, root.GetAllocator());
	decPath = rapidjson::StringRef(rdgi.decompilerPyPath);

	rapidjson::Value pyInt(JSON_pythonInterpreterPath, root.GetAllocator());
	pyInt = rapidjson::StringRef(rdgi.pythonInterpreter);

	rapidjson::Value pyIntArgs(JSON_pythonInterpreterArgs, root.GetAllocator());
	pyIntArgs = rapidjson::StringRef(rdgi.pythonInterpreterArgs);

	std::ofstream jsonFile(rdgi.pluginConfigFile.getPath().c_str());
	rapidjson::OStreamWrapper osw(jsonFile);

	rapidjson::Writer<rapidjson::OStreamWrapper> writer(osw);
	root.Accept(writer);
}

/**
 * Present plugin configuration form to developer.
 * @param rdgi Plugin's global information.
 * @return @c True if cancelled, @c false otherwise.
 */
bool askUserToConfigurePlugin(RdGlobalInfo& rdgi)
{
	char cDecompilerPy[QMAXPATH];
	char cPythonInterpreter[QMAXPATH];

	if (rdgi.decompilerPyPath.empty())
	{
		std::string pattern = rdgi.decompilerPyName;
		std::copy(pattern.begin(), pattern.begin() + QMAXPATH, cDecompilerPy);
	}
	else
	{
		std::copy(
				rdgi.decompilerPyPath.begin(),
				rdgi.decompilerPyPath.begin() + QMAXPATH,
				cDecompilerPy);
	}

	if (rdgi.pythonInterpreter.empty())
	{
		std::string tmp = "python3";
		std::copy(
				tmp.begin(),
				tmp.begin() + QMAXPATH,
				cPythonInterpreter);
	}
	else
	{
		std::copy(
				rdgi.pythonInterpreter.begin(),
				rdgi.pythonInterpreter.begin() + QMAXPATH,
				cPythonInterpreter);
	}

	qstring formRetDecPluginSettings =
		"RetDec Plugin Settings\n"
		"\n"
		"\n"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"Path to %A (unnecessary if it is in the system PATH):\n"
		"<RetDec script:f1::60:::>\n"
		"\n"
		"Path to Python interpreter version >= 3.4 (unnecessary if it is in the system PATH):\n"
		"<Python interpreter:f2::60:::>\n"
		"\n";

	int ok = ask_form(formRetDecPluginSettings.c_str(),
		rdgi.decompilerPyName.c_str(),
		cDecompilerPy,
		cPythonInterpreter,
		&cDecompilerPy,
		&cPythonInterpreter
		);

	if (ok == 0)
	{
		// ESC or CANCEL
		return true;
	}
	else
	{
		rdgi.decompilerPyPath = cDecompilerPy;
		rdgi.pythonInterpreter = cPythonInterpreter;
		rdgi.pythonInterpreterArgs = "";
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
 * @return @c False if success, @c true otherwise.
 */
bool addConfigurationMenuOption(RdGlobalInfo& rdgi)
{
	char optionsActionName[] = "retdec:ShowOptions";
	char optionsActionLabel[] = "RetDec plugin options...";

	static show_options_ah_t show_options_ah(&rdgi);

	static const action_desc_t desc = ACTION_DESC_LITERAL(
			optionsActionName,
			optionsActionLabel,
			&show_options_ah,
			nullptr,
			NULL,
			-1);

	if (!register_action(desc)
			|| !attach_action_to_menu(
					"Options/SourcePaths",
					optionsActionName,
					SETMENU_APP)
			|| !attach_action_to_menu(
					"Options/SourcePaths",
					"-",
					SETMENU_APP))
	{
		ERROR_MSG("Failed to register Options menu item for RetDec plugin!\n");
		return true;
	}

	return false;
}

} // namespace idaplugin
