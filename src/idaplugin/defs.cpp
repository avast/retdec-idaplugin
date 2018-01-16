/**
 * @file idaplugin/defs.cpp
 * @brief Plugin-global definitions and includes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "defs.h"
#include "plugin_config.h"

namespace idaplugin {

RdGlobalInfo::RdGlobalInfo()
{
	pluginInfo.id = pluginID.data();
	pluginInfo.name = pluginName.data();
	pluginInfo.producer = pluginProducer.data();
	pluginInfo.version = pluginVersion.data();
	pluginInfo.url = pluginContact.data();
	pluginInfo.freeform = pluginCopyright.data();

	navigationActual = navigationList.end();

	pluginConfigFile = get_user_idadir();
#ifdef OS_WINDOWS
	pluginConfigFile += "\\" + pluginConfigFileName;
#else // Linux
	pluginConfigFile += "/" + pluginConfigFileName;
#endif
}

bool RdGlobalInfo::isAllDecompilation()
{
	return !outputFile.empty();
}

bool RdGlobalInfo::isSelectiveDecompilation()
{
	return !isAllDecompilation();
}

bool RdGlobalInfo::isDecompileShInSystemPath() const
{
#ifdef OS_WINDOWS
	return std::system("sh retdec-decompiler.sh --help") == 0;
#else
	return std::system("retdec-decompiler.sh --help") == 0;
#endif
}

bool RdGlobalInfo::isDecompileShInSpecifiedPath() const
{
	std::string cmd = "'" + decompileShPath + "'" + " --help";
#ifdef OS_WINDOWS
	cmd = "sh " + cmd;
#endif
	return std::system(cmd.c_str()) == 0;
}

bool RdGlobalInfo::isApiKeyOk() const
{
	return !apiKey.empty();
}

bool RdGlobalInfo::isApiUrlOk() const
{
	return !apiUrl.empty();
}

bool RdGlobalInfo::isUseThreads() const
{
	return useThreads;
}

void RdGlobalInfo::setIsUseThreads(bool f)
{
	useThreads = f;
}

bool RdGlobalInfo::isLocalDecompilation() const
{
	return locaDecomp;
}

void RdGlobalInfo::setIsLocalDecompilation(bool f)
{
	locaDecomp = f;
}

bool RdGlobalInfo::isApiDecompilation() const
{
	return !isLocalDecompilation();
}

void RdGlobalInfo::setIsApiDecompilation(bool f)
{
	locaDecomp = !f;
}

/**
 * @return @c True if canceled, @c false otherwise.
 */
bool RdGlobalInfo::configureDecompilation()
{
	if (isLocalDecompilation() && isDecompileShInSystemPath())
	{
		INFO_MSG("retdec-decompiler.sh in system PATH -> using local decompilation\n");
		decompilationShCmd = "retdec-decompiler.sh";
		return false;
	}
	else if (isLocalDecompilation() && isDecompileShInSpecifiedPath())
	{
		INFO_MSG("retdec-decompiler.sh at %s -> using local decompilation\n", decompileShPath.c_str());
		decompilationShCmd = decompileShPath;
		return false;
	}
	else if (isApiDecompilation() && isApiKeyOk() && isApiUrlOk())
	{
		INFO_MSG("API key and URL ok -> using remote API decompilation");
		return false;
	}
	else
	{
		warning("Decompilation is not properly configured.\n"
				"Either retdec-decompiler.sh must be in system PATH,\n"
				"or path to retdec-decompiler.sh must be provided in configuration menu,\n"
				"or API key and URL must be set.");
		auto canceled = pluginConfigurationMenu(*this);
		if (canceled)
		{
			return canceled;
		}
		else
		{
			return configureDecompilation();
		}
	}
}

} // namespace idaplugin
