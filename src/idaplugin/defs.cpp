/**
 * @file idaplugin/defs.cpp
 * @brief Plugin-global definitions and includes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "defs.h"
#include "plugin_config.h"

#if defined(OS_WINDOWS)
	#include <windows.h>
#endif

namespace idaplugin {

/**
 * Run command using IDA SDK API.
 */
int runCommand(
		const std::string& cmd,
		const std::string& args,
		intptr_t* pid,
		bool showWarnings)
{
	launch_process_params_t procInf;
	procInf.path = cmd.c_str();
	procInf.args = args.c_str();
	procInf.flags = LP_HIDE_WINDOW;
#if defined(OS_WINDOWS)
	PROCESS_INFORMATION pi{};
	procInf.info = &pi;
#endif

	qstring errbuf;

	void* p = launch_process(procInf, &errbuf);
	if (p == nullptr)
	{
		warning("launch_process(%s %s) failed to launch %S\n",
				procInf.path,
				procInf.args,
				errbuf.c_str());
		return 1;
	}
	if (pid)
	{
#if defined(OS_WINDOWS)
	*pid = pi.dwProcessId;
#else // Linux || macOS
	*pid = reinterpret_cast<intptr_t>(p);
#endif
	}

	int rc;
	auto cpe = check_process_exit(p, &rc, 1);
	if (pid)
	{
		*pid = 0;
	}
	if (cpe != 0)
	{
		if (showWarnings)
		{
			warning("Error in check_process_exit() while executing: %s %s\n",
					procInf.path,
					procInf.args);
		}
		return 1;
	}

	if (rc != 0)
	{
		if (showWarnings)
		{
			warning("launch_process(%s %s) failed with error code %d\n",
					procInf.path,
					procInf.args,
					rc);
		}

		return 1;
	}

	return 0;
}

RdGlobalInfo::RdGlobalInfo() :
		pluginConfigFile(get_user_idadir())
{
	pluginInfo.id = pluginID.data();
	pluginInfo.name = pluginName.data();
	pluginInfo.producer = pluginProducer.data();
	pluginInfo.version = pluginVersion.data();
	pluginInfo.url = pluginContact.data();
	pluginInfo.freeform = pluginCopyright.data();

	navigationActual = navigationList.end();

	pluginConfigFile.append(pluginConfigFileName);
}

bool RdGlobalInfo::isAllDecompilation()
{
	return !outputFile.empty();
}

bool RdGlobalInfo::isSelectiveDecompilation()
{
	return !isAllDecompilation();
}

/**
 * Find out how to (which command) execute the python interpreter.
 * @return @c False if python command initialized successfully,
 *         @c true otherwise.
 */
bool RdGlobalInfo::initPythonCommand()
{
	if (!pythonInterpreter.empty())
	{
		// Python interpreter was already initialized. Do not rewrite it here
		// even if it does not work - it could have been read from config, or
		// set by user.
		return false;
	}

	if (runCommand("python3", "--version") == 0)
	{
		pythonInterpreter = "python3";
		return false;
	}
	else if (runCommand("py", "-3 --version") == 0)
	{
		pythonInterpreter = "py -3";
		return false;
	}
	else if (runCommand("python", "--version") == 0)
	{
		pythonInterpreter = "python";
		return false;
	}

	return true;
}

/**
 * Check that the selected Python command is in fact running an expected
 * Python version.
 * @return @c False if python command ok,
 *         @c true otherwise.
 */
bool RdGlobalInfo::checkPythonCommand()
{
	return runCommand(
			pythonInterpreter,
			"-c \"import sys; sys.exit(0 if sys.version_info >= (3,4) else 1)\"");
}

bool RdGlobalInfo::isDecompilerInSpecifiedPath() const
{
	return runCommand(pythonInterpreter, "\"" + decompilerPyPath + "\" --help") == 0;
}

bool RdGlobalInfo::isDecompilerInSystemPath()
{
	char buff[MAXSTR];
	if (search_path(buff, sizeof(buff), decompilerPyName.c_str(), false))
	{
		if (runCommand(pythonInterpreter, "\"" + std::string(buff) + "\" --help") == 0)
		{
			decompilerPyPath = buff;
			return true;
		}
	}

	return false;
}

bool RdGlobalInfo::isUseThreads() const
{
	return useThreads;
}

void RdGlobalInfo::setIsUseThreads(bool f)
{
	useThreads = f;
}

/**
 * @return @c True if canceled, @c false otherwise.
 */
bool RdGlobalInfo::configureDecompilation()
{
	if (initPythonCommand())
	{
		warning("Unable to execute Python interpreter.\n"
				"Make sure Python version >= 3.4 is properly installed.");

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

	if (checkPythonCommand())
	{
		qstring path;
		qgetenv("PATH", &path);

		warning("Found Python interpreter of incompatible version: \"%s\".\n"
				"The RetDec IDA plugin requires Python version >= 3.4.\n"
				"Used PATH: \"%s\"",
				pythonInterpreter.c_str(),
				path.c_str());

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

	if (isDecompilerInSpecifiedPath())
	{
		INFO_MSG("Found %s at %s -> plugin is properly configured.\n",
				decompilerPyName.c_str(),
				decompilerPyPath.c_str());
		decompilationCmd = decompilerPyPath;
		return false;
	}
	else if (isDecompilerInSystemPath())
	{
		INFO_MSG("Found %s at system PATH %s -> plugin is properly configured.\n",
				decompilerPyName.c_str(),
				decompilerPyPath.c_str());
		decompilationCmd = decompilerPyPath;
		return false;
	}
	else
	{
		warning("Decompilation is not properly configured.\n"
				"The path to %s must be provided in the configuration menu.",
				decompilerPyName.c_str());
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
