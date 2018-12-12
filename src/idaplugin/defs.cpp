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
		if (showWarnings)
		{
			WARNING_GUI("launch_process(" << procInf.path << " "
					<< procInf.args << ") failed to launch " << errbuf.c_str()
					<< "\n");
		}
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
			WARNING_GUI("Error in check_process_exit() while executing: "
					<< procInf.path << " " << procInf.args << "\n");
		}
		return 1;
	}

	if (rc != 0)
	{
		if (showWarnings)
		{
			WARNING_GUI("launch_process(" << procInf.path << " " << procInf.args
					<< ") failed with error code " << rc << "\n");
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

#ifdef OS_WINDOWS
	pluginConfigFile.append("\\" + pluginConfigFileName);
#else // Linux & macOS
	pluginConfigFile.append("/" + pluginConfigFileName);
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
		pythonInterpreterArgs = "";
		return false;
	}
	else if (runCommand("py", "-3 --version") == 0)
	{
		pythonInterpreter = "py";
		pythonInterpreterArgs = "-3 ";
		return false;
	}
	else if (runCommand("python", "--version") == 0)
	{
		pythonInterpreter = "python";
		pythonInterpreterArgs = "";
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
			pythonInterpreterArgs + "-c \"import sys; sys.exit(0 if sys.version_info >= (3,4) else 1)\"");
}

bool RdGlobalInfo::isDecompilerInSpecifiedPath() const
{
	return runCommand(
			pythonInterpreter,
			pythonInterpreterArgs + "\"" + decompilerPyPath + "\" --help") == 0;
}

bool RdGlobalInfo::isDecompilerInSystemPath()
{
	char buff[MAXSTR];
	if (search_path(buff, sizeof(buff), decompilerPyName.c_str(), false))
	{
		if (runCommand(
				pythonInterpreter,
				pythonInterpreterArgs + "\"" + std::string(buff) + "\" --help") == 0)
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
		WARNING_GUI("Unable to execute Python interpreter.\n"
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

		WARNING_GUI("Found Python interpreter of incompatible version: \""
				<< pythonInterpreter << "\".\n"
				"The RetDec IDA plugin requires Python version >= 3.4.\n"
				"Used PATH: \"" << path.c_str() << "\"");

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
		INFO_MSG("Found " << decompilerPyName << " at " << decompilerPyPath
				<< " -> plugin is properly configured.\n");
		decompilationCmd = decompilerPyPath;
		return false;
	}
	else if (isDecompilerInSystemPath())
	{
		INFO_MSG("Found " << decompilerPyName << " at system PATH "
				<< decompilerPyPath << " -> plugin is properly configured.\n");
		decompilationCmd = decompilerPyPath;
		return false;
	}
	else
	{
		WARNING_GUI("Decompilation is not properly configured.\n"
				"The path to " << decompilerPyName << " must be provided in the configuration menu.");
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
