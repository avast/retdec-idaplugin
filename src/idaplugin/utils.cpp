
#include <retdec/utils/filesystem_path.h>

#include "utils.h"

bool isX86()
{
	std::string procName = inf_get_procname().c_str();
	return procName == "80386p"
			|| procName == "80386r"
			|| procName == "80486p"
			|| procName == "80486r"
			|| procName == "80586p"
			|| procName == "80586r"
			|| procName == "80686p"
			|| procName == "p2"
			|| procName == "p3"
			|| procName == "p4"
			|| procName == "metapc";
}

std::string getInputPath()
{
	char buff[MAXSTR];

	get_root_filename(buff, sizeof(buff));
	std::string inName = buff;

	get_input_file_path(buff, sizeof(buff));
	std::string inPath = buff;

	std::string idb = get_path(PATH_TYPE_IDB);
	std::string id0 = get_path(PATH_TYPE_ID0);
	std::string workDir;
	if (!idb.empty())
	{
		retdec::utils::FilesystemPath fsIdb(idb);
		workDir = fsIdb.getParentPath();
	}
	else if (!id0.empty())
	{
		retdec::utils::FilesystemPath fsId0(id0);
		workDir = fsId0.getParentPath();
	}
	if (workDir.empty())
	{
		return std::string();
	}

	if (!retdec::utils::FilesystemPath(inPath).exists())
	{
		retdec::utils::FilesystemPath fsWork(workDir);
		fsWork.append(inName);
		inPath = fsWork.getPath();

		if (!retdec::utils::FilesystemPath(inPath).exists())
		{
			char *tmp = ask_file(                ///< Returns: file name
					false,                       ///< bool for_saving
					nullptr,                     ///< const char *default_answer
					"%s",                        ///< const char *format
					"Input binary to decompile"
			);

			if (tmp == nullptr)
			{
				return std::string();
			}
			if (!retdec::utils::FilesystemPath(std::string(tmp)).exists())
			{
				return std::string();
			}

			inPath = tmp;
		}
	}

	return inPath;
}

void saveIdaDatabase(bool inSitu, const std::string& suffix)
{
	INFO_MSG("Saving IDA database ...\n");

	std::string workIdb = get_path(PATH_TYPE_IDB);
	if (workIdb.empty())
	{
		return;
	}

	auto dotPos = workIdb.find_last_of(".");
	if (dotPos != std::string::npos)
	{
		workIdb.erase(dotPos, std::string::npos);
	}

	if (!inSitu)
	{
		workIdb += suffix;
	}

	workIdb += std::string(".") + IDB_EXT;

	save_database(workIdb.c_str(), DBFL_COMP);

	INFO_MSG("IDA database saved into :  " << workIdb << "\n");
}

func_t* getIdaFunc(const std::string& name)
{
	func_t* fnc = nullptr;

	for (unsigned i = 0; i < get_func_qty(); ++i)
	{
		func_t* f = getn_func(i);
		qstring qFncName;
		get_func_name(&qFncName, f->start_ea);
		if (qFncName.c_str() == name)
		{
			fnc = f;
			break;
		}
	}

	return fnc;
}

ea_t getIdaFuncEa(const std::string& name)
{
	auto* fnc = getIdaFunc(name);
	return fnc ? fnc->start_ea : BADADDR;
}

ea_t getIdaGlobalEa(const std::string& name)
{
	// TODO
	return BADADDR;
}
