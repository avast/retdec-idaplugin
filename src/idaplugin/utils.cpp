
#include <fstream>

#include <retdec/utils/filesystem.h>

#include "utils.h"

bool isRelocatable()
{
	if (inf_get_filetype() == f_COFF && inf_get_start_ea() == BADADDR)
	{
		return true;
	}
	else if (inf_get_filetype() == f_ELF)
	{
		auto inFile = getInputPath();
		if (inFile.empty())
		{
			return false;
		}

		std::ifstream infile(inFile, std::ios::binary);
		if (infile.good())
		{
			std::size_t e_type_offset = 0x10;
			infile.seekg(e_type_offset, std::ios::beg);

			// relocatable -- constant 0x1 at <0x10-0x11>
			// little endian -- 0x01 0x00
			// big endian -- 0x00 0x01
			char b1 = 0;
			char b2 = 0;
			if (infile.get(b1))
			{
				if (infile.get(b2))
				{
					if (std::size_t(b1) + std::size_t(b2) == 1)
					{
						return true;
					}
				}
			}
		}
	}

	// f_BIN || f_PE || f_HEX || other
	return false;
}

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
		fs::path fsIdb(idb);
		workDir = fsIdb.parent_path();
	}
	else if (!id0.empty())
	{
		fs::path fsId0(id0);
		workDir = fsId0.root_path();
	}
	if (workDir.empty())
	{
		return std::string();
	}

	if (!fs::exists(inPath))
	{
		fs::path fsWork(workDir);
		fsWork.append(inName);
		inPath = fsWork.string();

		if (!fs::exists(inPath))
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
			if (!fs::exists(std::string(tmp)))
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
