//
// run by:
//     idal -A -S"retdec-decompile-full.idc <path>/input.exe [--debug]" <path>/input.exe
//
// output:
//     <path>/input.exe.c
//

#include <idc.idc>

static main()
{
	Message("[RD]\tWaiting for the end of the auto analysis...\n");
	Wait();

	if (ARGV.count != 2 && ARGV.count != 3)
	{
		Message("[RD]\tScript usage: retdec-decompile-full.idc <path>/input.exe [--debug]\n");
		Exit(1);
	}
	if (ARGV.count == 3)
	{
		if (ARGV[2] != "--debug")
		{
			Message("[RD]\tScript usage: retdec-decompile-full.idc <path>/input.exe [--debug]\n");
			Exit(1);
		}
	}

	auto in = ARGV[1];
	SetInputFilePath(in);

	auto debug = (ARGV.count == 3);

	auto ret = 0;
	Message("[RD]\tRun Retargetable Decompiler...\n");
	if (RunPlugin("retdec", 3))
	{
		Message("[RD]\tOK: plugin run\n");
	}
	else
	{
		Message("[RD]\tFAIL: plugin run\n");
		ret = 1;
	}

	Message("[RD]\tAll done, exiting...\n");

	if (debug)
	{
		Message("[RD]\tAll done, exit code = %d\n", ret);
	}
	else
	{
		Exit(ret);
	}
}
