//
// run by:
//     idal -A -S"retdec-decompile-selective.idc <path>/input.exe <address inside function> [--debug]" <path>/input.exe
//
// output:
//     <path>/input.exe.c
//
// note:
//     It is not possible to effectively change ASM position from this script.
//     Jump(ea) takes effect only after IDC script is finished.
//     Therefore, we can not use this simple mechanism (current position) to
//     select function to decompile.
//     We use hack to inform plugin which function to decompile:
//     Tag the function with "<retdec_select>" comment -> run plugin -> reset
//     comment to original.
//     Invoked plugin option must find tagged function and decompile it.
//

#include <idc.idc>

static main()
{
	Message("[RD]\tWaiting for the end of the auto analysis...\n");
	Wait();

	if (ARGV.count != 3&& ARGV.count != 4)
	{
		Message("[RD]\tScript usage: retdec-decompile-selective.idc <path>/input.exe <address inside function> [--debug]\n");
		Exit(1);
	}
	if (ARGV.count == 4)
	{
		if (ARGV[3] != "--debug")
		{
			Message("[RD]\tScript usage: retdec-decompile-selective.idc <path>/input.exe <address inside function> [--debug]\n");
			Exit(1);
		}
	}

	auto in = ARGV[1];
	SetInputFilePath(in);

	auto ea = ARGV[2];

	auto debug = (ARGV.count == 4);

	if (GetFunctionFlags(ea) == -1)
	{
		Message("[RD]\tFunction @ %a does NOT exist.\n", ea);
		if (!debug)
		{
			Exit(1);
		}
	}
	else
	{
		Message("[RD]\tFunction @ %a DOES exist.\n", ea);

		auto regular = 0; // non-repeatable
		auto cmt = GetFunctionCmt(ea, regular);
		SetFunctionCmt(ea, cmt+"<retdec_select>", regular);

		auto ret = 0;
		Message("[RD]\tRun Retargetable Decompiler...\n");
		if (RunPlugin("retdec", 4))
		{
			Message("[RD]\tOK: plugin run\n");
		}
		else
		{
			Message("[RD]\tFAIL: plugin run\n");
			ret = 1;
		}

		SetFunctionCmt(ea, cmt, regular);

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
}
