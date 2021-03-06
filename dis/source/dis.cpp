#include "spvgentwo/Logger.h"
#include "spvgentwo/Module.h"
#include "spvgentwo/Grammar.h"
#include "common/HeapAllocator.h"
#include "common/BinaryFileWriter.h"
#include "common/BinaryFileReader.h"
#include "common/ConsoleLogger.h"
#include "common/ModulePrinter.h"

#include <cstring>

#ifndef NDEBUG
#include <cstdlib> // system
#endif // !_NDEBUG

using namespace spvgentwo;
using namespace ModulePrinter;

int main(int argc, char* argv[])
{
	ConsoleLogger logger;

	const char* spv = nullptr;
	const char* tabs = "\t\t";
	bool serialize = false; // for debugging
	bool reassignIDs = false;
	bool callSPIRVDis = false;
	bool colors = true;

	PrintOptions options{ PrintOptionsBits::All };

	for (int i = 1u; i < argc; ++i)
	{
		const char* arg = argv[i];
		if (spv == nullptr)
		{
			spv = arg;
		}
		else if (strcmp(arg, "--serialize") == 0)
		{
			serialize = true;
		}
		else if (strcmp(arg, "--assignIDs") == 0 || strcmp(arg, "--assignids") == 0)
		{
			reassignIDs = true;
		}
		else if (strcmp(arg, "--calldis") == 0)
		{
			callSPIRVDis = true;
		}
		else if (strcmp(arg, "--noinstrnames") == 0)
		{
			options ^= PrintOptionsBits::InstructionName;
		}
		else if (strcmp(arg, "--noopnames") == 0)
		{
			options ^= PrintOptionsBits::OperandName;
		}
		else if (strcmp(arg, "--nopreamble") == 0)
		{
			options ^= PrintOptionsBits::Preamble;
		}
		else if (strcmp(arg, "--nocolors") == 0)
		{
			colors = false;
		}
		else if (i+1 < argc && strcmp(arg, "--tabs") == 0)
		{
			tabs = argv[++i];
		}
	}

	if (spv == nullptr)
	{
		return -1;
	}

	HeapAllocator alloc;

#ifndef NDEBUG
	if (callSPIRVDis)
	{
		String cmd(&alloc, "spirv-dis ");
		cmd += spv;
		system(cmd.c_str());
	}
#endif

	if (BinaryFileReader reader(spv); reader.isOpen())
	{
		Module module(&alloc, spv::Version, &logger);
		Grammar gram(&alloc);

		// parse the binary instructions & operands
		if (module.read(&reader, gram) == false)
		{
			return -1;
		}

		// turn <id> operands into instruction pointers
		if (module.resolveIDs() == false)
		{
			return -1;
		}

		// creates type & constant infos for lookup (needed for codegen)
		if (module.reconstructTypeAndConstantInfo() == false)
		{
			return -1;
		}

		// parses strings for lookup of named instructions, needed for printing
		if (module.reconstructNames() == false)
		{
			return -1;
		}

		if (reassignIDs)
		{
			module.assignIDs(); // compact ids
		}

		auto printer = ModulePrinter::ModuleSimpleFuncPrinter([](const char* _pStr) { printf("%s", _pStr);	}, colors);
		const bool success = ModulePrinter::printModule(module, gram, printer, options, tabs);

		if (success == false)
		{
			return -1;
		}

		if (serialize)
		{
			if (BinaryFileWriter writer("serialized.spv"); writer.isOpen())
			{
				module.write(&writer);
			}
		}
	}
	else
	{
		logger.logError("Failed to open %s", spv);
	}

	return 0;
}