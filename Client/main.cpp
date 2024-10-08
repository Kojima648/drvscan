#define _CRT_SECURE_NO_WARNINGS
#include "scan/scan.h"
#include <chrono>

int main(int argc, char **argv)
{
	//
	// reset font
	//
	FontColor(7);

	if (!cl::initialize())
	{
		LOG("驱动程序未运行\n");  // driver is not running
		printf("按任意键继续 . . .");
		return getchar();
	}

	if (argc < 2)
	{
		LOG("--帮助\n");  // --help
		return getchar();
	}

	DWORD scan = 0, pid = 4, savecache = 0, scanpci = 0, advanced=0, block=0, cfg=0, use_cache = 0, scanefi = 0, dump = 0, scanmouse=0, log = 0;
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                 扫描目标进程内存变化\n"
				"    --pid              (可选) 目标进程ID\n"
				"    --usecache         (可选) 我们使用本地缓存而不是原始的PE文件\n"
				"    --savecache        (可选) 将目标进程模块保存到磁盘\n\n"
				"--scanefi              扫描EFI内存映射中的异常\n"
				"    --dump             (可选) 将发现的异常保存到磁盘\n\n"
				"--scanpci              扫描系统中的PCI卡\n"
				"    --advanced         (可选) 测试PCI功能\n"
				"    --block            (可选) 阻止非法卡\n"
				"    --cfg              (可选) 输出每个卡的配置空间\n"
				"--scanmouse            通过监控鼠标数据包捕获自动瞄准外挂\n"
				"    --log              (可选) 输出每个鼠标数据包\n\n\n"
			);

			printf("\n示例（通过使用缓存验证模块完整性）:\n"
				"1.                     加载恶意软件\n"
				"2.                     drvscan.exe --scan --savecache --pid 4\n"
				"3.                     重启计算机\n"
				"4.                     加载无恶意软件的Windows\n"
				"5.                     drvscan.exe --scan --usecache --pid 4\n"
				"所有恶意软件的补丁现在都应该可见\n\n"
			);
		}

		else if (!strcmp(argv[i], "--scan"))
		{
			scan = 1;
		}

		else if (!strcmp(argv[i], "--pid"))
		{
			pid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--savecache"))
		{
			savecache = 1;
		}

		else if (!strcmp(argv[i], "--scanpci"))
		{
			scanpci = 1;
		}

		else if (!strcmp(argv[i], "--scanmouse"))
		{
			scanmouse = 1;
		}

		else if (!strcmp(argv[i], "--log"))
		{
			log = 1;
		}

		else if (!strcmp(argv[i], "--advanced"))
		{
			advanced = 1;
		}

		else if (!strcmp(argv[i], "--block"))
		{
			block = 1;
		}

		else if (!strcmp(argv[i], "--cfg"))
		{
			cfg = 1;
		}

		else if (!strcmp(argv[i], "--scanefi"))
		{
			scanefi = 1;
		}

		else if (!strcmp(argv[i], "--dump"))
		{
			dump = 1;
		}

		else if (!strcmp(argv[i], "--usecache"))
		{
			use_cache = 1;
		}
	}

	auto timer_start = std::chrono::high_resolution_clock::now();

	if (scanpci)
	{
		LOG("正在扫描PCIe设备\n\n");  // scanning PCIe devices
		scan::pci(block, advanced, cfg);
	}

	if (scan)
	{
		std::vector<FILE_INFO> modules;

		if (!cl::kernel_access && pid == 4)
		{
			for (auto& proc : get_system_processes())
			{
				if (!_strcmpi(proc.name.c_str(), "explorer.exe"))
				{
					pid = proc.id;
					break;
				}
			}
		}

		if (pid == 4)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		LOG("正在扫描模块\n");  // scanning modules
		for (auto mod : modules)
		{
			scan::image(savecache, modules, pid, mod, use_cache);
		}
	}

	if (scanefi)
	{
		LOG("正在扫描EFI\n");  // scanning EFI
		scan::efi(dump);
	}

	if (scanmouse)
	{
		LOG("正在监控鼠标\n");  // monitoring mouse
		scan::mouse(log);
	}

	auto timer_end = std::chrono::high_resolution_clock::now() - timer_start;

	if (scanefi+scan+scanpci)
		LOG("扫描完成 [%lldms]\n",  // scan is complete [%lldms]
			std::chrono::duration_cast<std::chrono::milliseconds>(timer_end).count());

	//
	// 添加水印
	//
	PRINT_GREEN("\n # 结果仅供参考，请自行承担任何风险！");
	PRINT_BLUE("\n # 此工具免费 原创: ekknod(github)  汉化: 梦遥无归期(哔哩哔哩)");
	PRINT_BLUE("\n # 构建时间: 2024年10月8日21:32:56 \n");


	cl::terminate();

	return 0;
}

