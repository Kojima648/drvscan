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
		LOG("��������δ����\n");  // driver is not running
		printf("����������� . . .");
		return getchar();
	}

	if (argc < 2)
	{
		LOG("--����\n");  // --help
		return getchar();
	}

	DWORD scan = 0, pid = 4, savecache = 0, scanpci = 0, advanced=0, block=0, cfg=0, use_cache = 0, scanefi = 0, dump = 0, scanmouse=0, log = 0;
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                 ɨ��Ŀ������ڴ�仯\n"
				"    --pid              (��ѡ) Ŀ�����ID\n"
				"    --usecache         (��ѡ) ����ʹ�ñ��ػ��������ԭʼ��PE�ļ�\n"
				"    --savecache        (��ѡ) ��Ŀ�����ģ�鱣�浽����\n\n"
				"--scanefi              ɨ��EFI�ڴ�ӳ���е��쳣\n"
				"    --dump             (��ѡ) �����ֵ��쳣���浽����\n\n"
				"--scanpci              ɨ��ϵͳ�е�PCI��\n"
				"    --advanced         (��ѡ) ����PCI����\n"
				"    --block            (��ѡ) ��ֹ�Ƿ���\n"
				"    --cfg              (��ѡ) ���ÿ���������ÿռ�\n"
				"--scanmouse            ͨ�����������ݰ������Զ���׼���\n"
				"    --log              (��ѡ) ���ÿ��������ݰ�\n\n\n"
			);

			printf("\nʾ����ͨ��ʹ�û�����֤ģ�������ԣ�:\n"
				"1.                     ���ض������\n"
				"2.                     drvscan.exe --scan --savecache --pid 4\n"
				"3.                     ���������\n"
				"4.                     �����޶��������Windows\n"
				"5.                     drvscan.exe --scan --usecache --pid 4\n"
				"���ж�������Ĳ������ڶ�Ӧ�ÿɼ�\n\n"
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
		LOG("����ɨ��PCIe�豸\n\n");  // scanning PCIe devices
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

		LOG("����ɨ��ģ��\n");  // scanning modules
		for (auto mod : modules)
		{
			scan::image(savecache, modules, pid, mod, use_cache);
		}
	}

	if (scanefi)
	{
		LOG("����ɨ��EFI\n");  // scanning EFI
		scan::efi(dump);
	}

	if (scanmouse)
	{
		LOG("���ڼ�����\n");  // monitoring mouse
		scan::mouse(log);
	}

	auto timer_end = std::chrono::high_resolution_clock::now() - timer_start;

	if (scanefi+scan+scanpci)
		LOG("ɨ����� [%lldms]\n",  // scan is complete [%lldms]
			std::chrono::duration_cast<std::chrono::milliseconds>(timer_end).count());

	//
	// ���ˮӡ
	//
	PRINT_GREEN("\n # ��������ο��������ге��κη��գ�");
	PRINT_BLUE("\n # �˹������ ԭ��: ekknod(github)  ����: ��ң�޹���(��������)");
	PRINT_BLUE("\n # ����ʱ��: 2024��10��8��21:32:56 \n");


	cl::terminate();

	return 0;
}

