#include <iostream>
#include <windows.h>

IMAGE_DOS_HEADER myDosHeader;
IMAGE_NT_HEADERS myNTHeader;
IMAGE_FILE_HEADER myFileHeader;
IMAGE_OPTIONAL_HEADER myOptionHeader;
IMAGE_SECTION_HEADER* pmySectionHeader;
LONG e_lfanew;

int main(int argc, char* argv[])
{
	FILE* pfile;
	errno_t err;
	DWORD fielSize = 0;

	if ((err = fopen_s(&pfile, "C:\\Users\\Administrator\\Desktop\\notepad.exe", "r")) != 0)
	{
		printf("打开文件错误 ！");
		getchar();
	}

	//DOS头部分
	printf("=================================IMAGE_DOS_HEADER=========================\n");
	fread(&myDosHeader, 1, sizeof(IMAGE_DOS_HEADER), pfile);
	if (myDosHeader.e_magic != 0x5A4D)
	{
		printf("不是MZ开头的文件！！");
		fclose(pfile);
		exit(0);
	}

	printf("MZ头 \n\
				WORD e_magic 1*:           %4X\n", myDosHeader.e_magic);
	printf("指示NT头的偏移 \n\
				DWORD e_lfaner 2*:         %8X\n", myDosHeader.e_lfanew);

	e_lfanew = myDosHeader.e_lfanew;
	//NT头部分
	printf("=================================IMAGE_NT_HEADER===============================\n");
	fseek(pfile, e_lfanew, SEEK_SET);
	fread(&myNTHeader, 1, sizeof(IMAGE_NT_HEADERS), pfile);
	
	if (myNTHeader.Signature != 0x4550)
	{
		printf("文件有问题！！");
		fclose(pfile);
		exit(0);
	}

	printf("PE标识 DWORD Signature:                       %8X\n\n", myNTHeader.Signature);

	//FILE头部分
	printf("=================================IMAGE_FILE_HEADER===========================\n");

	printf("指出该PE文件运行的平台，每个CPU都有唯一的标识码，一般0x14c(x86) \n\
			WORD Machine 3*:                         %04X\n\n", myNTHeader.FileHeader.Machine);
	printf("指出文件中存在的节区数量 注：这一的定义一定要等于实际的大小，不然程序会运行失败 \n\
			WORD NumberOfSection 4*:                 %04X\n\n", myNTHeader.FileHeader.NumberOfSections);
	printf("PE文件的创建时间， 一般是由链接器填写UTC（世界标准时间）进行存贮， 从1970年1日00:00:00起算的秒数值 \n\
            我们可以用C语言的localtime()函数（时区也会转换）计算 \n\
			DWORD TimeDateStamp:                  %08x\n\n", myNTHeader.FileHeader.TimeDateStamp);
	printf("指向符号表COFF的指针， 用于调试信息， 发现每次看都是00 00 00 00 \n\
			DWORD pointerToSymbolTable            %08X\n\n", myNTHeader.FileHeader.PointerToSymbolTable);
	printf("符号表数量， 发现每次看都是00 00 00 00 \n\
			DWORD NumberOfSymbole:                %08X\n\n", myNTHeader.FileHeader.NumberOfSymbols);
	printf("指出PE的IMAGE_OPTIONAL_HEADER32结构体或PE+格式文件的IMAGE_OPTIONAL_HEADER64结构体的长度\n\
			这两个结构体尺寸是不相同的，所以需要在SizeOfOptionalHeader中指明大小，通常32位：EO \n\
			64位： F0（不是绝对的）他们只是最小值， 可能有更大的 \n\
			WORD SizeOfOptionHeader 5*:              %04X\n\n", myNTHeader.FileHeader.SizeOfOptionalHeader);
	printf("标识文件的属性，文件是否可运行，是否为DLL文件等， 二进制中每一位代表不同的属性，以bit, or 形式结合起来\n\
			2个需要记住的值 0002H： .exe文件， 2000h： .dll文件 \n\
			WORD Characteristics:                 %04X\n\n", myNTHeader.FileHeader.Characteristics);

	//OPTIONAL头部分
	printf("=================================IMAGE_OPTION_HEADER========================\n");

	printf("这个可选头的类型PE: 10Bh PE+: 20Bh 可以依次区分是32位还是64位 \n\
			WORD Magic 6*:                           %04X\n\n", myNTHeader.OptionalHeader.Magic); 
	printf("链接器的版本号（不重要） \n\
			BYTE MajorLinkerVersion:              %02X\n\n", myNTHeader.OptionalHeader.MajorLinkerVersion);
	printf("链接器的小版本号（不重要）\n\
			BYTE MinorLinkerVersion:              %02X\n\n", myNTHeader.OptionalHeader.MinorLinkerVersion);
	printf("代码段的长度  （由编译器填写 没用）\n\
			DWORD SizeOfCode:                     %08X\n\n", myNTHeader.OptionalHeader.SizeOfCode);
	printf("初始化的数据长度（由编译器填写 没用） \n\
			DWORD SizeOfInitializedData:          %08X\n\n", myNTHeader.OptionalHeader.SizeOfInitializedData);
	printf("未初始化的数据长度（由编译器填写 没用） \n\
			DWORD SizeOfUninitializeData:         %08X\n\n", myNTHeader.OptionalHeader.SizeOfUninitializedData);
	printf("程序EP的RVA 指出程序最先执行代码的起始地址（很重要） \n\
			DWORD AddressOfEntryPoint 7*:            %08X\n\n", myNTHeader.OptionalHeader.AddressOfEntryPoint);
	printf("代码段起始地址的RVA （由编译器填写 没用）\n\
			DWORD BaseOfCode                      %08X\n\n", myNTHeader.OptionalHeader.BaseOfCode);
	printf("数据段起始地址的RVA （由编译器填写 没用）\n\
			DWORD BaseOfDate                      %08X\n\n", myNTHeader.OptionalHeader.BaseOfData);
	printf("VA: 0-FFFFFFFF(32位系统)， PE文件加载到虚拟内存时， 指出文件优先装入地址\n\
			exe, dll文件被装载到0-7FFFFFFF SYS文件载入内核内存的 80000000-FFFFFFFF  \n\
			执行PE文件时， PE装载器会把EIP设置为 ImageBase + AddressOfEntrypoint \n\
			DWORD ImageBase 8*:                       %08X\n\n", myNTHeader.OptionalHeader.ImageBase);
	printf("内存对齐，节在内存中的最小单位， 一般为1000h \n\
			DWORD SectionAlignment 9*:               %08X\n\n", myNTHeader.OptionalHeader.SectionAlignment);
	printf("文件对齐，节在磁盘文件中的最小单位， 一般为200h \n\
			DWORD FileAlignment 10*:                  %08X\n\n", myNTHeader.OptionalHeader.FileAlignment);
	printf("操作系统主版本号（不重要）\n\
			WORD MajorOperatingSystemVersion:     %04X\n\n", myNTHeader.OptionalHeader.MajorOperatingSystemVersion);
	printf("操作系统小版本号（不重要）\n\
			WORD MinorOperationfSystemVersion:    %04X\n\n", myNTHeader.OptionalHeader.MinorOperatingSystemVersion);
	printf("映像文件主版本号， 这个是开发者自己指定的， 由链接器填写（不重要） \n\
			WORD MajorImageVersion:               %04X\n\n", myNTHeader.OptionalHeader.MajorImageVersion);
	printf("映像文件小版本号（不重要） \n\
			WORD MinorImageVerion:                %04X\n\n", myNTHeader.OptionalHeader.MinorImageVersion);
	printf("子系统版本号 \n\
			WORD MjorSubsystemVersion:            %04X\n\n", myNTHeader.OptionalHeader.MajorSubsystemVersion);
	printf("子系统小版本号 \n\
			WORD MinorSubsystemVersion:           %04X\n\n", myNTHeader.OptionalHeader.MinorSubsystemVersion);
	printf("Win32版本值 目前看过的值都是 00 00 00 00 \n\
			DWORD Win32VersionValue:              %08X\n\n", myNTHeader.OptionalHeader.Win32VersionValue);
	printf("指定PE image在虚拟内存中所占空间的大小 SectionAlignment的倍数 \n\
			DWORD SizeOfImage 11*:                    %08X\n\n", myNTHeader.OptionalHeader.SizeOfImage);
	printf("所有头(dos + pe标记 + 标准PE + 可选PE) + 节表按照文件对齐后的大小 \n\
			(FileAlignment整数倍) 它也是从文件头的开头到第一节的原始数据的偏移量，\n\
			可以找到第一节区 \n\
			DWORD SizeOfHeaders 12*:                  %08X\n\n", myNTHeader.OptionalHeader.SizeOfHeaders);
	printf("映像文件的校验和， 目的是为了防止载入无论如何都会冲突的、已损坏的二进制文件 \n\
			DWORD CheckSum:                       %08X\n\n", myNTHeader.OptionalHeader.CheckSum);
	printf("说明映像文件应运行于什么样的NT子系统之上,\n\
			该值用来区分系统驱动文件（*.sys）与普通可执行文件(*.exe, *.dll)\n\
			value: 1 含义： Driver文件  tips: 系统驱动（如： ntfs.sys） \n\
			value: 2 含义： GUI文件     tips: 窗口应用程序（如： notepad.exe） \n\
			value: 3 含义： CUI文件     tips: 控制台应用程序（如：cmd.exe） \n\
			WORD Subsystem:                       %04X\n\n", myNTHeader.OptionalHeader.Subsystem);
	printf("DLL的文件属性 如果是DLL文件， 何时调用DLL文件的入口点， 一般的exe文件有一下两个属性：\n\
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE(表示支持终端服务器)800h \n\
			IMAGE_DLLCHARACTERISTICS_NX_COMPAT (表示程序采用了)NXCOMPAT编译100h (bit or 为 81000) \n\
			但是开启了ASLR的程序会多一个（IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE(DLL can move）40h 的属性 \n\
			（bit or 后为8140h）， 那可以修改这里关闭ASLR  \n\
			WORD DllCharacteristics:              %04X\n\n", myNTHeader.OptionalHeader.DllCharacteristics);
	printf("保留栈的大小， 默认是1MB \n\
			DWORD SizeOfStackReserve:             %08X\n\n", myNTHeader.OptionalHeader.SizeOfStackReserve);
	printf("初始时指定栈大小， 默认是4KB \n\
			DWORD SizeOfStackCommit:              %08X\n\n", myNTHeader.OptionalHeader.SizeOfStackCommit);
	printf("保留堆的大小，默认是1MB \n\
			DWORD SizeOfHeapReserve:              %08X\n\n", myNTHeader.OptionalHeader.SizeOfHeapReserve);
	printf("指定堆的大小 默认是 4k \n\
			DWORD SizeOfHeapCommit:               %08X\n\n", myNTHeader.OptionalHeader.SizeOfHeapCommit);
	printf("看到的资料都是保留 VALUE为0 \n\
			DWORD LoaderFlags:                    %08X\n\n", myNTHeader.OptionalHeader.LoaderFlags);
	printf("数据目录项数， 即指出了我们下面一个成员数组的个数，\n\
			虽然宏定义了#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES16 \n\
			但是PE装载器会通过此值来识别数组大小，说明数组大小也可能非16 \n\
			DWORD NumberOfRvaAndSizes:            %08X\n\n", myNTHeader.OptionalHeader.NumberOfRvaAndSizes);
	printf("此处未打印的可选头最后一个成员很重要即目录项 是一个数组 包含导出表，导入表，资源表等的描述 \n\n");
	//节表目录
	printf("==============================IMAGE_SECIION_HEADER==================\n");

	pmySectionHeader = (IMAGE_SECTION_HEADER*)calloc(myNTHeader.FileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER));
	fseek(pfile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
	fread(pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), myNTHeader.FileHeader.NumberOfSections, pfile);

	for (int i = 0; i < myNTHeader.FileHeader.NumberOfSections; i++, pmySectionHeader++)
	{
		printf("节区的名字数组，大小为节数量个字节，如果全部字节都被用光，该字符串就没有0结束符 \n\
				典型的名称.data .text .bss 形式，(.不是必须)， 节区名称和节区内容不一定相关，\n\
				节名称没有严格要求,前边带有“$”的相同名字的区块在载入时会被合并， 合并之后的区块中 \n\
				他们是按照“$”后边的字符的字母顺序进行合并的，每个区块的名称都是唯一的，不能有同名的两个区块 \n\
				BYTE Name:                          %s\n\n", pmySectionHeader->Name);
		printf("\n\
				DWORD PhysicalAddress:            %08X\n\n", pmySectionHeader->Misc.PhysicalAddress);
		printf("内存中节区所占大小（实际初始了的数据大小， 未内存对齐） \n\
				DWORD VirtualSize:                %08X\n\n", pmySectionHeader->Misc.VirtualSize);
		printf("内存中节区的起始位置（RVA）, 开始没有值， 由SectionAlignment确定 \n\
				DWORD VirtualAddress:             %08X\n\n", pmySectionHeader->VirtualAddress);
		printf("磁盘文件中节区所占大小（对齐后的大小） \n\
				DWORD SizeOfRawData:              %08X\n\n", pmySectionHeader->SizeOfRawData);
		printf("磁盘文件中节区的起始位置， 开始没有值， 由FileAlignment确定 \n\
				DWORD PointerToRawData:           %08X\n\n", pmySectionHeader->PointerToRawData);
		printf("重定位指针 下面四个都是用于目标文件的信息 \n\
				DWORD PointerToRelocations:       %08X\n\n", pmySectionHeader->PointerToRelocations);
		printf("行数指针 \n\
				DWORD PointerToLinenumber:        %08X\n\n", pmySectionHeader->PointerToLinenumbers);
		printf("重定位数 \n\
				WORD NumberOfRelocations          %04X\n\n", pmySectionHeader->NumberOfLinenumbers);
		printf("行数 \n\
				WORD NumberOfLinenumbers:         %04X\n\n", pmySectionHeader->NumberOfLinenumbers);
		printf("指定节的属性，权限，有不同的值bit or 而成 \n\
				0x20: 包含代码，                  0x40: 包含初始化数据的节 \n\
				0x80； 包含未初始化数据的节       0x20000000: 可执行 （x）\n\
				0x40000000: 可读（r）             0x80000000: 可写（w）\n\
				DWORD Characteristics:            %08X\n\n", pmySectionHeader->Characteristics);
	}

	pmySectionHeader = NULL;
	free(pmySectionHeader);
	fclose(pfile);
	getchar();

	return 0;



}