// mem.cpp : 定义控制台应用程序的入口点。
//PE文件从文件加载到内存，再从内存读取，然后存盘到文件

#include <iostream>
#include <windows.h>
#include <winnt.h>

#define  PATH "C:\\Users\\Administrator\\Desktop\\notepad.exe"
int Filelength(FILE *fp);
int main(int argc, char* argv[])
{
	FILE* Fp;
	fopen_s(&Fp, PATH, "rb");
	int FileSize = Filelength(Fp); //获取文件大小
	char* FileBuffer = (char*)malloc(FileSize); //申请存放文件的内存空间

	if (FileBuffer == NULL)
	{
		printf("申请iImageBuffer");
	}
	fread_s(FileBuffer, FileSize, 1, FileSize, Fp); //将文件复制到内存中

	//定位一下内存中的数据 各个头表
	//定位标准PE头
	PIMAGE_FILE_HEADER MyFileHeader;
	MyFileHeader = (PIMAGE_FILE_HEADER)(char*)(FileBuffer +  * (int*)(FileBuffer + 0x3c) + 0x4);

	//定位可选PE头
	PIMAGE_OPTIONAL_HEADER MyOptionalHeader;
	MyOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((char*)MyFileHeader + 0x14);

	//定位节表
	PIMAGE_SECTION_HEADER MySectionHeader;
	MySectionHeader = (PIMAGE_SECTION_HEADER)((char*)MyOptionalHeader + MyFileHeader->SizeOfOptionalHeader);

	//拉伸， 也就是读到内存中的状态
	char* ImageBuffer = (char*)malloc(MyOptionalHeader->SizeOfImage); //给拉伸申请内存空间
	//ZeroMemory(ImageBuffer, MyOptionalHeader->ZizeOfImage)

	if (ImageBuffer == NULL)
	{
		printf("申请iImageBuffer失败");
	}
	memcpy(ImageBuffer, FileBuffer,MyOptionalHeader->SizeOfHeaders);

	
	for (int i = 0; i < MyFileHeader->NumberOfSections; i++)
	{
		memcpy(ImageBuffer + MySectionHeader->VirtualAddress, FileBuffer + MySectionHeader->PointerToRawData, MySectionHeader->SizeOfRawData);
		MySectionHeader++;
	}

	//压缩， 为存盘做准备
	char* NewBuffer = (char*)malloc(FileSize); //给压缩申请内存空间
	if (NewBuffer == NULL)
	{
		printf("申请iImageBuffer失败");
	}

	memcpy(NewBuffer, ImageBuffer, MyOptionalHeader->SizeOfHeaders);
	MySectionHeader = (PIMAGE_SECTION_HEADER)((char*)MyOptionalHeader + MyFileHeader->SizeOfOptionalHeader);  //重新指一下， 前面动过了
	
	for (int i = 0; i < MyFileHeader->NumberOfSections; i++)
	{
		memcpy(NewBuffer + MySectionHeader->PointerToRawData, ImageBuffer + MySectionHeader->VirtualAddress, MySectionHeader->SizeOfRawData);
		MySectionHeader++;
	}

	FILE* nFp;
	fopen_s(&nFp, "c:\\Users\\Administrator\\Desktop\\notepad1.exe", "wb");
	fwrite(NewBuffer, FileSize, 1, nFp);

	//gerchar();
	fclose(nFp);
	free(FileBuffer);
	free(ImageBuffer);
	free(NewBuffer);

	return 0;
}

//获取文件大小



int Filelength(FILE* fp)
{
	int num;
	fseek(fp, 0, SEEK_END);
	num = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return num;
}