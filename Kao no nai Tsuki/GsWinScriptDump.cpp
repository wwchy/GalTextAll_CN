#include <Windows.h>
#include <iostream>
#include <fstream>

#define _WORD short
#define _BYTE char

int uncompre(_WORD* thisx, int a2, int a3, int a4, int a5)
{
    _WORD* v5; // ebx
    int v6; // ebp
    int v7; // esi
    int v8; // ecx
    int v9; // edx
    char v10; // al
    char v11; // al
    __int16 v12; // ax
    int v13; // esi
    char v14; // dl
    __int16 v15; // di
    int v16; // edx
    __int16 v17; // ax
    bool v18; // sf
    int v19; // edx
    char v20; // bl
    unsigned __int16 v22; // [esp+10h] [ebp-Ch]
    int v24; // [esp+18h] [ebp-4h]

    v5 = thisx;
    v6 = 0;
    v7 = 0;
    memset(thisx + 4, 0, 0xFECu);
    thisx[0x7FA] = 0;
    v8 = 0xFEE;
    v22 = 0;
    while (1)
    {
        while (1)
        {
            v22 >>= 1;
            if ((v22 & 0x100) != 0)
            {
                v9 = a2;
            }
            else
            {
                if (v7 == a4)
                    return 1;
                v9 = a2;
                v10 = *(_BYTE*)(v7 + a2);
                ++v7;
                v22 = *(_WORD*)&v10 | 0xFF00;
            }
            if ((v22 & 1) == 0)
                break;
            if (v7 == a4)
                return 1;
            v11 = *(_BYTE*)(v7 + v9);
            ++v7;
            *(_BYTE*)(a3 + v6++) = v11;
            *((_BYTE*)v5 + v8 + 8) = v11;
            v8 = ((_WORD)v8 + 1) & 0xFFF;
        }
        if (v7 == a4)
            break;
        v12 = *(unsigned __int8*)(v7 + v9);
        v13 = v7 + 1;
        if (v13 == a4)
            break;
        v14 = *(_BYTE*)(v13 + v9);
        v15 = 16 * (v14 & 0xF0);
        v16 = v14 & 0xF;
        v7 = v13 + 1;
        v17 = v15 | v12;
        v18 = v16 + 2 < 0;
        v24 = v16 + 2;
        v19 = 0;
        if (!v18)
        {
            do
            {
                v20 = *((_BYTE*)v5 + (((_WORD)v19 + v17) & 0xFFF) + 8);
                *(_BYTE*)(a3 + v6) = v20;
                *((_BYTE*)thisx + v8 + 8) = v20;
                v5 = thisx;
                ++v6;
                v8 = ((_WORD)v8 + 1) & 0xFFF;
                ++v19;
            } while (v19 <= v24);
        }
    }
    return 1;
}

//Frome crass/cui-1.0.4
typedef struct {
	unsigned char magic[16];
	unsigned short minor_version;
	unsigned short major_version;
	unsigned int is_compr;
	unsigned int uncomprlen;
	unsigned int comprlen;
	unsigned int always_1;					// 1
	unsigned int instruction_table_entries;	// 脚本指令的个数
	unsigned int string_table_entries;		// 字符串的个数
	unsigned int unknown_table_entries;		// ？？的个数
	unsigned int instruction_data_length;	// 脚本数据总长度
	unsigned int string_data_length;			// 字符串数据总长度
	unsigned int unknown_data_length;		// ？？数据总长度
	unsigned char pad[0x188];
} Scw4Header;

void XorRawData(char* buffer, size_t szBuffer, char key)
{
	for (size_t p = 0; p < szBuffer; ++p)
	{
		buffer[p] ^= key & p;
	}
}

size_t GetFileSize(std::ifstream& fsFile)
{
	size_t szFile = 0;
	size_t odlOff = fsFile.tellg();

	fsFile.seekg(0, std::ios::end);
	szFile = fsFile.tellg();
	fsFile.seekg(odlOff, std::ios::beg);
	return szFile;
}

void DecSCW(std::string strFileName)
{
    char* pTmp = new char[0x10000];

    size_t szFile = 0;
    std::ifstream iFile(strFileName, std::ios::binary);
    if (iFile.is_open())
    {
        szFile = GetFileSize(iFile);

        char* pData = new char[szFile];
        iFile.read(pData, szFile);
        XorRawData(&pData[sizeof(Scw4Header)], szFile - sizeof(Scw4Header), 0xFF);

        size_t szUncompre = ((Scw4Header*)pData)->uncomprlen;
        char* pDec = new char[szUncompre];
        uncompre((short*)pTmp, (int)(&pData[sizeof(Scw4Header)]), (int)pDec, szFile - sizeof(Scw4Header), ((Scw4Header*)pData)->uncomprlen);
        std::ofstream oFile(strFileName + ".dec", std::ios::binary);
        if (oFile.is_open())
        {
            ((Scw4Header*)pData)->is_compr = 0;
            oFile.write(pData, sizeof(Scw4Header));
            oFile.write(pDec, szUncompre);
            oFile.flush();
            oFile.close();
        }

        iFile.close();
        delete[] pData;
        delete[] pDec;
    }

    delete[] pTmp;

}

void DumpString(std::string strFileName)
{
    size_t szFile = 0;
    std::ofstream oFile(strFileName + ".txt");
    std::ifstream iFile(strFileName, std::ios::binary);
    if (iFile.is_open())
    {
        std::string str;

        szFile = GetFileSize(iFile);
        char* pDecData = new char[szFile];
        iFile.read(pDecData, szFile);
        char* pStrOffsetTable = &pDecData[((Scw4Header*)pDecData)->instruction_table_entries * 8] + sizeof(Scw4Header);
        char* pStringData = pStrOffsetTable + ((Scw4Header*)pDecData)->string_table_entries * 8 + ((Scw4Header*)pDecData)->instruction_data_length + ((Scw4Header*)pDecData)->unknown_data_length;
        for (size_t i = 0; i < ((Scw4Header*)pDecData)->string_table_entries * 2;i+=2)
        {
            str = &pStringData[((int*)pStrOffsetTable)[i]];
            oFile << str << std::endl;
        }
        delete[] pDecData;
        oFile.flush();
        oFile.close();
        iFile.close();
    }
}

int main(int argc, char* argv[])
{
    std::string fileName = "AF01.scw";
    if (argc > 1)
    {
        fileName = argv[1];
        DecSCW(fileName);
        DumpString(fileName + ".dec");
    }

    DecSCW(fileName);
    DumpString(fileName + ".dec");
}