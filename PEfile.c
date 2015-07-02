#include <stdio.h>

#include "PEfile.h"


/* ヘッダ情報を取得し、テキストファイルに出力する関数 */
int Read_header(FILE *bfp, t_header *th){
	int i;
	unsigned long addr = 0;
	unsigned char c1;
	union{
		unsigned short b2;
		unsigned long b4;
		unsigned char b1[16];
	}code;

	FILE *htfp;
	if ((htfp = fopen(th->htname, "w")) == NULL){
		printf("\aファイルをオープンできません。\n");
		return 1;
	}

	/*逆アセンブルに必要な情報を取得*/
	//IMAGE_DOS_HEADER
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "e_magic:              %04X (\"%c%c\")\n", code.b2, code.b1[0], code.b1[1]);
	if (code.b2 != 0x5a4d){ exit(1); }

	while (addr < 0x3c){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "e_lfanew:             %08X\n\n", code.b4);
	unsigned long e_lfanew = code.b4;	//PE signatureへのファイルオフセット

	//PE signature
	while (addr < e_lfanew){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "Magic:                %08X (\"%s\")\n", code.b4, code.b1);
	if (code.b4 != 0x00004550){ return 1; }
	unsigned long fhead = addr;		//IMAGE_FILE_HEADERへのファイルオフセット

	//IMAGE_FILE_HEADER
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "Machine:              %04X", code.b2);
	if (code.b2 != 0x014c){ return 1; }
	else{ fprintf(htfp, " (Intel 386以降およびその互換プロセッサ)\n"); }

	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "NumberOfSections:     %04X\n", code.b2);
	unsigned long NumberOfSections = code.b2;	//セクションの数

	while (addr < fhead + 16){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 2, bfp);
	addr += 2;
	fprintf(htfp, "SizeOfOptionalHeader: %04X\n\n", code.b4);
	unsigned long ohead = addr + 2;		//IMAGE_OPTINAL_HEADERへのファイルオフセット
	unsigned long shead = ohead + code.b4;		//IMAGE_SECTION_HEADERへのファイルオフセット

	//IMAGE_OPTINAL_HEADER
	while (addr < ohead + 4){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "SizeOfCode:           %08X\n", code.b4);
	unsigned long SizeOfCode = code.b4;

	while (addr < ohead + 16){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "AddressOfEntryPoint:  %08X\n", code.b4);

	while (addr < ohead + 20){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "BaseOfCode:           %08X\n", code.b4);
	th->BaseOfCode = code.b4;

	while (addr < ohead + 28){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	fprintf(htfp, "ImageBase:            %08X\n\n", code.b4);
	th->ImageBase = code.b4;

	//インポートテーブルのRVA取得
	while (addr < ohead + 104){
		fread(&c1, 1, 1, bfp);
		addr++;
	}
	fread(code.b1, 1, 4, bfp);
	addr += 4;
	unsigned long ITrva = code.b4;


	//IMAGE_SECTION_HEADER
	int ptr = 0;
	int flag_text;
	th->PointerToRawData = 0;
	th->no.idata = -1;
	while (NumberOfSections){
		flag_text = 0;

		while (addr < shead){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 8, bfp);
		addr += 8;
		code.b1[8] = '\0';
		fprintf(htfp, "[%s]\n", code.b1);
		if (!strcmp(code.b1, ".text")){ flag_text = 1; th->no.text = ptr; }
		else if (!strcmp(code.b1, ".idata")){ th->no.idata = ptr; }

		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "VirtualSize:          %08X\n", code.b4);
		th->ts[ptr].VirtualSize = code.b4;

		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "VirtualAddress:       %08X\n", code.b4);
		if (flag_text){ th->VirtualAddress = code.b4; }
		th->ts[ptr].VirtualAddress = code.b4;

		while (addr < shead + 16){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "SizeOfRawData:        %08X\n", code.b4);
		if (flag_text){ th->SizeOfRawData = code.b4; }
		th->ts[ptr].SizeOfRawData = code.b4;

		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "PointerToRawData:     %08X\n", code.b4);
		if (flag_text){ th->PointerToRawData = code.b4; }
		th->ts[ptr].PointerToRawData = code.b4;

		while (addr < shead + 36){
			fread(&c1, 1, 1, bfp);
			addr++;
		}
		fread(code.b1, 1, 4, bfp);
		addr += 4;
		fprintf(htfp, "Characteristics:      %08X\n\n", code.b4);

		ptr++;
		shead = addr;
		NumberOfSections--;
	}
	if (th->PointerToRawData == 0){ return 1; }

	//インポート情報のファイル位置をRVAから特定
	if (th->no.idata < 0){
		th->no.idata = ptr;
		th->ts[ptr].VirtualAddress = ITrva;
		for (i = 0; i < ptr; i++){
			if (th->ts[i].VirtualAddress <= ITrva && ITrva <= th->ts[i].VirtualAddress + th->ts[i].VirtualSize){
				th->ts[ptr].PointerToRawData = ITrva - th->ts[i].VirtualAddress + th->ts[i].PointerToRawData;
			}
		}
	}

	fclose(htfp);

	return 0;
}

/* インポート情報の読み込み＆ファイル出力関数 */
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]){
	int i, j;
	int num_dll = 0;
	char c1;
	unsigned short b2;
	unsigned long b4;
	unsigned long offs;
	unsigned long ptrd = th->ts[th->no.idata].PointerToRawData;
	unsigned long rva = th->ts[th->no.idata].VirtualAddress;


	offs = ptrd;
	for (i = 0; ; i++){
		//ILTのRVA取得
		fseek(bfp, offs, SEEK_SET);
		fread(&b4, 1, 4, bfp);
		ti[i].OriginalFirstThunk = b4;

		//DLL名のRVA取得
		fseek(bfp, 8, SEEK_CUR);
		fread(&b4, 1, 4, bfp);
		ti[i].Name = b4;

		//IATのRVA取得
		fread(&b4, 1, 4, bfp);
		if (b4 == 0){ break; }
		ti[i].FirstThunk = b4;

		num_dll++;
		offs += 20;
	}

	//IATの情報取得
	for (i = 0; i < num_dll; i++){
		unsigned long addr = ti[i].FirstThunk;
		fseek(bfp, ptrd + ti[i].FirstThunk - rva, SEEK_SET);

		ti[i].size_IAT = 0;
		for (j = 0; ; j++){
			fread(&b4, 1, 4, bfp);
			if (b4 == 0){ break; }
			ti[i].IAT[j] = b4;

			ti[i].IAT_rva[j] = addr;
			addr += 4;
			ti[i].size_IAT++;
		}
	}

	//DLL名とインポート関数のヒントと名前を取得
	for (i = 0; i < num_dll; i++){
		//DLL名取得
		fseek(bfp, ptrd + ti[i].Name - rva, SEEK_SET);
		fscanf(bfp, "%s", ti[i].dll);
		//インポート関数のヒントと名前取得
		for (j = 0; j < ti[i].size_IAT; j++){
			fseek(bfp, ptrd + ti[i].IAT[j] - rva, SEEK_SET);
			fread(&b2, 1, 2, bfp);
			ti[i].Hint[j] = b2;
			fscanf(bfp, "%s", ti[i].function[j]);
		}
	}
	
	//ファイル出力
	FILE *itfp;
	if ((itfp = fopen(th->itname, "w")) == NULL){
		printf("\aファイルをオープンできません。\n");
		return 1;
	}
	fprintf(itfp, "[IMPORTS]\n\n");
	for (i = 0; i < num_dll; i++){
		fprintf(itfp, "DLL: %s\n", ti[i].dll);
		for (j = 0; j < ti[i].size_IAT; j++){
			fprintf(itfp, " rva: %08X, hint: %04X, name: %s\n", ti[i].IAT_rva[j], ti[i].Hint[j], ti[i].function[j]);
		}
		fprintf(itfp, "\n");
	}

	return 0;
}