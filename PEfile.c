#include <stdio.h>
#include <string.h>

#include "PEfile.h"


/*
ヘッダ情報を取得し、テキストファイルに出力する関数
成功時は0を、失敗時は-1を返す
*/
int Read_header(FILE *bfp, t_header *th){
	int i, ptr;
	FILE *htfp;
	unsigned char c1, name[10];
	union{
		unsigned short b2;
		unsigned long b4;
		unsigned char b1[4];
	}code;
	char name_IDD[16][20] = {
		"Export", "Import", "Resource", "Exception", "Security", "Relocation", "Debug", "Copyright",
		"GlobalPtr", "TLS", "Load Config", "Bound Import", "IAT", "Delayed Imports", "COM Runtime", "Reserved"
	};


	/* 結果出力ファイルをオープン */
	if ((htfp = fopen(th->htname, "w")) == NULL){
		printf("\aファイルをオープンできません。\n");
		return -1;
	}

	/*逆アセンブルに必要な情報を取得*/
	//IMAGE_DOS_HEADER
	fseek(bfp, 0, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "e_magic:              %04X (\"%c%c\")\n", code.b2, code.b1[0], code.b1[1]);
	if (code.b2 != 0x5a4d){ return -1; }   //MZシグネチャの存在を確認

	fseek(bfp, 0x3c, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "e_lfanew:             %08X\n", code.b4);
	unsigned long e_lfanew = code.b4;	//PE signatureへのファイルオフセット
	unsigned long fhead = e_lfanew + 4;		//IMAGE_FILE_HEADERへのファイルオフセット
	unsigned long ohead = fhead + 20;		//IMAGE_OPTINAL_HEADERへのファイルオフセット

	fputc('\n', htfp);   //改行

	//PE signature
	fseek(bfp, e_lfanew, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "Magic:                %08X (\"%s\")\n", code.b4, code.b1);
	if (code.b4 != 0x00004550){ return -1; }   //PEシグネチャの存在を確認

	fputc('\n', htfp);   //改行

	//IMAGE_FILE_HEADER
	fseek(bfp, fhead, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "Machine:              %04X", code.b2);
	if (code.b2 != 0x014c){ return 1; }   //マシンタイプがI386であることを確認
	else{ fprintf(htfp, " (Intel 386)\n"); }

	fseek(bfp, fhead + 2, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "NumberOfSections:     %04X\n", code.b2);
	th->NumberOfSections = code.b2;	//セクションの数
	if (th->NumberOfSections > 10){ return -1; }   //セクション数が想定より多い場合、終了

	fseek(bfp, fhead + 16, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "SizeOfOptionalHeader: %04X\n", code.b2);
	unsigned long shead = ohead + code.b4;		//IMAGE_SECTION_HEADERへのファイルオフセット

	fseek(bfp, fhead + 18, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "Characteristics:      %04X\n", code.b2);
	if (!((code.b2 & 0x0002) && (code.b2 & 0x0100))){ return -1; }   //実行可能かつ32ビットアーキテクチャのマシンであることを確認

	fputc('\n', htfp);   //改行

	//IMAGE_OPTINAL_HEADER
	fseek(bfp, ohead + 4, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "SizeOfCode:           %08X\n", code.b4);
	th->SizeOfCode = code.b4;   //全コード（テキスト）セクションのサイズ

	fseek(bfp, ohead + 16, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "AddressOfEntryPoint:  %08X\n", code.b4);
	th->AddressOfEntryPoint = code.b4;   //実行ファイルがメモリにロードされたときの、エントリポイントのRVA

	fseek(bfp, ohead + 20, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "BaseOfCode:           %08X\n", code.b4);
	th->BaseOfCode = code.b4;   //メモリにロードされたときの、コード セクションの先頭RVA

	fseek(bfp, ohead + 28, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "ImageBase:            %08X\n", code.b4);
	th->ImageBase = code.b4;   //メモリにロードされるときのイメージの先頭バイトの望ましいアドレス

	fseek(bfp, ohead + 56, SEEK_SET);
	fread(code.b1, 1, 4, bfp);
	fprintf(htfp, "SizeOfImage:          %08X\n", code.b4);
	th->SizeOfImage = code.b4;   //すべてのヘッダを含めたイメージのサイズ

	fputc('\n', htfp);   //改行

	//IMAGE_DATA_DIRECTORY
	fprintf(htfp, "[IMAGE_DATA_DIRECTORY]\n");
	fseek(bfp, ohead + 96, SEEK_SET);
	for (i = 0; i < 16; i++){
		strcpy(th->IDD[i].Name, name_IDD[i]);
		fread(&th->IDD[i].RVA, 1, 4, bfp);
		fread(&th->IDD[i].Size, 1, 4, bfp);
		fprintf(htfp, "Name: %-15s | RVA: %08X, Size: %08X\n", th->IDD[i].Name, th->IDD[i].RVA, th->IDD[i].Size);
	}

	fputc('\n', htfp);   //改行

	//インポートテーブルのRVA取得
	unsigned long ITrva = th->IDD[1].RVA;

	//IMAGE_SECTION_HEADER
	th->ptr_text = -1;   //初期化処理
	for (ptr = 0; ptr < th->NumberOfSections; ptr++){
		fseek(bfp, shead, SEEK_SET);
		fread(name, 1, 8, bfp);
		name[8] = '\0';
		fprintf(htfp, "[%s]\n", name);   //セクション名を出力

		fseek(bfp, shead + 8, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "VirtualSize:          %08X\n", code.b4);
		th->ts[ptr].VirtualSize = code.b4;   //メモリにロードされたときのセクションの合計サイズ

		fseek(bfp, shead + 12, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "VirtualAddress:       %08X\n", code.b4);
		th->ts[ptr].VirtualAddress = code.b4;   //メモリにロードされたときのセクションの先頭バイトのRVA
		if (th->ts[ptr].VirtualAddress > th->SizeOfImage){ return -1; }   //RVAが適切かどうか確認

		fseek(bfp, shead + 16, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "SizeOfRawData:        %08X\n", code.b4);
		th->ts[ptr].SizeOfRawData = code.b4;   //ファイル上におけるセクションのサイズ

		fseek(bfp, shead + 20, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "PointerToRawData:     %08X\n", code.b4);
		th->ts[ptr].PointerToRawData = code.b4;   //ファイル上におけるセクションの位置

		fseek(bfp, shead + 36, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "Characteristics:      %08X\n", code.b4);
		th->ts[ptr].Characteristics = code.b4;
		if ((code.b4 & 0x20000000) && (code.b4 & 0x00000020)){   //.textセクションの特定
			th->ptr_text = ptr;   //.textセクションが何番目のセクションであるかを記憶
		}

		fputc('\n', htfp);   //改行

		shead += 40;   //次セクションのファイルオフセットに更新
	}
	if (th->ptr_text < 0){ return 1; }   //.textセクションを特定できたかどうか確認

	//インポート情報のファイル位置をRVAから特定
	th->no.idata = ptr;
	th->ts[ptr].VirtualAddress = ITrva;
	for (i = 0; i < ptr; i++){
		if (th->ts[i].VirtualAddress <= ITrva && ITrva <= th->ts[i].VirtualAddress + th->ts[i].VirtualSize){
			th->ts[ptr].PointerToRawData = ITrva - th->ts[i].VirtualAddress + th->ts[i].PointerToRawData;
		}
	}

	fclose(htfp);

	return 0;
}

/* インポート情報の読み込み＆ファイル出力関数 */
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]){
	int i, j;
	FILE *itfp;
	int num_dll = 0;
	unsigned long offs, rva;
	unsigned long ptrd = th->ts[th->no.idata].PointerToRawData;
	unsigned long va = th->ts[th->no.idata].VirtualAddress;


	offs = ptrd;
	for (i = 0;; i++){
		//ILTのRVA取得
		fseek(bfp, offs, SEEK_SET);
		fread(&ti[i].OriginalFirstThunk, 1, 4, bfp);

		//DLL名のRVA取得
		fseek(bfp, 8, SEEK_CUR);
		fread(&ti[i].Name, 1, 4, bfp);

		//IATのRVA取得
		fread(&ti[i].FirstThunk, 1, 4, bfp);

		if (ti[i].FirstThunk == 0){ break; }
		num_dll++;
		offs += 20;
	}

	//ILTの情報取得
	if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合のみ
		for (i = 0; i < num_dll; i++){
			rva = ti[i].OriginalFirstThunk;
			fseek(bfp, ptrd + (ti[i].OriginalFirstThunk - va), SEEK_SET);

			ti[i].size_ILT = 0;
			for (j = 0;; j++){
				fread(&ti[i].ILT[j], 1, 4, bfp);
				if (ti[i].ILT[j] == 0){ break; }
				ti[i].ILT_rva[j] = rva;
				rva += 4;
				ti[i].size_ILT++;
			}
		}
	}

	//IATの情報取得
	for (i = 0; i < num_dll; i++){
		rva = ti[i].FirstThunk;
		fseek(bfp, ptrd + (ti[i].FirstThunk - va), SEEK_SET);

		ti[i].size_IAT = 0;
		for (j = 0;; j++){
			fread(&ti[i].IAT[j], 1, 4, bfp);
			if (ti[i].IAT[j] == 0){ break; }
			ti[i].IAT_rva[j] = rva;
			rva += 4;
			ti[i].size_IAT++;
		}
	}

	//DLL名とインポート関数のヒントと名前を取得
	for (i = 0; i < num_dll; i++){
		//DLL名取得
		fseek(bfp, ptrd + (ti[i].Name - va), SEEK_SET);
		fscanf(bfp, "%s", ti[i].dll);
		//インポート関数の序数もしくはヒントと名前取得
		if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合のみ
			for (j = 0; j < ti[i].size_ILT; j++){
				if ((ti[i].ILT[j] & 0x80000000) != 0){   //序数の取得
					ti[i].OrdinalNumber[j] = ti[i].ILT[j] & 0x7FFFFFFF;
				}
				else{   //ヒントと名前取得
					fseek(bfp, ptrd + (ti[i].ILT[j] - va), SEEK_SET);
					fread(&ti[i].Hint[j], 1, 2, bfp);
					fscanf(bfp, "%s", ti[i].function[j]);
				}
			}
		}
	
	}
	
	//ファイル出力
	if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合のみ
		if ((itfp = fopen(th->itname, "w")) == NULL){
			printf("\aファイルをオープンできません。\n");
			return 1;
		}
		fprintf(itfp, "[IMPORTS]\n\n");
		for (i = 0; i < num_dll; i++){
			fprintf(itfp, "DLL: %s\n", ti[i].dll);
			for (j = 0; j < ti[i].size_ILT; j++){
				if ((ti[i].ILT[j] & 0x80000000) != 0){
					fprintf(itfp, " RVA: %08X, Ord#: %4d(%04X)\n", ti[i].IAT_rva[j], ti[i].OrdinalNumber[j], ti[i].OrdinalNumber[j]);
				}
				else{
					fprintf(itfp, " RVA: %08X, Hint: %4d(%04X), Name: %s\n", ti[i].IAT_rva[j], ti[i].Hint[j], ti[i].Hint[j], ti[i].function[j]);
				}
			}
			fprintf(itfp, "\n");
		}
	}

	return 0;
}