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
	if (code.b2 != 0x014c){ return -1; }   //マシンタイプがI386であることを確認
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
	if (th->ptr_text < 0){ return -1; }   //.textセクションを特定できたかどうか確認

	fclose(htfp);   //結果出力ファイルをクローズ

	return 0;
}

/* 
インポート情報の読み込み＆ファイル出力関数 
成功時は0を、失敗時は-1を返す
*/
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]){
	int i, j, len;
	FILE *itfp;
	unsigned long offs, rva;
	unsigned long VA, PTRD;   //IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置


	/* IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置を取得 */
	VA = th->IDD[1].RVA;   //IMAGE_IMPORT_DESCRIPTORのRVAをIMAGE_DATA_DIRECTORY構造体より取得
	for (i = 0; i < th->NumberOfSections; i++){   //RVAからどのセクションにあるのかを特定し、ファイル位置を取得
		if (th->ts[i].VirtualAddress <= VA && VA <= th->ts[i].VirtualAddress + th->ts[i].VirtualSize){
			PTRD = VA - th->ts[i].VirtualAddress + th->ts[i].PointerToRawData;
			break;
		}
	}
	if (i == th->NumberOfSections){ return -1; }   //IMAGE_IMPORT_DESCRIPTORのファイル位置を取得できなかった場合、終了

	/* IMAGE_IMPORT_DESCRIPTORからILT,DLL名,IATのRVAを取得 */
	for (i = 0; i < 30; i++){
		//ILTのRVA取得
		fseek(bfp, PTRD + (i * 20), SEEK_SET);
		fread(&ti[i].OriginalFirstThunk, 1, 4, bfp);

		//DLL名のRVA取得
		fseek(bfp, 8, SEEK_CUR);
		fread(&ti[i].Name, 1, 4, bfp);

		//IATのRVA取得
		fread(&ti[i].FirstThunk, 1, 4, bfp);
		if (ti[i].FirstThunk == 0){ break; }   //IMAGE_IMPORT_DESCRIPTORの終端
	}
	if (i == 30){ return -1; }   //DLLの数が想定より多い場合、終了

	/* DLL名取得 */
	for (i = 0; ti[i].FirstThunk != 0; i++){
		fseek(bfp, PTRD + (ti[i].Name - VA), SEEK_SET);
		for (len = 0; len < 50; len++){
			fread(ti[i].dll + len, 1, 1, bfp);
			if (ti[i].dll[len] == '\0'){ break; }   //DLL名の終端
		}
		if (len == 50){ return -1; }   //DLL名の長さが想定よりも長かった場合、終了
	}

	/* インポート関数の序数もしくはヒントと名前取得 */
	for (i = 0; ti[i].FirstThunk != 0; i++){
		//offsにILTもしくはIATのファイル位置をセット
		if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合、ILTをセット
			offs = PTRD + (ti[i].OriginalFirstThunk - VA);
		}
		else{   //ILTが存在しない場合、IATをセット
			offs = PTRD + (ti[i].FirstThunk - VA);
		}

		//インポート関数の序数もしくはヒントと名前取得
		for (j = 0; j < 150; j++){
			fseek(bfp, offs + (j * 4), SEEK_SET);
			fread(&rva, 1, 4, bfp);
			if (rva == 0){ break; }   //ILTもしくはIATの終端

			if ((rva & 0x80000000) != 0){   //序数の取得
				ti[i].OrdinalNumber[j] = rva & 0x7FFFFFFF;
				ti[i].function[j][0] = '\0';   //インポート関数名を取得できなかったことを示す
			}
			else{   //ヒントと名前取得
				if (rva > th->SizeOfImage){ return -1; }   //RVAが適切でない場合、終了
				fseek(bfp, PTRD + (rva - VA), SEEK_SET);
				fread(&ti[i].Hint[j], 1, 2, bfp);
				for (len = 0; len < 50; len++){
					fread(ti[i].function[j] + len, 1, 1, bfp);
					if (ti[i].function[j][len] == '\0'){ break; }   //インポート関数名の終端
				}
				if (len == 50){ return -1; }   //インポート関数名の長さが想定よりも長かった場合、終了
			}
		}
		if (j == 150){ return -1; }   //ILTもしくはIATのサイズが想定より大きかった場合、終了
		ti[i].size_IAT = j;   //IATのサイズを記憶
	}
	
	//ファイル出力
	if ((itfp = fopen(th->itname, "w")) == NULL){
		printf("\aファイルをオープンできません。\n");
		return -1;
	}
	fprintf(itfp, "[IMPORTS]\n\n");
	for (i = 0; ti[i].FirstThunk != 0; i++){
		fprintf(itfp, "DLL: %s\n", ti[i].dll);   //DLL名出力
		for (j = 0; j < ti[i].size_IAT; j++){
			if (ti[i].function[j][0] == '\0'){   //序数出力
				fprintf(itfp, " RVA: %08X, Ord#: %4d(%04X)\n", ti[i].FirstThunk + (j * 4), ti[i].OrdinalNumber[j], ti[i].OrdinalNumber[j]);
			}
			else{   //ヒントとインポート関数名出力
				fprintf(itfp, " RVA: %08X, Hint: %4d(%04X), Name: %s\n", ti[i].FirstThunk + (j * 4), ti[i].Hint[j], ti[i].Hint[j], ti[i].function[j]);
			}
		}
		fprintf(itfp, "\n");
	}
	fclose(itfp);


	return 0;
}