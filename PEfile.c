#include <stdio.h>
#include <string.h>

#include "PEfile.h"



/*
ヘッダ情報を取得し、テキストファイルに出力する関数
成功時は0を、失敗時は-1を返す
*/
int Read_header(FILE *htfp, FILE *bfp, t_header *th){
	int i, ptr;
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

	/* ヘッダ情報を取得 */
	//IMAGE_DOS_HEADER
	fseek(bfp, 0, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "e_magic:              %04X (\"%c%c\")\n", code.b2, code.b1[0], code.b1[1]);
	if (code.b2 != 0x5a4d){   //MZシグネチャが存在しない場合、終了
		printf("ERROR: Not MZ signature\n");
		return -1; 
	}

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
	if (code.b4 != 0x00004550){   //PEシグネチャが存在しない場合、終了 
		printf("ERROR: Not PE signature\n");
		return -1; 
	}

	fputc('\n', htfp);   //改行

	//IMAGE_FILE_HEADER
	fseek(bfp, fhead, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "Machine:              %04X", code.b2);
	if (code.b2 != 0x014c){   //マシンタイプがI386でない場合、終了
		printf("ERROR: Not Machine I386\n");
		return -1; 
	}   //マシンタイプがI386であることを確認
	else{ fprintf(htfp, " (Intel 386)\n"); }

	fseek(bfp, fhead + 2, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "NumberOfSections:     %04X\n", code.b2);
	th->NumberOfSections = code.b2;	//セクションの数
	th->sh = (t_sheader *)calloc(th->NumberOfSections, sizeof(t_sheader));   //sh構造体をセクションの数だけ動的確保
	if (th->sh == NULL){
		printf("ERROR: calloc th->sh\n");
		return -1; 
	}   

	fseek(bfp, fhead + 16, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "SizeOfOptionalHeader: %04X\n", code.b2);
	unsigned long shead = ohead + code.b4;		//IMAGE_SECTION_HEADERへのファイルオフセット

	fseek(bfp, fhead + 18, SEEK_SET);
	fread(code.b1, 1, 2, bfp);
	fprintf(htfp, "Characteristics:      %04X\n", code.b2);
	if (!((code.b2 & 0x0002) && (code.b2 & 0x0100))){   //実行可能かつ32ビットアーキテクチャのマシンでない場合、終了
		printf("ERROR: Not executable or Not 32bit machine\n");
		return -1;
	}

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
		th->sh[ptr].VirtualSize = code.b4;   //メモリにロードされたときのセクションの合計サイズ

		fseek(bfp, shead + 12, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "VirtualAddress:       %08X\n", code.b4);
		th->sh[ptr].VirtualAddress = code.b4;   //メモリにロードされたときのセクションの先頭バイトのRVA
		if (th->sh[ptr].VirtualAddress > th->SizeOfImage){   //RVAが適切でない場合、終了
			printf("ERROR: Get VirtualAddress of sheader\n");
			return -1; 
		}

		fseek(bfp, shead + 16, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "SizeOfRawData:        %08X\n", code.b4);
		th->sh[ptr].SizeOfRawData = code.b4;   //ファイル上におけるセクションのサイズ

		fseek(bfp, shead + 20, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "PointerToRawData:     %08X\n", code.b4);
		th->sh[ptr].PointerToRawData = code.b4;   //ファイル上におけるセクションの位置

		fseek(bfp, shead + 36, SEEK_SET);
		fread(code.b1, 1, 4, bfp);
		fprintf(htfp, "Characteristics:      %08X\n", code.b4);
		th->sh[ptr].Characteristics = code.b4;
		if ((code.b4 & 0x20000000) && (code.b4 & 0x00000020)){   //.textセクションの特定
			th->ptr_text = ptr;   //.textセクションが何番目のセクションであるかを記憶
		}

		fputc('\n', htfp);   //改行

		shead += 40;   //次セクションのファイルオフセットに更新
	}
	if (th->ptr_text < 0){   //.textセクションを特定できたかどうか確認
		printf("ERROR: Get ptr_text\n");
		return -1;
	}

	return 0;
}


/* 
初期化して値をセットしたt_idata構造体を返す関数 
失敗時はNULLを返す
*/
t_idata *Get_idata(FILE *bfp, t_header *th){
	int i, size_IID;
	unsigned long rva;
	unsigned long VA, PTRD;   //IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置


	/* IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置を取得 */
	VA = th->IDD[1].RVA;   //IMAGE_IMPORT_DESCRIPTORのRVAをIMAGE_DATA_DIRECTORY構造体より取得
	for (i = 0; i < th->NumberOfSections; i++){   //RVAからどのセクションにあるのかを特定し、ファイル位置を取得
		if (th->sh[i].VirtualAddress <= VA && VA <= th->sh[i].VirtualAddress + th->sh[i].VirtualSize){
			PTRD = VA - th->sh[i].VirtualAddress + th->sh[i].PointerToRawData;
			break;
		}
	}
	if (i == th->NumberOfSections){   //IMAGE_IMPORT_DESCRIPTORのファイル位置を取得できなかった場合、終了 
		printf("ERROR: Get PTRD\n");
		return NULL; 
	}

	/* IMAGE_IMPORT_DESCRIPTORのサイズをカウント */
	size_IID = 0;
	for (i = 0; i >= 0; i++){
		fseek(bfp, PTRD + (i * 20) + 16, SEEK_SET);
		fread(&rva, 1, 4, bfp);
		if (rva == 0){   //IMAGE_IMPORT_DESCRIPTORの終端
			size_IID = i + 1;
			break;
		}
	}
	if (size_IID <= 0){   //IMAGE_IMPORT_DESCRIPTORのサイズが想定よりも大きい場合、終了
		printf("ERROR: Get size_IDD\n");
		return NULL;
	}

	/* ti構造体をインポートするDLLの総数だけ動的確保 */
	t_idata *ti;
	ti = (t_idata *)calloc(size_IID, sizeof(t_idata));
	if (ti == NULL){
		printf("ERROR: calloc ti\n");
		return NULL;
	}

	/* IMAGE_IMPORT_DESCRIPTORからILT,DLL名,IATのRVAを取得 */
	for (i = 0; i >= 0; i++){
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

	return ti;
}


/* 
インポート情報の読み込み＆ファイル出力関数 
成功時は0を、失敗時は-1を返す
*/
int Read_idata(FILE *itfp, FILE *bfp, t_header *th, t_idata *ti){
	int i, j, len;
	char c1;
	short hint;
	long ord;
	unsigned long offs, b4;
	unsigned long VA, PTRD;   //IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置


	/* IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置を取得 */
	VA = th->IDD[1].RVA;   //IMAGE_IMPORT_DESCRIPTORのRVAをIMAGE_DATA_DIRECTORY構造体より取得
	for (i = 0; i < th->NumberOfSections; i++){   //RVAからどのセクションにあるのかを特定し、ファイル位置を取得
		if (th->sh[i].VirtualAddress <= VA && VA <= th->sh[i].VirtualAddress + th->sh[i].VirtualSize){
			PTRD = VA - th->sh[i].VirtualAddress + th->sh[i].PointerToRawData;
			break;
		}
	}
	if (i == th->NumberOfSections){   //IMAGE_IMPORT_DESCRIPTORのファイル位置を取得できなかった場合、終了
		printf("ERROR: Get PTRD\n");
		return -1;
	}

	/* 各DLL名ごとに、IATのRVAに加えてインポート関数の序数もしくはヒントと名前を出力 */
	for (i = 0; ti[i].FirstThunk != 0; i++){
		//DLL名出力
		fprintf(itfp, "DLL: ");
		fseek(bfp, PTRD + (ti[i].Name - VA), SEEK_SET);
		for (len = 0; len >= 0; len++){
			fread(&c1, 1, 1, bfp);
			fprintf(itfp, "%c", c1);
			if (c1 == '\0'){ break; }   //DLL名の終端
		}
		fputc('\n', itfp);

		//offsにILTもしくはIATのファイル位置をセット
		if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合、ILTをセット
			offs = PTRD + (ti[i].OriginalFirstThunk - VA);
		}
		else{   //ILTが存在しない場合、IATをセット
			offs = PTRD + (ti[i].FirstThunk - VA);
		}

		//IATのRVAに加え、インポート関数の序数もしくはヒントと名前出力
		for (j = 0; j >= 0; j++){
			fseek(bfp, offs + (j * 4), SEEK_SET);
			fread(&b4, 1, 4, bfp);
			if (b4 == 0){   //ILTもしくはIATの終端
				ti[i].num_function = j;
				break; 
			}
			fprintf(itfp, " RVA: % 08X, ", ti[i].FirstThunk + (j * 4));   //IATのRVA出力

			if ((b4 & 0x80000000) != 0){   //序数の出力
				ord = b4 & 0x7FFFFFFF;
				fprintf(itfp, "Ord#: %4d(%04X)\n", ord, ord);
			}
			else{   //ヒントと名前出力
				if (b4 > th->SizeOfImage){   //適切なRVAではない場合、終了
					printf("ERROR: Get function\n");
					return -1; 
				}   
				fseek(bfp, PTRD + (b4 - VA), SEEK_SET);
				fread(&hint, 1, 2, bfp);
				fprintf(itfp, "Hint: %4d(%04X), Name: ", hint, hint);
				for (len = 0; len >= 0; len++){
					fread(&c1, 1, 1, bfp);
					fprintf(itfp, "%c", c1);
					if (c1 == '\0'){ break; }   //インポート関数名の終端
				}
				fputc('\n', itfp);
			}
		}
		if (j <= 0){   //IATのサイズが想定よりも大きい場合、終了
			printf("ERROR: over size of IAT\n");
			return -1;
		}
		fputc('\n', itfp);
	}
	
	return 0;
}