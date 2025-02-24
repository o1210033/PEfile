/* main.c */
/* PEファイルの情報取得、逆アセンブル、結果出力 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>
#include <windows.h>

#include "disasm.h"
#include "PEfile.h"


//ファイルパス名取得用
char *Get_filename(void);

//逆アセンブル結果出力関連の関数
int Disasm_LinearSweep(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);
void change_reg(char reg_name[8][5], char reg[8][5]);
void Set_regname(char reg_name[8][5], int size_reg);
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);
int Print_function(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th, t_idata *ti);
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th);
int Print_RefDisasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti);



/* main関数 */
int main(void){
	int i;
	FILE *bfp, *htfp, *dtfp, *itfp;

	/* PEファイル名を取得＆拡張子以前のパス名を設定 */
	char szFile[320], fname[320], htname[320], dtname[320], itname[320];
	strcpy(szFile, Get_filename(szFile));
	strcpy(fname, szFile);
	for (i = 0; i < 300; i++){
		if (szFile[i] == '.')
			szFile[i] = '\0';
	}
	
	/* PEファイルのオープン処理 */
	if ((bfp = fopen(fname, "rb")) == NULL){
		printf("ERROR: fopen PEfile\n");
		exit(1);
	}

	/* ヘッダ情報を取得＆ファイル出力 */
	//ヘッダ情報出力ファイルをオープン
	sprintf(htname, "%s_Header.txt", szFile);
	if ((htfp = fopen(htname, "w")) == NULL){
		printf("ERROR: fopen *_Header.txt\n");
		fclose(bfp);
		exit(1);
	}
	fprintf(htfp, "[Header]\n\n");
	//ヘッダ情報を取得＆ファイル出力
	t_header th = { 0 };
	if (Read_header(htfp, bfp, &th) != 0){
		printf("ERROR: Read_header\n");
		if (th.sh != NULL){ free(th.sh); }
		fclose(bfp);
		fclose(htfp);
		exit(1);
	}
	fclose(htfp);   //ヘッダ情報出力ファイルをクローズ

	/* referenceナシの逆アセンブル結果をファイル出力 */
	// 逆アセンブル結果出力ファイルをオープン
	sprintf(dtname, "%s_Disasm.txt", szFile);
	if ((dtfp = fopen(dtname, "w")) == NULL){
		printf("ERROR: fopen *_Disasm.txt\n");
		free(th.sh);
		fclose(bfp);
		exit(1);
	}
	//referenceナシの逆アセンブル結果をファイル出力
	t_disasm da = { 0 };
	if (Disasm_LinearSweep(dtfp, bfp, &da, &th, NULL) != 0){
		printf("ERROR: Disasm_LinearSweep (not reference)\n");
		free(th.sh);
		fclose(bfp);
		fclose(dtfp);
		exit(1);
	}
	fclose(dtfp);   //逆アセンブル結果出力ファイルをクローズ

	/* インポート情報を取得＆ファイル出力 */
	//インポート情報出力ファイルをオープン
	sprintf(itname, "%s_Imports.txt", szFile);
	if ((itfp = fopen(itname, "w")) == NULL){
		printf("ERROR: fopen *_Imports.txt\n");
		free(th.sh);
		fclose(bfp);
		exit(1);
	}
	fprintf(itfp, "[IMPORTS]\n\n");
	//インポート情報を取得＆ファイル出力
	t_idata *ti = Get_idata(bfp, &th);
	if (ti == NULL){   //ti構造体の取得に失敗した場合
		printf("ERROR: Get_idata\n");
		free(th.sh);
		fclose(itfp);
		fclose(bfp);
		exit(1);
	}
	if (Print_idata(itfp, bfp, &th, ti) != 0){
		printf("ERROR: Print_idata\n");
		free(th.sh);
		free(ti);
		fclose(itfp);
		fclose(bfp);
		exit(1);
	}
	fclose(itfp);   //インポート情報出力ファイルをクローズ

	/* referenceアリの逆アセンブル結果をファイル出力 */
	// 逆アセンブル結果出力ファイルをオープン
	sprintf(dtname, "%s_RefDisasm.txt", szFile);
	if ((dtfp = fopen(dtname, "w")) == NULL){
		printf("ERROR: fopen *_RefDisasm.txt\n");
		free(th.sh);
		free(ti);
		fclose(bfp);
		exit(1);
	}
	//referenceアリの逆アセンブル結果をファイル出力
	if (Print_RefDisasm(dtfp, bfp, &da, &th, ti) != 0){
		printf("ERROR: Print RefDisasm\n");
		free(th.sh);
		free(ti);
		fclose(bfp);
		fclose(dtfp);
		exit(1);
	}
	fclose(dtfp);   //逆アセンブル結果出力ファイルをクローズ

	/* 動的確保したメモリ解放＆PEファイルのクローズ処理 */
	free(th.sh);
	free(ti);
	fclose(bfp);

	return 0;
}


/* オープンファイルダイアログを用いて得たファイル名を返す関数 */
char *Get_filename(void){
	char szFile[300] = {0};
	OPENFILENAME ofn = {0};

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "all file(*.*)\0*.*\0\0";
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.Flags = OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn) == 0){
		printf("ERROR: GetOpenFileName\n");
		exit(1);
	}

	return szFile;
}


/* .textセクションの読み込み＆逆アセンブル処理＆ファイル出力関数 */
int Disasm_LinearSweep(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
	int i, j;
	unsigned char hex;
	unsigned long rva;
	unsigned long AddressOfCode = th->ImageBase + th->sh[th->ptr_text].VirtualAddress;
	unsigned long EndAddressOfCode = th->ImageBase + th->sh[th->ptr_text].VirtualAddress + th->sh[th->ptr_text].SizeOfRawData;

	
	/* da構造体のaddr_code, offsの初期化 */
	da->addr_code = AddressOfCode;
	da->offs = 0;

	/* .textセクションの読み込み＆逆アセンブル処理＆ファイル出力 */
	fseek(bfp, th->sh[th->ptr_text].PointerToRawData, SEEK_SET);   //.textセクションの先頭へシーク
	while (da->addr_code < EndAddressOfCode){   //.textセクションの最後まで読み込み
		//ネイティブコード以外のデータ(IMAGE_DATA_DIRECTORY)部分は逆アセンブルしない
		for (i = 0; i < 16; i++){ da->flag_IDD[i] = 0; }
		while (1){
			rva = da->addr_code - th->ImageBase;
			for (i = 0; i < 16; i++){
				if (th->IDD[i].RVA <= rva && rva < th->IDD[i].RVA + th->IDD[i].Size){
					da->addr_code += th->IDD[i].Size - (rva - th->IDD[i].RVA);
					fseek(bfp, th->sh[th->ptr_text].PointerToRawData + (da->addr_code - AddressOfCode), SEEK_SET);
					da->flag_IDD[i] = 1;   //ファイル出力用のフラグセット
					break;
				}
			}
			if (i == 16){ break; }
		}

		//逆アセンブル処理
		if (Disasm(bfp, da) != 0){   //逆アセンブル失敗時、終了
			printf("ERROR: Disasm\n");
			return -1; 
		}

		//逆アセンブル結果をファイル出力
		if (dtfp != NULL){   //引数dtfpがNULLでない場合のみファイル出力
			Print_disasm(dtfp, bfp, da, th, ti);
		}

		//jump, call命令用のreference table 設定用
		if (ti != NULL){   //引数tiがNULLでない場合のみ実行
			if ((da->instruction[0] == 'J' && strcmp(da->instruction, "JMPF") != 0) || strcmp(da->instruction, "CALL") == 0){
				if (da->flag_ref == COUNT){   //jump, call命令の総数をカウント
					da->num_rtable++;
				}
				else if (da->flag_ref == SET){   //rtable構造体にjump, call命令の指定先・元アドレスと命令種類をセット
					da->rtable[da->ptr_rtable].src = da->addr_code;
					if (da->operand[0] == REL8){
						da->rtable[da->ptr_rtable].dst = da->addr_code + da->offs + (char)da->imm8;
					}
					else if (da->operand[0] == REL32){
						da->rtable[da->ptr_rtable].dst = da->addr_code + da->offs + (long)da->imm32;
					}
					if (strcmp(da->instruction, "JMP") == 0){
						da->rtable[da->ptr_rtable].flag = UJMP;
					}
					else if (da->instruction[0] == 'J'){
						da->rtable[da->ptr_rtable].flag = CJMP;
					}
					else if (strcmp(da->instruction, "CALL") == 0){
						da->rtable[da->ptr_rtable].flag = CALL;
					}
					da->ptr_rtable++;
				}
			}
		}
	
		//Addressの更新
		da->addr_code += da->offs;
		da->offs = 0;
	}

	return 0;
}


/* Set_regname関数に用いる関数 */
void change_reg(char reg_name[8][5], char reg[8][5]){
	int i;
	for (i = 0; i < 8; i++){
		strcpy(reg_name[i], reg[i]);
	}
}


/* 引数reg_name[8][5]にレジスタ名を格納する関数 */
void Set_regname(char reg_name[8][5], int size_reg){
	int i;
	char reg8[8][5] = {
		"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"
	};
	char reg16[8][5] = {
		"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"
	};
	char reg32[8][5] = {
		"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
	};
	char sreg[8][5] = {
		"ES", "CS", "SS", "DS", "FS", "GS", "res.", "res."
	};

	switch (size_reg)
	{
	case R8:
	case RM8:
		change_reg(reg_name, reg8);
		break;
	case R16:
	case RM16:
		change_reg(reg_name, reg16);
		break;
	case R32:
	case RM32:
		change_reg(reg_name, reg32);
		break;
	case SREG:
		change_reg(reg_name, sreg);
		break;
	default:
		break;
	}
}


/* 逆アセンブル結果をファイル出力 */
int Print_disasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
	int i, j;
	int size_code;
	int scale[4] = { 1, 2, 4, 8 };
	char data[50], reg_name[8][5];
	unsigned long ptr, rva;
	union{
		unsigned short b2;
		unsigned char b1[2];
	}bit16;
	union{
		unsigned long b4;
		unsigned char b1[4];
	}bit32;

	//ネイティブコード以外のデータ(IMAGE_DATA_DIRECTORY)部分
	for (i = 0; i < 16; i++){
		if (da->flag_IDD[i]){
			fprintf(dtfp, "\n* %s (%08X - %08X)\n\n", th->IDD[i].Name, th->ImageBase + th->IDD[i].RVA, th->ImageBase + th->IDD[i].RVA + th->IDD[i].Size - 1);
		}
	}

	//必要に応じて Reference of JUMP or CALL を出力
	if (da->flag_ref == PRINT){   //reference出力フラグ
		for (ptr = 0; ptr < da->num_rtable; ptr++){
			if (da->addr_code == da->rtable[ptr].dst){
				fprintf(dtfp, "\n* Referenced by (U)nconditional or (C)onditional Jump or (c)all at Address:\n");
				fprintf(dtfp, "| %08X", da->rtable[ptr].src);
				if (da->rtable[ptr].flag == UJMP){ fprintf(dtfp, "(U)"); }
				if (da->rtable[ptr].flag == CJMP){ fprintf(dtfp, "(C)"); }
				if (da->rtable[ptr].flag == CALL){ fprintf(dtfp, "(c)"); }
				for (ptr++; ptr < da->num_rtable; ptr++){
					if (da->addr_code == da->rtable[ptr].dst){
						fprintf(dtfp, ", %08X", da->rtable[ptr].src);
						if (da->rtable[ptr].flag == UJMP){ fprintf(dtfp, "(U)"); }
						if (da->rtable[ptr].flag == CJMP){ fprintf(dtfp, "(C)"); }
						if (da->rtable[ptr].flag == CALL){ fprintf(dtfp, "(c)"); }
					}
				}
				fprintf(dtfp, "\n|\n");
			}
		}
	}

	//メモリアドレスを出力
	fprintf(dtfp, "%08X|   ", da->addr_code);

	//prefixを出力
	for (i = 0; i < da->ptr_pref; i++){
		fprintf(dtfp, "%02X:", da->pref[i]);
		for (j = 3; j < 30; j++){	//空白部分の調節
			fputc(' ', dtfp);
		}
		fprintf(dtfp, "| PREFIX %02X:\n", da->pref[i]);
		fprintf(dtfp, "%08X|   ", da->addr_code + (i + 1));
	}

	//ネイティブコード出力
	size_code = 0;
	for (i = 0; i < da->size_opc; i++){
		fprintf(dtfp, "%02X ", da->opc[i]);
		size_code += 3;
	}

	if (da->flag_modrm){   //ModR/M アリ
		fprintf(dtfp, "%02X ", da->modrm.hex);
		size_code += 3;
	}

	if (da->flag_sib){   //SIB アリ
		fprintf(dtfp, "%02X ", da->sib.hex);
		size_code += 3;
	}

	switch (da->size_disp)	//ディスプレースメント アリ
	{
	case 8:
		fprintf(dtfp, "%02X ", da->disp8);
		size_code += 3;
		break;
	case 32:
		bit32.b4 = da->disp32;
		for (i = 0; i < 4; i++){
			fprintf(dtfp, "%02X", bit32.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	}

	switch (da->size_imm)	//即値 アリ
	{
	case 8:
		fprintf(dtfp, "%02X ", da->imm8);
		size_code += 3;
		break;
	case 16:
		bit16.b2 = da->imm16;
		for (i = 0; i < 2; i++){
			fprintf(dtfp, "%02X", bit16.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	case 32:
		bit32.b4 = da->imm32;
		for (i = 0; i < 4; i++){
			fprintf(dtfp, "%02X", bit32.b1[i]);
			size_code += 2;
		}
		fputc(' ', dtfp);
		size_code++;
		break;
	}

	for (; size_code < 30; size_code++){	//空白部分の調節
		fputc(' ', dtfp);
	}

	//x86命令を出力
	fprintf(dtfp, "| %-10s", da->instruction);

	//x86命令の引数を出力
	strcpy(data, "\0");
	for (i = 0; i < 3; i++){
		if (!da->operand[i]){ break; }

		if (i != 0 && da->operand[i] != -1){		//引数間の区切りを出力
			fprintf(dtfp, ", ");
		}

		Set_regname(reg_name, R32);
		switch (da->operand[i])
		{
		case IMM8:
			fprintf(dtfp, "%02Xh", da->imm8);
			break;
		case IMM16:
			fprintf(dtfp, "%04Xh", da->imm16);
			break;
		case IMM32:
			fprintf(dtfp, "%08Xh", da->imm32);
			break;
		case RM8:
		case RM16:
		case RM32:
			if (da->flag_sib){	//SIB アリ
				fprintf(dtfp, "%s", data);
				switch (da->modrm.mod)
				{
				case 0:
					if (da->sib.base == 5){
						if (da->sib.index == 4){
							fprintf(dtfp, "[%08Xh]", da->disp32);
						}
						else{
							fprintf(dtfp, "[%s*%d+%08Xh]", reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
						}
					}
					else{
						if (da->sib.index == 4){
							fprintf(dtfp, "[%s]", reg_name[da->sib.base]);
						}
						else{
							fprintf(dtfp, "[%s+%s*%d]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale]);
						}
					}
					break;
				case 1:
					if (da->sib.index == 4){
						fprintf(dtfp, "[%s+%02Xh]", reg_name[da->sib.base], da->disp8);
					}
					else{
						fprintf(dtfp, "[%s+%s*%d+%02Xh]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp8);
					}
					break;
				case 2:
					if (da->sib.index == 4){
						fprintf(dtfp, "[%s+%08Xh]", reg_name[da->sib.base], da->disp32);
					}
					else{
						fprintf(dtfp, "[%s+%s*%d+%08Xh]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
					}
					break;
				}
			}
			else{	//SIB ナシ
				switch (da->modrm.mod)
				{
				case 0:
					if (da->modrm.rm == 5){
						fprintf(dtfp, "%s[%08Xh]", data, da->disp32);
					}
					else{
						fprintf(dtfp, "%s[%s]", data, reg_name[da->modrm.rm]);
					}
					break;
				case 1:
					fprintf(dtfp, "%s[%s+%02Xh]", data, reg_name[da->modrm.rm], da->disp8);
					break;
				case 2:
					fprintf(dtfp, "%s[%s+%08Xh]", data, reg_name[da->modrm.rm], da->disp32);
					break;
				case 3:
					Set_regname(reg_name, da->operand[i]);
					fprintf(dtfp, "%s", reg_name[da->modrm.rm]);
					break;
				}
			}
			break;
		case REL8:
			fprintf(dtfp, "%08Xh", da->addr_code + da->offs + (char)da->imm8);
			break;
		case REL16:
			break;
		case REL32:
			fprintf(dtfp, "%08Xh", da->addr_code + da->offs + (long)da->imm32);
			break;
		case MOFFS8:
		case MOFFS16:
			break;
		case MOFFS32:
			fprintf(dtfp, "%s[%08Xh]", data, da->disp32);
			break;
		case DEF1:
			fprintf(dtfp, "1");
			break;
		case R8:
		case R16:
		case R32:
		case SREG:
			Set_regname(reg_name, da->operand[i]);
			fprintf(dtfp, "%s", reg_name[da->modrm.ro]);
			break;
		case EAX:
			fprintf(dtfp, "EAX");
			break;
		}
	}

	//必要に応じて注釈をファイル出力
	if (da->flag_ref == PRINT){   //reference出力フラグ
		rva = th->SizeOfImage + 1;
		if (da->size_disp == 32){   //ディスプレースメントフィールドが4バイトのとき
			rva = da->disp32 - th->ImageBase;
		}
		else if (da->size_imm == 32){   //即値フィールドが4バイトのとき
			rva = da->imm32 - th->ImageBase;
		}

		if (rva <= th->SizeOfImage){   //rvaの値がRVAの範囲内であるかどうか判定
			if (Print_function(dtfp, rva, bfp, th, ti) != 0){   //インポート関数の注釈
				Print_string(dtfp, rva, bfp, th);   //文字列の注釈
			}
		}
	}
	
	fputc('\n', dtfp);	//改行

	return 0;
}


/* 
引数rvaがIATを指している場合かつ、インポート関数名がわかる場合、
そのDLL名とインポート関数名をファイル出力する関数
成功の場合は0を、失敗の場合は-1を返す
*/
int Print_function(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th, t_idata *ti){
	int i, j, k, len;
	char c1;
	long ord;
	unsigned long offs_log, offs, b4;
	unsigned long VA, PTRD;   //IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置


	for (i = 0; ti[i].FirstThunk != 0; i++){
		for (j = 0; j < ti[i].num_function; j++){
			if (rva == ti[i].FirstThunk + (j * 4)){   //引数rvaがIATを指している場合
				//IMAGE_IMPORT_DESCRIPTORのRVAとファイル位置を取得
				VA = th->IDD[1].RVA;   //IMAGE_IMPORT_DESCRIPTORのRVAをIMAGE_DATA_DIRECTORY構造体より取得
				for (k = 0; k < th->NumberOfSections; k++){   //RVAからどのセクションにあるのかを特定し、ファイル位置を取得
					if (th->sh[k].VirtualAddress <= VA && VA <= th->sh[k].VirtualAddress + th->sh[k].VirtualSize){
						PTRD = VA - th->sh[k].VirtualAddress + th->sh[k].PointerToRawData;
						break;
					}
				}

				offs_log = ftell(bfp);   //初期ファイル位置を記憶

				//offsにILTもしくはIATのファイル位置をセット
				if (ti[0].OriginalFirstThunk != 0){   //ILTが存在する場合、ILTをセット
					offs = PTRD + (ti[i].OriginalFirstThunk - VA);
				}
				else{   //ILTが存在しない場合、IATをセット
					offs = PTRD + (ti[i].FirstThunk - VA);
				}
				fseek(bfp, offs + (j * 4), SEEK_SET);
				fread(&b4, 1, 4, bfp);

				//インポート関数名がわかる場合のみ、DLL名とインポート関数名出力
				if ((b4 & 0x80000000) != 0){   //序数指定の場合、終了
					return -1;
				}
				else{   //名前出力
					//DLL名出力
					fprintf(dtfp, "   | ");
					fseek(bfp, PTRD + (ti[i].Name - VA), SEEK_SET);
					for (len = 0; len >= 0; len++){
						fread(&c1, 1, 1, bfp);
						fprintf(dtfp, "%c", c1);
						if (c1 == '\0'){ break; }   //DLL名の終端
					}
					fputc(' ', dtfp);
					//インポート関数名出力
					fseek(bfp, PTRD + (b4 - VA) + 2, SEEK_SET);
					for (len = 0; len >= 0; len++){
						fread(&c1, 1, 1, bfp);
						fprintf(dtfp, "%c", c1);
						if (c1 == '\0'){ break; }   //インポート関数名の終端
					}
				}

				fseek(bfp, offs_log, SEEK_SET);   //初期ファイル位置にシーク
				return 0;
			}
		}
	}

	return -1;
}


/* 
引数rvaがASCIIもしくはUNICODE文字列を指す場合、その文字列をファイル出力する関数 
成功の場合0を、失敗の場合-1を返す
*/
int Print_string(FILE *dtfp, unsigned long rva, FILE *bfp, t_header *th){
	int i;
	long offs_log, offs_string;
	char c, str[200];
	wchar_t wc, wstr[200];


	offs_log = ftell(bfp);   //初期ファイル位置を記憶

	/* 引数rvaが初期化されたデータを含むセクション内であれば、ファイル位置を取得 */
	for (i = 0; i < th->NumberOfSections; i++){
			if (th->sh[i].VirtualAddress <= rva && rva <= th->sh[i].VirtualAddress + th->sh[i].VirtualSize){
				if (th->sh[i].Characteristics == 0x40000040){   //初期化されたデータを含むセクションであるかどうか判定
					offs_string = rva - th->sh[i].VirtualAddress + th->sh[i].PointerToRawData;
					break;
				}
			}
	}
	if (i == th->NumberOfSections){ return -1; }   //引数rvaが条件に合わない場合、終了

	/* 引数rvaが指すデータがASCII文字列であるか判定し、そうであれば出力 */
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&c, 1, 1, bfp);
		if (c < 0x20 || 0x7e < c){ break; }
		str[i] = c;
	}
	if (i >= 4){
		str[i] = '\0';
		fprintf(dtfp, "   | ASCII \"%s\"", str);
		if (i == 100){ fprintf(dtfp, "..."); }
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	/* 引数rvaが指すデータがUNICODE文字列であるか判定し、そうであれば出力 */
	fseek(bfp, offs_string, SEEK_SET);
	for (i = 0; i < 100; i++){
		fread(&wc, 1, 2, bfp);
		if (wc < 0x0020 || 0x007e < wc){ break; }
		wstr[i] = wc;
	}
	if (i >= 4){
		wstr[i] = L'\0';
		fwprintf(dtfp, L"   | UNICODE \"%s\"", wstr);
		if (i == 100){ fprintf(dtfp, "..."); }
		fseek(bfp, offs_log, SEEK_SET);
		return 0;
	}

	fseek(bfp, offs_log, SEEK_SET);   //初期ファイル位置にシーク
	return -1;
}


/* referenceアリの逆アセンブル結果をファイル出力する関数 */
int Print_RefDisasm(FILE *dtfp, FILE *bfp, t_disasm *da, t_header *th, t_idata *ti){
	/* jump, call命令の総数をカウント */
	da->flag_ref = COUNT;
	da->num_rtable = 0;
	if (Disasm_LinearSweep(NULL, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:COUNT)\n");
		return -1;
	}

	/* rtable構造体をjump, call命令の総数だけ動的確保 */
	da->rtable = (t_rtable *)calloc(da->num_rtable, sizeof(t_rtable));
	if (da->rtable == NULL){
		printf("ERROR: calloc rtable\n");
		return -1;
	}

	/* rtable構造体にjump, call命令の指定先・元アドレスと命令種類をセット */
	da->flag_ref = SET;
	da->ptr_rtable = 0;
	if (Disasm_LinearSweep(NULL, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:SET)\n");
		free(da->rtable);
		return -1;
	}

	/* referenceアリの逆アセンブル結果をファイル出力 */
	da->flag_ref = PRINT;
	if (Disasm_LinearSweep(dtfp, bfp, da, th, ti) != 0){
		printf("ERROR: Disasm_LinearSweep (da->flag_ref:PRINT)\n");
		free(da->rtable);
		fclose(bfp);
		return -1;
	}

	/* 動的確保したrtable構造体のメモリを解放 */
	free(da->rtable);

	return 0;
}