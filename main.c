#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "disasm.h"
#include "PEfile.h"


int Disasm(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]);
char *Get_filename(void);
void change_reg(char reg_name[8][5], char reg[8][5]);
void Set_regname(char reg_name[8][5], int size_reg);
void Print_function(FILE *tfp, t_idata ti[], unsigned long rva);


/* main関数 */
int main(void){
	int i;

	FILE *bfp;
	t_disasm da;
	t_header th;
	t_idata ti[32];
	char szFile[256], fname[256];

	/* 必要なファイル名を取得、設定 */
	//strcpy(szFile, Get_filename(szFile));
	strcpy(szFile, "wsample01a.exe");
	strcpy(fname, szFile);
	for (i = 0; i < 256; i++){
		if (szFile[i] == '.')
			szFile[i] = '\0';
	}
	sprintf(da.dtname, "%s_Disasm.txt", szFile);
	sprintf(th.htname, "%s_Header.txt", szFile);
	sprintf(th.itname, "%s_Imports.txt", szFile);


	/* PEファイルのオープン処理 */
	if ((bfp = fopen(fname, "rb")) == NULL){
		printf("\aファイルをオープンできません。\n");
		exit(1);
	}

	/* ヘッダ情報を取得＆ファイル出力 */
	if (Read_header(bfp, &th) == 1){
		printf("\aFailed Read_header\n");
		exit(1);
	}

	/* インポート情報を取得＆ファイル出力 */
	Read_idata(bfp, &th, ti);

	/* .textセクションの読み込み＆逆アセンブル処理＆ファイル出力 */
	Disasm(bfp, &da, &th, ti);

	/* PEファイルのクローズ処理 */
	fclose(bfp);

	//出力結果ファイルをメモ帳で開く
	//char cmdbuf[300];
	//sprintf(cmdbuf, "notepad %s", th.htname);
	//system(cmdbuf);
	//sprintf(cmdbuf, "notepad %s", tname);
	//system(cmdbuf);

	return 0;
}

/* .textセクションの読み込み＆逆アセンブル処理＆ファイル出力関数 */
int Disasm(FILE *bfp, t_disasm *da, t_header *th, t_idata ti[]){
	int i, n;
	FILE *dtfp;
	unsigned long addr_code = th->ImageBase + th->ts[th->no.text].VirtualAddress;
	unsigned long offs = 0;
	unsigned long rva;
	int size_code;
	int scale[4] = { 1, 2, 4, 8 };
	char data[20];
	char reg_name[8][5];
	unsigned char hex, opc, modrm;
	union{
		unsigned short b2;
		unsigned char b1[2];
	}bit16;
	union{
		unsigned long b4;
		unsigned char b1[4];
	}bit32;

	/* 逆アセンブル結果出力ファイルのオープン処理 */
	if ((dtfp = fopen(da->dtname, "w")) == NULL){
		printf("\aファイルをオープンできません。\n");
	}

	/* .textセクションの読み込み＆逆アセンブル処理＆ファイル出力 */
	fseek(bfp, th->ts[th->no.text].PointerToRawData, SEEK_SET);   //.textセクションの先頭へシーク
	while (((n = fread(&hex, 1, 1, bfp)) > 0) && offs < th->ts[th->no.text].SizeOfRawData){   //.textセクションの最後まで読み込み
		//ネイティブコード以外のデータ部分は省略
		while (1){
			rva = th->ts[th->no.text].VirtualAddress + offs;
			for (i = 0; i < 16; i++){
				if (th->IDD[i].RVA <= rva && rva < th->IDD[i].RVA + th->IDD[i].Size){
					fprintf(dtfp, "\n* %s (%08X - %08X)\n\n", th->IDD[i].Name, th->ImageBase + th->IDD[i].RVA, th->ImageBase + th->IDD[i].RVA + th->IDD[i].Size - 1);
					offs += th->IDD[i].Size - (rva - th->IDD[i].RVA);
					fseek(bfp, th->ts[th->no.text].PointerToRawData + offs, SEEK_SET);
					if ((n = fread(&hex, 1, 1, bfp)) == 0 || offs >= th->ts[th->no.text].SizeOfRawData){ 
						fclose(dtfp);
						return 0; 
					}
					break;
				}
			}
			if (i == 16){ break; }
		}

		//メモリアドレスを出力
		fprintf(dtfp, "%08X|   ", addr_code + offs);
		offs++;

		//ネイティブコードを出力＆解析
		fprintf(dtfp, "%02X", hex);
		size_code = 2;
		Init_disasm(da);

		//prefixの有無を確認
		Check_pref(da, hex);
		if (da->flag_pref){	//prefix アリの場合、ネイティブコード解析を中止
			fputc(':', dtfp);
			size_code++;
		}
		else{	//prefix ナシの場合、ネイティブコード解析を続行
			fputc(' ', dtfp);
			size_code++;
			da->size_opc = 1;
			while (Set_opc(da, hex)){   //opcodeの解析
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(dtfp, "%02X ", hex);
				size_code += 3;
			}
			if (da->flag_modrm){		//ModR/M アリ
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(dtfp, "%02X ", hex);
				size_code += 3;
				Set_modrm(da, hex);
			}
			if (da->flag_sib){		//SIB アリ
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(dtfp, "%02X ", hex);
				size_code += 3;
				Set_sib(da, hex);
			}
			switch (da->size_disp)	//ディスプレースメント アリ
			{
			case 8:
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(dtfp, "%02X ", hex);
				size_code += 3;
				da->disp8 = hex;
				break;
			case 32:
				fread(&bit32.b1, 1, 4, bfp);
				offs += 4;
				for (i = 0; i < 4; i++){
					fprintf(dtfp, "%02X", bit32.b1[i]);
				}
				fputc(' ', dtfp);
				size_code += 9;
				da->disp32 = bit32.b4;
				break;
			}
			switch (da->size_imm)	//即値 アリ
			{
			case 8:
				fread(&hex, 1, 1, bfp);
				offs++;
				fprintf(dtfp, "%02X ", hex);
				size_code += 3;
				da->imm8 = hex;
				break;
			case 16:
				fread(&bit16.b1, 1, 2, bfp);
				offs += 2;
				for (i = 0; i < 2; i++){
					fprintf(dtfp, "%02X", bit16.b1[i]);
				}
				fputc(' ', dtfp);
				size_code += 5;
				da->imm16 = bit16.b2;
				break;
			case 32:
				fread(&bit32.b1, 1, 4, bfp);
				offs += 4;
				for (i = 0; i < 4; i++){
					fprintf(dtfp, "%02X", bit32.b1[i]);
				}
				fputc(' ', dtfp);
				size_code += 9;
				da->imm32 = bit32.b4;
				break;
			}
		}

		for (; size_code < 30; size_code++){	//空白部分の調節
			fputc(' ', dtfp);
		}

		//prefix or x86命令を出力
		if (da->flag_pref){		//prefix アリの場合、prefixを出力
			fprintf(dtfp, "| PREFIX %s:", da->asm);
		}
		else{	//prefix ナシの場合、x86命令を出力
			fprintf(dtfp, "| %-10s", da->asm);
			//x86命令の引数を出力
			Set_regname(reg_name, R32);
			strcpy(data, "\0");
			for (i = 0; i < 3; i++){
				if (!da->arg[i]){ break; }

				if (i != 0 && da->arg[i] != -1){		//引数間の区切りを出力
					fputc(',', dtfp);
				}

				switch (da->arg[i])
				{
				case IMM8:
					fprintf(dtfp, "%02X", da->imm8);
					break;
				case IMM16:
					fprintf(dtfp, "%04X", da->imm16);
					break;
				case IMM32:
					fprintf(dtfp, "%08X", da->imm32);
					break;
				case R8:
				case R16:
				case R32:
				case SREG:
					Set_regname(reg_name, da->arg[i]);
					fprintf(dtfp, "%s", reg_name[da->modrm.ro]);
					break;
				case EAX:
					fprintf(dtfp, "EAX");
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
									fprintf(dtfp, "[%08X]", da->disp32);
								}
								else{
									fprintf(dtfp, "[%s*%d+%08X]", reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
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
								fprintf(dtfp, "[%s+%02X]", reg_name[da->sib.base], da->disp8);
							}
							else{
								fprintf(dtfp, "[%s+%s*%d+%02X]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp8);
							}
							break;
						case 2:
							if (da->sib.index == 4){
								fprintf(dtfp, "[%s+%08X]", reg_name[da->sib.base], da->disp32);
							}
							else{
								fprintf(dtfp, "[%s+%s*%d+%08X]", reg_name[da->sib.base], reg_name[da->sib.index], scale[da->sib.scale], da->disp32);
							}
							break;
						}
					}
					else{	//SIB ナシ
						switch (da->modrm.mod)
						{
						case 0:
							if (da->modrm.rm == 5){
								fprintf(dtfp, "%s[%08X]", data, da->disp32);
							}
							else{
								fprintf(dtfp, "%s[%s]", data, reg_name[da->modrm.rm]);
							}
							break;
						case 1:
							fprintf(dtfp, "%s[%s+%02X]", data, reg_name[da->modrm.rm], da->disp8);
							break;
						case 2:
							fprintf(dtfp, "%s[%s+%08X]", data, reg_name[da->modrm.rm], da->disp32);
							break;
						case 3:
							Set_regname(reg_name, da->arg[i]);
							fprintf(dtfp, "%s", reg_name[da->modrm.rm]);
							break;
						}
					}
					break;
				case REL8:
					fprintf(dtfp, "%08X", addr_code + offs + (char)da->imm8);
					break;
				case REL16:
					break;
				case REL32:
					fprintf(dtfp, "%08X", addr_code + offs + (long)da->imm32);
					break;
				case MOFFS8:
				case MOFFS16:
					break;
				case MOFFS32:
					fprintf(dtfp, "%s[%08X]", data, da->imm32);
					break;
				case DEF1:
					fprintf(dtfp, "1");
					break;
				}
			}

			//必要に応じて注釈を出力
			if (da->size_disp == 32){
				Print_function(dtfp, ti, da->disp32 - th->ImageBase);
			}
		}

		fputc('\n', dtfp);	//改行

		//flag_prefのリセット
		if (!da->flag_pref){
			for (i = 0; i < 5; i++){
				da->pref[i] = -1;
			}
		}
	}

	fclose(dtfp);
	return 0;
}

/* オープンファイルダイアログを用いて得たファイル名を返す関数 */
char *Get_filename(void){
	int i;
	OPENFILENAME ofn;
	char szFile[256];

	szFile[0] = '\0';
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "all file(*.*)\0*.*\0\0";
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.Flags = OFN_FILEMUSTEXIST;

	GetOpenFileName(&ofn);

	return szFile;
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

/* RVAからDLL名とインポート関数をファイル出力する関数 */
void Print_function(FILE *tfp, t_idata ti[], unsigned long rva){
	int i, j;

	for (i = 0;; i++){
		if (ti[i].OriginalFirstThunk == 0){ break; }
		for (j = 0;; j++){
			if (ti[i].ILT[j] == 0 || (ti[i].ILT[j] & 0x80000000) != 0){ break; }
			else if (ti[i].IAT_rva[j] == rva){
				fprintf(tfp, "   | %s %s", ti[i].dll, ti[i].function[j]);
			}
		}
	}
}