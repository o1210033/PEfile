#include <stdio.h>

#include "PEfile.h"



int Read_idata(FILE *bfp, t_header *th, t_idata ti[]){
	int i, j;
	int num_dll = 0;
	int size_name;
	char c1;
	unsigned short b2;
	unsigned long b4;
	unsigned long offs;
	unsigned long ptrd = th->ts[th->no.idata].PointerToRawData;
	unsigned long rva = th->ts[th->no.idata].VirtualAddress;


	printf("RVA:  %08X\n", rva);
	printf("ptrd: %08X\n", ptrd);

	offs = ptrd;
	for (i = 0; ; i++){
		fseek(bfp, offs, SEEK_SET);
		fread(&b4, 1, 4, bfp);
		ti[i].OriginalFirstThunk = b4;

		fseek(bfp, 8, SEEK_CUR);
		fread(&b4, 1, 4, bfp);
		ti[i].Name = b4;

		fread(&b4, 1, 4, bfp);
		if (b4 == 0){ break; }
		ti[i].FirstThunk = b4;

		printf("%08X\n", ti[i].OriginalFirstThunk);

		num_dll++;
		offs += 20;
	}
	printf("\n");

	for (i = 0; i < num_dll; i++){
		unsigned long addr = ti[i].FirstThunk;
		fseek(bfp, ptrd + ti[i].FirstThunk - rva, SEEK_SET);

		ti[i].size_IAT = 0;
		for (j = 0; ; j++){
			fread(&b4, 1, 4, bfp);
			if (b4 == 0){ break; }
			ti[i].IAT[j] = b4;
			printf("%08X\n", ti[i].IAT[j]);

			ti[i].IAT_rva[j] = addr;
			addr += 4;
			ti[i].size_IAT++;
		}
		printf("\n");
	}

	for (i = 0; i < num_dll; i++){
		fseek(bfp, ptrd + ti[i].Name - rva, SEEK_SET);
		fscanf(bfp, "%s", ti[i].dll);
		printf("DLL: %s\n", ti[i].dll);
		
		for (j = 0; j < ti[i].size_IAT; j++){
			fseek(bfp, ptrd + ti[i].IAT[j] - rva, SEEK_SET);
			fread(&b2, 1, 2, bfp);
			ti[i].Hint[j] = b2;
			fscanf(bfp, "%s", ti[i].function[j]);
			printf("rva: %08X, hint: %04X, function: %s\n", ti[i].IAT_rva[j], ti[i].Hint[j], ti[i].function[j]);
		}
		printf("\n");
	}
	

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