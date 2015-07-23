/* IMAGE_DATA_DIRECTORY構造体用 */
typedef struct IDD{
	char Name[20];
	unsigned long RVA;
	unsigned long Size;
}t_IDD;

/* セクション情報用の構造体 */
typedef struct Section{
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	unsigned long Characteristics;
}t_section;

/* Headerを解析して得た情報用の構造体 */
typedef struct Header{
	char htname[256];
	char itname[256];
	unsigned short NumberOfSections;
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	t_IDD IDD[16];
	t_section ts[10];
	struct NO{
		int text, idata;
	}no;
}t_header;

/* インポート情報用の構造体 */
typedef struct Idata{
	unsigned long OriginalFirstThunk;
	unsigned long Name;
	unsigned long FirstThunk;

	unsigned long ILT_rva[150];   //ILT自身のRVA
	unsigned long ILT[150];   //ILTが保持しているRVA
	int size_ILT;   //ILTの数

	unsigned long IAT_rva[150];   //IAT自身のRVA
	unsigned long IAT[150];   //IATが保持しているRVA
	int size_IAT;   //IATの数

	char dll[50];   //DLL名
	long OrdinalNumber[150];
	short Hint[150];
	char function[150][50];   //インポート関数名
}t_idata;


int Read_header(FILE *bfp, t_header *th);
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]);