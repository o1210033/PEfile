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
	char htname[300];
	char itname[300];
	unsigned short NumberOfSections;
	unsigned long SizeOfCode;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	unsigned long SizeOfImage;
	t_IDD IDD[16];
	t_section ts[10];
	int ptr_text;
}t_header;

/* インポート情報用の構造体 */
typedef struct Idata{
	unsigned long OriginalFirstThunk;   //ILTのRVA
	unsigned long Name;   //DLL名のRVA
	unsigned long FirstThunk;   //IATのRVA

	int size_IAT;   //IATのサイズ
	char dll[50];   //DLL名
	long OrdinalNumber[150];   //序数
	short Hint[150];   //ヒント
	char function[150][50];   //インポート関数名
}t_idata;


int Read_header(FILE *bfp, t_header *th);
int Read_idata(FILE *bfp, t_header *th, t_idata ti[]);