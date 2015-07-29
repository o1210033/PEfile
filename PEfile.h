/* IMAGE_DATA_DIRECTORY構造体用 */
typedef struct IDD{
	char Name[20];
	unsigned long RVA;
	unsigned long Size;
}t_IDD;

/* セクション情報用の構造体 */
typedef struct SectionHeader{
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	unsigned long Characteristics;
}t_sheader;

/* Headerを解析して得た情報用の構造体 */
typedef struct Header{
	unsigned short NumberOfSections;
	unsigned long SizeOfCode;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	unsigned long SizeOfImage;
	t_IDD IDD[16];
	t_sheader *sh;
	int ptr_text;
}t_header;

/* インポート情報用の構造体 */
typedef struct Idata{
	unsigned long OriginalFirstThunk;   //ILTのRVA
	unsigned long Name;   //DLL名のRVA
	unsigned long FirstThunk;   //IATのRVA
	int num_function;   ////インポート関数の数
}t_idata;


int Read_header(FILE *htfp, FILE *bfp, t_header *th);
t_idata *Get_idata(FILE *bfp, t_header *th);
int Read_idata(FILE *itfp, FILE *bfp, t_header *th, t_idata *ti);