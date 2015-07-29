/* IMAGE_DATA_DIRECTORY�\���̗p */
typedef struct IDD{
	char Name[20];
	unsigned long RVA;
	unsigned long Size;
}t_IDD;

/* �Z�N�V�������p�̍\���� */
typedef struct SectionHeader{
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	unsigned long Characteristics;
}t_sheader;

/* Header����͂��ē������p�̍\���� */
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

/* �C���|�[�g���p�̍\���� */
typedef struct Idata{
	unsigned long OriginalFirstThunk;   //ILT��RVA
	unsigned long Name;   //DLL����RVA
	unsigned long FirstThunk;   //IAT��RVA
	int num_function;   ////�C���|�[�g�֐��̐�
}t_idata;


int Read_header(FILE *htfp, FILE *bfp, t_header *th);
t_idata *Get_idata(FILE *bfp, t_header *th);
int Read_idata(FILE *itfp, FILE *bfp, t_header *th, t_idata *ti);