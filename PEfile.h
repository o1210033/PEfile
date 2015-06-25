typedef struct Section{
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
}t_section;

/* Header‚ğ‰ğÍ‚µ‚Ä“¾‚½î•ñ—p‚Ì\‘¢‘Ì */
typedef struct Header{
	char htname[256];
	char itname[256];
	unsigned long BaseOfCode;
	unsigned long ImageBase;
	t_section ts[10];
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	struct NO{
		int text, idata;
	}no;
}t_header;


typedef struct Idata{
	unsigned long OriginalFirstThunk;
	unsigned long Name;
	unsigned long FirstThunk;

	unsigned long IAT_rva[256];
	unsigned long IAT[256];
	int size_IAT;

	char dll[64];
	unsigned short Hint[256];
	char function[256][64];
}t_idata;



int Read_idata(FILE *bfp, t_header *th, t_idata ti[]);