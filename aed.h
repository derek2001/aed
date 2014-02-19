/*
 * aed.h 
 * 2013/11/21
 * by Hui Zheng
 */
#define buffer_size 1024

typedef struct opt_flag_{
	int dflag;	/*-d flag, perform decryption*/
	int eflag;	/*-e flag, perform encryption*/
	int hflag;	/*-h flag, print usage*/
	int pflag;	/*-p flag, passphase*/
	char psphase[buffer_size];
	int sflag;	/*-s flag, use given salt*/
	char* salt;
}opt_flag;

typedef struct read_buf_{
    char* buffer;
    int len;
    int size;
}read_buf;

void de_encryption(opt_flag* opt, read_buf* buf);
void push_buffer(read_buf* buf, char* msg, int len);
void display_usage();
void checksalt(const char* str, opt_flag* opt, FILE* fd);
