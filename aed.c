/*
 * aed.c 
 * 2013/11/21
 * by Hui Zheng
 */
#include <sys/types.h>
#include <bsd/unistd.h>

#include <bsd/unistd.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "aed.h"

void 
display_usage()
{
    fputs("Usage: aed [-deh][-p passphase][-s salt]\n\n"
          "  -d Perform decryption of the input stream.\n"
          "  -e Perform encryption of the input stream.\n"
          "  -h Print a short usage summary and exit.\n"
          "  -p passphase Use the given passphase to derive the key\n"
          "  -s Use the given salt. If specified, then this needs to be exactly 8 hexadecimal characters\n"
          ,stdout);
}

int
main(int argc, char* argv[], char *envp[])
{
	int ch, count;
	read_buf buf;
	buf.size = 0;
	buf.len = 0;
	char buffer[buffer_size];
	char pass[buffer_size];
	char passtmp[buffer_size];
	opt_flag opt;
	opt.salt = NULL;
        FILE* fd;
	opt.pflag = 0;
	opt.eflag = 0;
	opt.dflag = 0;
	char* p=NULL;

	/*Get control terminal, to avoid the output redirection*/
	fd = fopen("/dev/tty","w");
	if(fd==NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	while ((ch = getopt(argc, argv, "dehp:s:")) != -1) {
		switch (ch) {
		case 'd':
			opt.dflag = 1;
			opt.eflag = 0;
			break;
		case 'e':
			opt.eflag = 1;
			opt.dflag = 0;
			break;
		case '?':
		case 'h':
			opt.hflag = 1;
			display_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'p':
			opt.pflag = 1;
			p = optarg;
			strcpy(opt.psphase, optarg);
			break;
		case 's':
			opt.sflag = 1;
			checksalt(optarg, &opt, fd);
			break;
		default: //no option
			fprintf(fd, "Try 'aed -h' for more information.\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	while((count = read(STDIN_FILENO, buffer, buffer_size-1)) > 0)
	{
		push_buffer(&buf, buffer, count);
	}
	freopen("/dev/tty", "r", stdin); 

	if(opt.pflag)
	{
		memset(p, '*', strlen(p)); 
	}
        else if(!opt.pflag && opt.eflag)
	{
	passphase:
                fprintf(fd,"Please enter the passphase for encryption: \n");
                fflush(stdout);
		fgets(pass, buffer_size, stdin);
		pass[strlen(pass)-1]='\0'; /*delete the new line*/
                fprintf(fd,"Please reenter the passphase: \n");
                fflush(stdout);
		fgets(passtmp,  buffer_size-1, stdin);
		passtmp[strlen(passtmp)-1]='\0';
		if(strcmp(pass, passtmp) == 0)
		{
			strcpy(opt.psphase, pass);
		}
		else
		{
			fprintf(fd, "Passphases mismatch, please try again.\n");
			goto passphase;
		}
	}
	else if((!opt.pflag) && opt.dflag)
	{
                fprintf(fd,"Please enter the passphase for decryption: \n");
                fflush(stdout);
		fgets(pass, buffer_size, stdin);
		pass[strlen(pass)-1]='\0';
		strcpy(opt.psphase, pass);
	}

	de_encryption(&opt, &buf);

	return EXIT_SUCCESS;
}

void checksalt(const char* str, opt_flag* opt, FILE* fd)
{
	if((strlen(str) != 8) ||
		strspn(str, "0123456789abcdefABCDEF") != 8)
	{
		fprintf(fd, "aed: the salt need to be\
		 8 hexadecimal characters.\n");
		exit(EXIT_FAILURE);
	}

	if((opt->salt = malloc(sizeof(char)*9)) == NULL)
		perror("malloc"),exit(EXIT_FAILURE);
	strcpy(opt->salt, str);
}

/*read the input from stdin, and put it into the buffer*/
void push_buffer(read_buf* buf, char* msg, int len)
{
    if(buf->size == 0)
    {
        if((buf->buffer = malloc(sizeof(char)*buffer_size)) == NULL)
        {
        	perror("malloc");
		exit(EXIT_FAILURE);
        }
        buf->size += buffer_size;
    }
    else if((buf->len + len) >= buf->size)
    {
         if(realloc(buf->buffer, buf->size + buffer_size) == NULL)
         {
             	perror("realloc");
		exit(EXIT_FAILURE);
         }
         buf->size += buffer_size;
    }

    memcpy(&(buf->buffer[buf->len]), msg, len);
    buf->len += len;
    buf->buffer[buf->len] = '\0';
}

void de_encryption(opt_flag* opt, read_buf* buf)
{	
	const EVP_CIPHER* cipher;
	EVP_CIPHER_CTX ctx;
	const EVP_MD* mode = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], 
		iv[EVP_MAX_KEY_LENGTH];
	unsigned char* outbuf;
	int outlen, tmplen;
	OpenSSL_add_all_algorithms();
	outbuf = malloc(sizeof(char)*(buf->len));
	if(outbuf==NULL)
	{
		perror("malloc");
       		exit(EXIT_FAILURE);
	}

	cipher = EVP_get_cipherbyname("aes-256-cbc");
	if(cipher==NULL)
	{
		perror("EVP_get_cipherbyname");
		exit(EXIT_FAILURE);
	}

	mode = EVP_get_digestbyname("SHA1");
	if(mode==NULL)
	{
		perror("EVP_get_digestbyname");
		exit(EXIT_FAILURE);
	}
	if(!EVP_BytesToKey(cipher, mode, 
		(const unsigned char*)opt->salt,
   		(unsigned char *) opt->psphase,
       		strlen(opt->psphase), 10000, key, iv))
   	{
       		perror("EVP_BytesToKey");
       		exit(EXIT_FAILURE);
    	}
	EVP_CIPHER_CTX_init(&ctx);

	if(opt->eflag) /*encryption*/
	{
		EVP_EncryptInit_ex(&ctx,  EVP_aes_256_cbc(), NULL, key, iv);
	
		if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, 
			(const unsigned char*)(buf->buffer), buf->len))
		{
			perror("EVP_EncryptUpdate");
	       		exit(EXIT_FAILURE);
		}
		if(!EVP_EncryptFinal_ex(&ctx, outbuf+outlen, &tmplen))
		{
			perror("EVP_EncryptFinal_ex");
	       		exit(EXIT_FAILURE);
		}
	}
	else  /*decription*/
	{
		EVP_DecryptInit_ex(&ctx,  EVP_aes_256_cbc(), NULL, key, iv);
	
		if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, 
			(const unsigned char*)(buf->buffer), buf->len))
		{
			perror("EVP_DecryptUpdate");
	       		exit(EXIT_FAILURE);
		}

		if(!EVP_DecryptFinal_ex(&ctx, outbuf+outlen, &tmplen))
		{
			perror("EVP_DecryptFinal_ex");
	       		exit(EXIT_FAILURE);
		}
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	write(STDOUT_FILENO, outbuf, outlen);
	return;	
}

