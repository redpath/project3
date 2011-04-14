/*
  _            _                 
   /_  /_ _   /_/_   _/_  _ _/_/_
(_//_// // / / \/_'/_//_//_|/ / / *
                     /   
(John Redpath)
01:198:352
SP2011
Lab 1

header.h
*/
#ifndef helper_H__
#define helper_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

#include <pthread.>
#include <errno.h>

#define MAXFNLEN 256
#define MAXDIRLEN 256
#define HEADERSZ 24
#define MD5SZ 16
#define CODESZ 4

char STOK [4] = {2,0,1,0}; 
char RSND[4]= 	{2,0,2,0};
char ABT[4]= 	{2,0,4,0}; 
char FIN[4]= 	{2,0,8,0}; 

void error(const char *msg)
{
		perror(msg);
		exit(1);
}
int code_cmp(char *str1, char *str2)
{
	if(str1[0]==str2[0]&& str1[1]==str2[1]&& str1[2]==str2[2]&& str1[3]==str2[3])
        return 0;
	else 
		return -1;
}
char* convertmd5(char* string)
{
	EVP_MD_CTX md5ctx;
	unsigned char md5str[EVP_MAX_MD_SIZE];
	int c = 0;
	unsigned int md5strlen = MD5SZ;
	char *output;
	const EVP_MD *md;

    if((output = (char*)malloc(sizeof(char)*MD5SZ))==NULL) err("MD5 memory\n");

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("MD5");
	EVP_MD_CTX_init(&md5ctx);
	EVP_DigestInit_ex(&md5ctx, md, NULL);
	EVP_DigestUpdate(&md5ctx, string, strlen(string));
	EVP_DigestFinal_ex(&md5ctx, md5str, &md5strlen);

	for(c = 0; c < md5strlen; c++)
    	output[c]=md5str[c];

	EVP_MD_CTX_cleanup(&md5ctx);
	return output;
}

typedef struct Meta_Struct
{
	
	int filenamesz;
	char filename[200];
	int file_size;
	time_t modified_time;
	unsigned char update_status; // 1: Updated ; 0: Not updated
		
}MetaStruct;

typedef struct File_Time_Node { // A node used in keeping track of file updates
	
	char * filename;
	time_t time;
	int new;
	struct File_Time_Node * next;
}FileTimeNode;

typedef struct File_Times_List { // Linked list comprised of above nodes
	FileTimeNode * head;
}FileTimesList;

#endif
