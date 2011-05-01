/*
  _            _                 
   /_  /_ _   /_/_   _/_  _ _/_/_
(_//_// // / / \/_'/_//_//_|/ / / *
                     /   
(John Redpath)
01:198:352
SP2011
Lab 2

client.c
*/
#include "header.h"

#define NUM_THREADS 2

#define S_THREAD 0
#define R_THREAD 1

pthread_mutex_t count_mutex     = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t lock;

struct t_args{
	struct hostent * server;
	int sockfd;
	int port;
	char * dir;
	int chunksize;
	int thread_id;
};

struct t_args state_struct[NUM_THREADS];


pthread_t threads[NUM_THREADS];


MetaStruct * CreateMetaStruct(int filnamesz, char * filename, time_t tm)
{
	MetaStruct * met = (MetaStruct*)malloc(sizeof(MetaStruct));
	strcpy(met->filename,filename);
	met->filenamesz = filnamesz;
	met->modified_time = tm;

	return met;
}

MetaStruct * ReadFromMeta(FILE * meta)
{
	MetaStruct * met = (MetaStruct*)malloc(sizeof(MetaStruct));
	if((fread((void*)met, sizeof(MetaStruct), 1, meta)) == 0)
	{
		free(met);
		return NULL;
	}
	return met;
}

FileTimeNode * CreateFileTimeNode(char * filname, time_t tm, int filenamesz)
{
	FileTimeNode * node = (FileTimeNode*)malloc(sizeof(FileTimeNode));
	node->filename = (char*)malloc(sizeof(char) * filenamesz);
	strcpy(node->filename, filname);
	node->time = tm;
	node->new = 1;
	return node;
}

FileTimesList * CreateTimeList()
{
	FileTimesList * list = (FileTimesList*)malloc(sizeof(FileTimesList));
	list->head = NULL;
	return list;
}

int AddFileToList(FileTimesList * list, char * filname, int filenamesz, time_t tm)
{
	FileTimeNode * ptr = list->head;
	
	fflush(stdout);
	if(list->head == NULL)
	{
		list->head = CreateFileTimeNode(filname, tm, filenamesz);
		list->head->next = NULL;
		return 2;
	}
	else
	{
		if(strcmp(list->head->filename, filname) == 0)
		{
			if(difftime(list->head->time, tm) == 0.0)
			{	
				list->head->new = 0;
				return 1;
			}
			else
			{
				list->head->new = 1;
				return 1;
			}
		}
		
	}
	
	while(ptr->next != NULL)
	{
		if(strcmp(ptr->next->filename, filname) == 0)
		{		
			if(difftime(ptr->next->time, tm) == 0.0)
			{
				ptr->next->new = 0;
				return 0;
			}
			ptr->next->new = 1;
			return 1;
		}
		ptr = ptr->next;
	}
	ptr->next = CreateFileTimeNode(filname, tm, filenamesz);
	ptr->next->next = NULL;
	return 2;
}



void AccumulateFileList(DIR * direct, FileTimesList * list)
{
	struct dirent * dirinfo = (struct dirent *)malloc(sizeof(struct dirent));
	struct stat * timehold = (struct stat *)malloc(sizeof(struct stat));
	time_t tm;
	char filename[256];
	char dataslash[6] = "data/";
	while((dirinfo = readdir(direct)) != NULL)
	{
		memcpy((void*)filename, (void*)dataslash, 5);
		memcpy((void*)(filename + 5), (void*)dirinfo->d_name, strlen(dirinfo->d_name) + 1);
		stat(filename, timehold);
		tm = timehold->st_mtime;
		if(dirinfo->d_name[0] != '.' && strcmp(dirinfo->d_name,"META-DATA") != 0)
		{
			fflush(stdout);
			AddFileToList(list, dirinfo->d_name, strlen(dirinfo->d_name) + 1, tm);
		}
	}
	
	
}

void MetaListUpdate(FileTimesList * list)
{
	FILE * meta;
	MetaStruct * met;
	char holder[50];
	meta = fopen("data/META-DATA", "rb");
	while((met = ReadFromMeta(meta)) != NULL)
	{
		AddFileToList(list, met->filename, strlen(met->filename) + 1, met->modified_time);
	}
	fclose(meta);
}


int AcceptFile(int acceptedsock, char * dirname)
{
	FILE * file;
	int chunksz;
	char resendbuf[4];
	char okbuf[4];
	char buffer[2000];
	
	int aborted = 0;
	int finished = 0;
	
	EVP_MD_CTX mdctx;     //md5
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len = 16;   
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("MD5");  // "md5"
	
	short int stattype = 2;
	short int reqtype = 6;
	short int resmes = 2;
	short int okmes = 1;
	char mdval[16];
	short int type;
	unsigned char mdsig[16];
	int dirlen = strlen(dirname);
	
	short int filenamesz;
	char * filename;
	char * chunk;
	short int status;
	char fullpath[100];
	char slash[2] = "/";
	memcpy((void*)fullpath, (void*)dirname, dirlen);
	memcpy((void*)(fullpath + dirlen), (void*)slash, 1);
		
	memcpy((void*)resendbuf, (void*)&stattype, 2);
	memcpy((void*)(resendbuf + 2), (void*)&resmes, 2);
	
	memcpy((void*)okbuf, (void*)&stattype, 2);
	memcpy((void*)(okbuf + 2), (void*)&okmes, 2);
	
	memset(buffer,0, 2000);
	
	if(read(acceptedsock, buffer, 1999) < 0)
	{
		perror("Read failed");
		return 0;
	}
	memcpy((void*)&type, (void*)buffer, 2);
	if(type == 9)
	  {
	    file = fopen("data/META-DATA", "wb");
	    fclose(file);
	    return 9;
	  }
	memcpy((void*)mdsig, (void*)(buffer + 2), 16);
	memcpy((void*)&chunksz, (void*)(buffer + 18), 4);
	
	chunk = (char*)malloc(chunksz);
	memcpy((void*)&filenamesz, (void*)(buffer + 22), 2);
	filename = (char*)malloc(filenamesz);
	memcpy((void*)filename, (void*)(buffer + 24), (size_t)filenamesz);
	memcpy((void*)chunk, (void*)(buffer + 24 + filenamesz), (size_t)chunksz);
	
	memcpy((void*)(fullpath + dirlen + 1), (void*)filename, filenamesz);

	printf("fullpath: %s\n", fullpath);
	file = fopen(fullpath, "wb");
	
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);	
	EVP_DigestUpdate(&mdctx, chunk, (size_t)chunksz);	
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);

	memcpy((void*)mdval, (void*)md_value, 16);
	
	fflush(stdout);
	while(1)
	{	  
		if(memcmp(mdval, mdsig, 16) == 0)
		{
			fwrite(chunk, 1, chunksz, file);
			write(acceptedsock, okbuf, 4);
		}
		else
		{
			write(acceptedsock, resendbuf, 4);
		}
		read(acceptedsock, buffer, 2000);
		memcpy((void*)&type, (void*)buffer, 2);
		if(type == 2)
		{
			memcpy((void*)&status, (void*)(buffer + 2), 2);
			if(status == 8)
			{
				finished = 1;
				break;
			}
			if(status == 4)
			{
				aborted = 1;
				break;
			}
		}
		else
		{  
			memcpy((void*)&mdsig, (void*)(buffer + 2), 16);	
			memcpy((void*)chunk, (void*)(buffer + 24 + filenamesz), (size_t)chunksz);
			
			if(chunk == NULL)
			  {
			    printf("Chunk is null\n");
			  }
		
			EVP_DigestInit_ex(&mdctx, md, NULL);
			EVP_DigestUpdate(&mdctx, chunk, (size_t)chunksz);
			EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
			memcpy((void*)mdval, (void*)md_value, 16);
			
		}		
	}  //end while
	
	fclose(file);
	if(aborted == 1)
	{
		EVP_MD_CTX_cleanup(&mdctx);
		unlink(filename);	
	}
	
	if(finished == 1)
	{
		EVP_MD_CTX_cleanup(&mdctx);
		printf("File transfer successful\n");
	}
}


void CreateChunkPacket(char * packet, char * md5sig, int chunksz, short int filenamesz, char * filename, char * chunk)
{
	short int type = 1;
	short int sz = filenamesz;
	int chunksztemp = chunksz;

	memcpy((void*)packet, (void*)&type, 2);
	memcpy((void*)(packet + 2), (void*)md5sig, 16);
	memcpy((void*)(packet + 18),(void*)&chunksztemp, 4);
	memcpy((void*)(packet + 22),(void*)&sz, 2);
	memcpy((void*)(packet + 24),(void*)filename, (size_t)sz);
	memcpy((void*)(packet + 24 + sz), (void*)chunk, (size_t)(chunksztemp));
}

int SendFile(char * filename, int sockfd, int chunksz, short int filsz, char * dirname)
{
	int counter = 0;
	FILE * file;
	int err;
	
	int dirlen = strlen(dirname);
	char slash[2] = "/";
	char fileopened[100];
	
	short int stattype = 2;
	short int finmess = 8;
	
	char * chunkbuf;
	char * buffer;
	char finbuf[4];
	
	short int status = 0;
	int sockrep;
	char statusbuffer[4];

	struct stat st;
	off_t sz;

	memcpy((void*)fileopened, (void*)dirname, dirlen);
	memcpy((void*)(fileopened + dirlen), (void*)slash, 1);
	memcpy((void*)(fileopened + dirlen + 1), (void*)filename, filsz);
	
	stat(fileopened, &st);
	sz = st.st_size;
	if(sz == 0){	}
	
	memcpy((void*)finbuf, &stattype, 2);
	memcpy((void*)(finbuf + 2), &finmess, 2);
	
	buffer = (char*)malloc(chunksz + filsz + 24);
	chunkbuf = (char*)malloc(chunksz);
	
	EVP_MD_CTX mdctx;     //md5
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len = 16;   
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("MD5");  // "md5"
	file = fopen(fileopened, "rb");
	
	while(!feof(file))
	{	
		if(status < 2)
		{			
			memset(buffer,0, (chunksz + filsz + 24));
			
			err = fread((void*)chunkbuf, 1, chunksz, file);
			if(err == 0)
			{
				break;
			}
			
			EVP_MD_CTX_init(&mdctx);
			EVP_DigestInit_ex(&mdctx, md, NULL);
			EVP_DigestUpdate(&mdctx, chunkbuf, chunksz);
			EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
			EVP_MD_CTX_cleanup(&mdctx);
		
			CreateChunkPacket(buffer, md_value, chunksz, filsz, filename, chunkbuf);
		}
			
		sockrep = write(sockfd, buffer, (chunksz + filsz + 24));
		counter ++;
	
		if(sockrep < 0)
		{
			perror("Unable to write");
			return 0;
		}
		
		sockrep = read(sockfd, statusbuffer, 4);
		memcpy((void*)&status, (void*)(statusbuffer + 2), 2);	
	}

	write(sockfd, finbuf, 4);
	fclose(file);
	free(buffer);
	free(chunkbuf);
	
	return 1;
}

void SendNumFiles(int sockfd, FileTimesList * list)
{
	char mesbuf[4];
	int numfiles = 0;
	FileTimeNode * ptr = list->head;
	while(ptr != NULL)
	{
		if(ptr->new == 1)
		{
			numfiles ++;
		}
		ptr = ptr->next;
	}
	memcpy((void*)mesbuf, (void*)&numfiles, 4);
	write(sockfd, mesbuf, 4);
}

void UpdateServerFiles(FileTimesList * list, int sockfd, int chunksz, char * dirname)
{
	FileTimeNode * ptr = list->head;
	printf("locking updater\n");
	pthread_mutex_lock( &condition_mutex );
	SendNumFiles(sockfd, list);
	while(ptr != NULL)
	{
		if(ptr->new == 1)
		{
			ptr->new = 0;
			SendFile(ptr->filename, sockfd, chunksz, strlen(ptr->filename) + 1, dirname);
		}
		ptr = ptr->next;
	}
	pthread_mutex_unlock( &condition_mutex );
	pthread_cond_signal( &condition_cond );
	
}

void SendKeepAlive(int sockfd)
{
  char keepbuf[4];
  short int type = 2;
  short int keepal = 8000;

  memcpy((void*)keepbuf, (void*)&type, 2);
  memcpy((void*)(keepbuf + 2), (void*)&keepal, 2);
  write(sockfd, keepbuf, 4);
}

void *set_up_connection(void *threadarg)
{
	int sockfd;
	int portno, cportno;

	struct t_args * loc_t_args;

	loc_t_args= (struct t_args *) threadarg;

	sockfd = loc_t_args->sockfd;
	portno= loc_t_args->port;
	char * dirname = loc_t_args->dir;
	int chunksz = loc_t_args->chunksize;

	struct sockaddr_in serv_addr;
	struct hostent * servername = loc_t_args->server;


	char * buffer;
	
	int timeout = 80;//seconds client will run for

	char abortbuf[4];
	char mdsig[16];

	int stopcount = 5;

	FILE * file;
	DIR * directory;

	FileTimesList * mainlist = CreateTimeList();
	
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	
	memcpy((char *)&serv_addr.sin_addr.s_addr,(char *)servername->h_addr, servername->h_length);
	
	serv_addr.sin_port = htons(portno);
	
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("connecting sender\n");
	else
		printf("Connected \n");



	if((loc_t_args->thread_id) == 0) directory = opendir(dirname);

	if((loc_t_args->thread_id) == 0) AcceptFile(sockfd, dirname); 
	//take the incoming meta-data
	
	if((loc_t_args->thread_id) == 0) 
	{
		//directory = opendir(dirname);
		AccumulateFileList(directory, mainlist);
	}
	//Create File List

	if((loc_t_args->thread_id) == 0)MetaListUpdate(mainlist);
	//Update the newly created File List according to the metadata
	
	if((loc_t_args->thread_id) == 0)UpdateServerFiles(mainlist, sockfd, chunksz, dirname);//Update the files on the server
	


	if(timeout != 0)
	{ 
		while(timeout > 0)
		{
			sleep(20);
			SendKeepAlive(sockfd);
			if((loc_t_args->thread_id) == 0)
			{
				AccumulateFileList(directory, mainlist);
				UpdateServerFiles(mainlist, sockfd, chunksz, dirname);
	    	}
			timeout -= 20;
		}
	}
	else
	{
		while(1)
		{
			sleep(20);
			SendKeepAlive(sockfd);
			if((loc_t_args->thread_id) == 0)
			{
				AccumulateFileList(directory, mainlist);
				UpdateServerFiles(mainlist, sockfd, chunksz, dirname);
			}
		}
	}

}
	int write_state(int tid, struct hostent * sname, int sockfd, int port, char* dir, int chunksz)
{
	state_struct[tid].server = sname;
	state_struct[tid].sockfd = sockfd;

	state_struct[tid].port = port;
	state_struct[tid].dir = dir;

	state_struct[tid].chunksize = chunksz;  
	state_struct[tid].thread_id = tid;

	return 0;
}

int main(int argc, char** argv)
{

	int send_sockfd, rec_sockfd;
	int sendportno, recportno;
	int retcode1, retcode2;

	char * dirname;
	int chunksz;

	struct sockaddr_in serv_addr;
	struct hostent * servername;
	char * buffer;
	
	int timeout = 80;

	char abortbuf[4];
	char mdsig[16];

	int stopcount = 5;

	pthread_mutex_init(&lock, NULL);
	
	FILE * file;
	DIR * directory;

	FileTimesList * mainlist = CreateTimeList();

    if ((send_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        error("opening socket\n");

    if ((rec_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        error("opening socket\n");


    if (argc < 6) 
	{	
       fprintf(stderr,"Usage: %s <hostname> <sendport> <receiveport> <directory name> <chunksize>\n", argv[0]);
		exit(0);
	}
    else
	{	

    	if ((servername = gethostbyname(argv[1])) == NULL) 
        	error("no such host\n");

    	sendportno = atoi(argv[2]);	// convert to int
    	recportno = atoi(argv[3]);	// convert to int
		dirname = argv[4];
		chunksz = atoi(argv[5]);
	}

	//assignment statements

	write_state(S_THREAD, servername, send_sockfd, sendportno, dirname, chunksz);
	write_state(R_THREAD, servername, rec_sockfd, recportno, dirname, chunksz);


	printf("Creating thread 0\n");
	retcode1 = pthread_create(&threads[0], NULL, set_up_connection, (void *) &state_struct[0]);

	printf("Creating thread 1\n");
	retcode2 = pthread_create(&threads[1], NULL, set_up_connection, (void *) &state_struct[1]);


	pthread_join( threads[0], NULL);
	pthread_join( threads[1], NULL);

	return 0;
}

