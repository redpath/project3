/*
  _            _                 
   /_  /_ _   /_/_   _/_  _ _/_/_
(_//_// // / / \/_'/_//_//_|/ / / *
                     /   
(John Redpath)
Dave Weiss
01:198:352
SP2011
Lab 3

server.c
*/
#include "header.h"
volatile sig_atomic_t exitvar = 0; //Exit variable used by alarm in main
int counter = 0;
pthread_mutex_t counterLock;
FileTimesList *mainlist;
const int SEND = 0;
const int REC = 1;
const int CHUNKSIZE = 500;
typedef struct threadData{
	int newsockfd;
	FileTimesList *mainlist;
	char *dirname;

} *ThreadData;
/*typedef struct job_{
	char filename[500][100];
	int count;
} *job;*/
typedef struct node_{
	MetaStruct *value;/*hold a job value pointer.*/
	struct node_ *next;
} *node;
typedef struct queue_{
	node head;
	node tail;
	int items;
	pthread_mutex_t mutex;/*Mutex for keeping track if this is being used.*/
} *queue;
typedef struct client_{
	int sendSocket;/*The socket that this user has*/
	int recSocket;/*the receive socket that is receieving.*/
	queue pendingJobs;/*currently pending jobs.*/
	
} *client;
typedef struct clients_{
     client clients[2000];
     pthread_mutex_t mutex;
     int size;
} *clients;
/*Function declarations*/
clients connectedClients;
queue createQueue();
void destroyQueue(queue);

int clientExists(int sockfd,int from){/*check if the client exists.*/
	int counter = 0;
	int foundIndex = -1;
	printf("Attempting to lock connected clients mutex: %d\n",__LINE__);
	pthread_mutex_lock(&connectedClients->mutex);
	while(counter < connectedClients->size){
		if(from == SEND){
			if(connectedClients->clients[counter]->sendSocket == sockfd){
				foundIndex = counter;
			}
		}
		if(from == REC){
			if(connectedClients->clients[counter]->recSocket == sockfd){
				foundIndex = counter;
			}
		}
		counter++;	
	}
	printf("Attempting to unlock connected clients mutex: %d\n",__LINE__);
	pthread_mutex_unlock(&connectedClients->mutex);
	return foundIndex;
}
int clientRemove(int sockfd){
	int foundIndex = clientExists(sockfd,SEND);
	if(foundIndex < 0){
		foundIndex = clientExists(sockfd,REC);
	}
	client temp;
	if(foundIndex >= 0){
		/*Shift the array*/
		printf("Attempting to lock connected clients mutex: %d\n",__LINE__);
		pthread_mutex_lock(&connectedClients->mutex);
		destroyQueue(connectedClients->clients[foundIndex]->pendingJobs);
		while(foundIndex < connectedClients->size){
			if((foundIndex +1) < connectedClients->size){
				temp = connectedClients->clients[foundIndex + 1];
				connectedClients->clients[foundIndex] = temp;
			}
			foundIndex++;
		}
		connectedClients->clients[foundIndex] = 0;
		connectedClients->size--;/*Decrement the size*/
		printf("Attempting to unlock connected clients mutex: %d\n",__LINE__);
		pthread_mutex_unlock(&connectedClients->mutex);
		return 0;
	}else{
		return -1;
	}
}
int clientAdd(int sockfd,int from){/*Add a client to the client list.*/
	int foundIndex = clientExists(sockfd,from);
	if(from == SEND){
		if(foundIndex < 0) {/*Client was not found already found*/
			printf("Attempting to lock connected clients mutex: %d\n",__LINE__);
			pthread_mutex_lock(&connectedClients->mutex);
				connectedClients->clients[connectedClients->size]->sendSocket = sockfd;
				connectedClients->clients[connectedClients->size]->pendingJobs = createQueue();
			printf("Attempting to unlock connected clients mutex: %d\n",__LINE__);
			pthread_mutex_unlock(&connectedClients->mutex);
		}
	}
	

	if(from == REC){
		printf("Attempting to lock connected clients mutex: %d\n",__LINE__);
		pthread_mutex_lock(&connectedClients->mutex);
			connectedClients->clients[connectedClients->size]->recSocket = sockfd;
		printf("Attempting to unlock connected clients mutex: %d\n",__LINE__);
		pthread_mutex_unlock(&connectedClients->mutex);
	}
	
}
queue createQueue(){/*Returns a queue pointer*/
	queue jobs = (queue)calloc(1,sizeof(struct queue_)); 
	jobs->head = NULL;
	jobs->tail = NULL;
	pthread_mutex_init(&jobs->mutex,0);/*Initialize the mutex*/ 
	return jobs;
}
void enqueue(queue orders, MetaStruct *order){/*Add a book order to the queue*/
	node temp;
	if(orders->head ==NULL){
		orders->head = (node)calloc(1,sizeof(struct node_));
		orders->head->value = order;
		orders->head->next = NULL;
		orders->tail = orders->head;
		
	}  else{
		temp = (node)calloc(1,sizeof(struct node_));
		temp->value = order;
		temp->next = NULL;
		orders->tail->next = temp;
		orders->tail = temp;/*set newest item as the tail*/
	}
	orders->items++;
}
node dequeue(queue orders){/*take off the front of the line*/
	if(orders->head == NULL){
		return NULL;
	}
	node temp= orders->head;/*Take off the current head*/
	orders->head = orders->head->next;
	temp->next = NULL;
	orders->items--;
	return temp;
	
	
}
void destroyQueue(queue orders){
	int i;
	node temp;
	while((temp = dequeue(orders)) != NULL){
		temp->value = NULL;
		free(temp);
	}
	free(orders);
}
MetaStruct * CreateMetaStruct(int filnamesz, char * filename, time_t tm)
{
	MetaStruct * met = (MetaStruct*)malloc(sizeof(MetaStruct));
	strcpy(met->filename,filename);
	met->filenamesz = filnamesz;
	met->modified_time = tm;
	/*Initialize the mutex for the metadata struct.*/
	pthread_mutex_init(&met->mutex,0);
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
/* This either adds a new file to the list or if the 
 * file exists sets its new indicator to 0
 */
int AddFileToList(FileTimesList * list, char * filname, int filenamesz, time_t tm) 
{
	FileTimeNode * ptr = list->head;
	if(list->head == NULL)
	{
		list->head = CreateFileTimeNode(filname, tm, filenamesz);
		list->head->next == NULL;
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
// This function goes through the given directory and creates a list of files in it
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
			AddFileToList(list, dirinfo->d_name, strlen(dirinfo->d_name) + 1, tm);
		}
	} //end while
}

void CreateChunkPacket(char * packet, char * md5sig, int chunksz, short int filenamesz, char * filename, char * chunk) //This method creates the file packet to be sent
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

void UpdateMetaFile(FileTimesList * list) // This function creates a metafile given the current list
{
	FILE * meta;
	MetaStruct * met;
	int bt;
	FileTimeNode * ptr = list->head;
	char filepath[25] = "data/META-DATA";

	meta = fopen(filepath, "wb");
	if(meta == NULL)
	{
		printf("We could not open file\n");
	}
	while(ptr != NULL)
	{
		met = CreateMetaStruct(strlen(ptr->filename) + 1, ptr->filename, ptr->time);
		ptr->metadata = met;
		bt = fwrite((void*)met, sizeof(MetaStruct), 1, meta);
		fflush(stdout);
		ptr = ptr->next; 
	}
	fclose(meta);
	
}
// This methods send the given file by packets over the given socket connection
int SendFile(char * filename, int sockfd, int chunksz, short int filsz, char * dirname)
{
	int counter = 0;
	FILE * file;
	int err;
	char emptymeta[2];
	short int emptymet = 9;

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
	
	char fullpath[100];
	char slash[2] = "/";
	int dirlen = strlen(dirname);
	memcpy((void*)fullpath, (void*)dirname, dirlen);
	memcpy((void*)(fullpath + dirlen), (void*)slash, 1);
	
	stat(filename, &st);
	sz = st.st_size;
	if(sz == 0)
	  {
		  memcpy((void*)emptymeta, (void*)&emptymet, 2);
		  write(sockfd, emptymeta, 2);
		  return 9;
	    
	  }
	
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
	
	file = fopen(filename, "rb");
	memset(buffer,0, (chunksz + filsz + 24));
	
	while(1)
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
		printf("status is:%d\n", status);
		
	} //end while

	write(sockfd, finbuf, 4);
	fclose(file);
	free(buffer);
	free(chunkbuf);
	
	return 1;
}

/* This function accepts the filepackets incoming over 
 * the given connection and forms the resulting file. 
*/
int AcceptFile(int newsockfd, char * dirname)
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
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("MD5");  // "md5"

	int md_len = 16;   

	
	short int stattype = 2;
	short int resmes = 2;
	short int okmes = 1;
	char mdval[16];
	short int type;
	unsigned char mdsig[16];
	short int filenamesz;
	char * filename;
	char * chunk;
	short int status;
	
	char fullpath[100];
	char slash[2] = "/";
	int dirlen = strlen(dirname);
	memcpy((void*)fullpath, (void*)dirname, dirlen);
	memcpy((void*)(fullpath + dirlen), (void*)slash, 1);
	
	
	memcpy((void*)resendbuf, (void*)&stattype, 2);
	memcpy((void*)(resendbuf + 2), (void*)&resmes, 2);
	
	memcpy((void*)okbuf, (void*)&stattype, 2);
	memcpy((void*)(okbuf + 2), (void*)&okmes, 2);
	
	memset(buffer,0, 2000);

	if(read(newsockfd, buffer, 1999) < 0)
	{
		perror("Read failed");
		return 0;
	}
	memcpy((void*)&type, (void*)buffer, 2);
	memcpy((void*)mdsig, (void*)(buffer + 2), 16);
	memcpy((void*)&chunksz, (void*)(buffer + 18), 4);

	chunk = (char*)malloc(chunksz);
	memcpy((void*)&filenamesz, (void*)(buffer + 22), 2);
	filename = (char*)malloc(filenamesz + 5);
	
	memcpy((void*)filename, (void*)(buffer + 24), (size_t)filenamesz);
	memcpy((void*)chunk, (void*)(buffer + 24 + filenamesz), (size_t)chunksz);
	
	memcpy((void*)(fullpath + dirlen + 1), (void*)filename, filenamesz);
	file = fopen(filename, "wb");
	
	EVP_MD_CTX_init(&mdctx);	
	EVP_DigestInit_ex(&mdctx, md, NULL);	
	EVP_DigestUpdate(&mdctx, chunk, (size_t)chunksz);
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);

	memcpy((void*)mdval, (void*)md_value, 16);
	
	while(1)
	{
		if(memcmp(mdval, mdsig, 16) == 0)
		{
			fwrite(chunk, 1, chunksz, file);
			write(newsockfd, okbuf, 4);
		}
		else
		{
			write(newsockfd, resendbuf, 4);
		}
		read(newsockfd, buffer, 2000);
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
	}
	
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

int RecieveNumFiles(int sockfd)
{
	char mesbuf[4];
	int message;
	int err;
	memset(mesbuf,0, 4);
	err = read(sockfd, mesbuf, 4);
	
	if(err == 0)
	  {
	    return -1;
	  }
	memcpy((void*)&message, (void*)mesbuf, 4);
	return message;
}

int AcceptFileUpdates(int sockfd, char * dirname)
{
	int numfiles = RecieveNumFiles(sockfd);
	if(numfiles == -1)
	  {
	    return 0;
	  }
	while(numfiles > 0)
	{
		AcceptFile(sockfd, dirname);
		numfiles --;
	}
	return 1;
}
int AcceptKeepAlive(int sockfd)
{
  short int type;
  short int mess;
  char buf[4];
  int err;
  err = read(sockfd, buf, 4);
  if(err == 0)
    {
      return -1;
    }
  memcpy((void*)&type, (void*)buf, 2);
  memcpy((void*)&mess, (void*)(buf + 2), 2);
  if(type == 2 && mess == 8000)
    {
      return 1;
    }
  else
    {
      return 0;
    }
}
void exit_prog(int signum)
{   
  exitvar = 1;
  signal(SIGALRM, exit_prog);
}
void *receiveThread(void *datastruct){
	DIR * directory;	
	FILE * file;
	int aerr;	
	ThreadData threadData = (ThreadData)datastruct;
	char *dirname = threadData->dirname;
	int newsockfd = threadData->newsockfd;
	signal(SIGALRM, exit_prog);
	directory = opendir(dirname);//Open data directory
	AccumulateFileList(directory, mainlist);
	UpdateMetaFile(mainlist);
	SendFile("data/META-DATA", newsockfd, 64, 15, dirname);
	while(exitvar==0)
	{ 
	    UpdateMetaFile(mainlist);
	    aerr = AcceptFileUpdates(newsockfd, dirname);
	    if(aerr == 0)
		{
			sleep(1);
		}
	    
	    if(AcceptKeepAlive(newsockfd) == 1)
		{
			alarm(30);
		}
	    else if(AcceptKeepAlive(newsockfd) == -1) {		}

	    else
		{
			perror("Invalid message");
			exit(1);
		}
	    
	} //end while
	/*Client has timed out so we remove him from the list.*/
	
}
void *sendThread(void *datastruct){
	ThreadData threadData = (ThreadData)datastruct;
	char *dirname = threadData->dirname;
	int newsockfd = threadData->newsockfd;
	node temp;
	signal(SIGALRM, exit_prog);
	
	while(exitvar==0)/*Check if there this user has a job to do. that has a job to do.*/
	{ 
	   int foundIndex = clientExists(newsockfd, SEND);
	   if(foundIndex >= 0){
		   printf("Locking pendingJobs mutex: %d\n",__LINE__);
		   pthread_mutex_lock(&connectedClients->clients[foundIndex]->pendingJobs->mutex);
			if(connectedClients->clients[foundIndex]->pendingJobs->items > 0){
				while((temp = dequeue(connectedClients->clients[foundIndex]->pendingJobs)) != NULL){
					SendFile(temp->value->filename, newsockfd, CHUNKSIZE, temp->value->file_size, dirname);
				}
			}
		   printf("Unlocking pendingJobs mutex: %d\n",__LINE__);
			pthread_mutex_unlock(&connectedClients->clients[foundIndex]->pendingJobs->mutex);
	   }
	    if(AcceptKeepAlive(newsockfd) == 1)
		{
			alarm(30);
		}
	    else if(AcceptKeepAlive(newsockfd) == -1) {		}

	    else
		{
			perror("Invalid message");
			exit(1);
		}
	    
	} //end while
	/*Client has timed out so remove him*/
	clientRemove(newsockfd);
}
void *listenReceive(void * port){
	int portno = *((int*) port);
	int sockfd,newsockfd;
	int running = 1;
	pthread_t clients[6];
	ThreadData threadData;
	char * dirname = "data";
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clientlen;
	printf("REC:attempting to open socket.\t%d\n",__LINE__);
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        	error("opening socket\n");
	
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	printf("REC:Attempting to open on port %d\t%d\n",portno,__LINE__);
    if ((bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0)
        error("binding");
	printf("REC: Waiting on clients.\n");
	while(running){
		listen(sockfd, 5);
		clientlen = sizeof(cli_addr);
		if ((newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clientlen))< 0){
        		error("accept");
		}else{
			/*Spawn the client handler threads.*/
			threadData->newsockfd = newsockfd;
			threadData->dirname = dirname;
			printf("REC: Client Connected.\n");
			clientAdd(newsockfd,REC);
			pthread_create(&clients[counter],0,receiveThread,(void*)threadData);
			counter++;
			
		}
	
	}
}

void *listenSend(void * port){
	int portno = *((int*) port);
	int sockfd,newsockfd;
	ThreadData threadData;
	int running = 1;
	pthread_t clients[6];
	char * dirname = "data";
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clientlen;
	 printf("SEND:Attempting to open socket.\t%d",__LINE__);
	 if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        	error("opening socket\n");
	
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	printf("\nSEND: Attempting open on port %d\t%d\n",portno,__LINE__);
    if ((bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0)
        error("binding");
	printf("SEND: Waiting on clients.\n");
	while(running){
		listen(sockfd, 5);
		clientlen = sizeof(cli_addr);
		if ((newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clientlen))< 0){
        		error("accept");
		}else{
			/*Spawn the client handler threads.*/
			printf("SEND:Client connected. Spawning thread.\n");
			threadData->newsockfd = newsockfd;
			threadData->dirname = dirname;
			clientAdd(newsockfd,SEND);
			pthread_create(&clients[counter],0,sendThread,(void*)threadData);
			counter++;
		}
	
	}
}

int main(int argc, char** argv)
{
	/*Initialize shared datastructures*/
	mainlist = CreateTimeList();
	pthread_t listen,send;	
	int sockfd,newsockfd, sportno,rportno;
	pthread_mutex_init(&counterLock,0);
    if (argc < 3) 
	{	
       fprintf(stderr,"Usage: %s<sendport> <receiveport>\n", argv[0]);
		exit(0);
	}
    else
	{	
		sportno = atoi(argv[1]);
		rportno = atoi(argv[2]);
		
	}
	
	/*Spawn the two threads for listening.*/
    	pthread_create(&send,0,listenSend,&sportno);
	printf("Send thread was spawned.");
   	pthread_create(&listen,0,listenReceive,&rportno);
	
	printf("Server has exited due to client inactivity\n");
	pthread_join(listen,NULL);
	pthread_join(send,NULL);
	return 0;
}
