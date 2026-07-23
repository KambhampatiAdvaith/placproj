#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX 256


unsigned char *fileData;
long fileSize;


/* Search pattern inside any file */
int contains(char *pattern)
{
    int len = strlen(pattern);

    for(long i=0;i<=fileSize-len;i++)
    {
        if(memcmp(fileData+i,pattern,len)==0)
            return 1;
    }

    return 0;
}


/* Read target file */
int loadFile(char *name)
{
    FILE *fp=fopen(name,"rb");

    if(!fp)
        return 0;


    fseek(fp,0,SEEK_END);
    fileSize=ftell(fp);
    rewind(fp);


    fileData=(unsigned char*)malloc(fileSize);


    fread(fileData,1,fileSize,fp);

    fclose(fp);

    return 1;
}



/* Scan one rule file */
void scanRuleFile(char *filename)
{
    FILE *fp=fopen(filename,"r");

    if(!fp)
        return;


    char line[MAX];

    char malware[100]="Unknown";


    while(fgets(line,sizeof(line),fp))
    {

        line[strcspn(line,"\n")]=0;


        if(strncmp(line,"Name=",5)==0)
        {
            strcpy(malware,line+5);
        }


        if(strncmp(line,"STRING:",7)==0)
        {
            char *sig=line+7;


            if(contains(sig))
            {
                printf("\nMalware Detected : %s\n",malware);
            }
        }

    }


    fclose(fp);
}



/* Recursive folder scan */
void scanDirectory(char *path)
{

    DIR *dir=opendir(path);

    if(!dir)
        return;


    struct dirent *entry;


    while((entry=readdir(dir))!=NULL)
    {

        if(strcmp(entry->d_name,".")==0 ||
           strcmp(entry->d_name,"..")==0)
            continue;


        char full[500];

        sprintf(full,"%s/%s",path,entry->d_name);



        struct stat st;

        stat(full,&st);


        if(S_ISDIR(st.st_mode))
        {
            scanDirectory(full);
        }
        else
        {
            scanRuleFile(full);
        }

    }


    closedir(dir);
}




int main(int argc,char *argv[])
{

    if(argc!=3)
    {
        printf("Usage: scanner <file> <rules_folder>\n");
        return 1;
    }


    if(!loadFile(argv[1]))
    {
        printf("Cannot open file\n");
        return 1;
    }


    printf("Scanning %s...\n",argv[1]);


    scanDirectory(argv[2]);


    free(fileData);


    printf("\nScan Completed\n");


    return 0;
}
