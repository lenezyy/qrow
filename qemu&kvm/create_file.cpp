#include<stdio.h>
#include <stdlib.h>
#include <string.h> 


int main(){
	char *file = "mmio";
	FILE * outFile;
	if((outFile = fopen (file, "wb+"))==NULL)
    {
        printf("cant open the outfile");
        exit(0);
	}
	char mmio[8];
	for (int i = 1; i <= 94; i ++) 
	{
		memset(mmio,32+i,8);
		fwrite(mmio,sizeof(char),8,outFile);
	}
	
	return 0;
}
