#include<stdio.h>
#include <stdlib.h>
#include <string.h>    
#include <fcntl.h>
#include <malloc.h>
#include <time.h>//用来产生随机数 
#include"qrow.h"
static int get_bits_from_size(uint32_t size)
{ // 如果size=2^n，那么返回n，否则返回－1
    int ret = 0;
    if (size == 0) {
        return -1;
    }
    while (size != 1) {
    	if (size & 1) {// 不是2的幂
    		return -1;
        }
        size >>= 1;
        ret++;
    }
    return ret;
}

int Qrow_generate_filename(char *dest, char *prefix, char *body, char *suffix) {
	// dst = prefix-body.suffix
	if(strlen(prefix) + strlen(body) + strlen(suffix) + 2 >= MAX_FILE_NAME_LENGTH) {
		fprintf(stderr, "Invalid filename length, max is %d\n", MAX_FILE_NAME_LENGTH);
		return -1;
	}
	strcpy(dest, prefix);
	strcat(dest, "-");
	strcat(dest, body);
	strcat(dest, ".");
	strcat(dest, suffix);
	return 0;
}
int Qrow_create(char *img_file, uint64_t disk_size, uint32_t block_size)
{
	
	QrowHeader *header = (QrowHeader*) malloc(sizeof(QrowHeader));	
	char *magic = "qrow";
	char *map_path = "file/qrow3.map";//先写死，功能实现后再利用irow_generate_filename()优化 
	/*
	if(irow_generate_filename(meta.current_btmp, cs->meta_file, cs->time_value, "btmp") < 0)	
	{
		
	}
	*/
	//分析参数是否合法 
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		return 0;
	}
	if(block_size == 0) {
		fprintf(stderr, "Invalid block_size\n");
		return 0;
	}
	uint32_t block_bits = get_bits_from_size(block_size); // 获取block_bits
	if ((block_bits < MIN_CLUSTER_BITS) || (block_bits > MAX_CLUSTER_BITS)) {
	   // block最小512B(至少包括一个sector)，最大2MB,且必须是2的幂
    	fprintf(stderr, "block size must be a power of two between %d and %dB\n",
            1 << MIN_CLUSTER_BITS,
            1 << MAX_CLUSTER_BITS);
    	return 0;
    } 
	  
	/* 计算出元数据头需要的所有信息*/
    
	strncpy(header->format_name, magic, 8);	
	header->version = 1;
	header->block_offset = 1;//磁盘文件block从0开始编号，第0个默认存放元数据头信息 
	//header->block_size = 4096;//默认为4K大小 ，这个可能要参考一下irow的写法。设置一个默认值 
	//header->block_bits = 12;//默认为12 
    header->disk_size = disk_size;
    header->block_size = block_size;
    header->sectors_per_block = block_size/512; 
    header->block_bits = block_bits;
    header->total_blocks = (disk_size + block_size -1) >> block_bits;
    strncpy(header->img_name, img_file, MAX_FILE_NAME_LENGTH);
    strncpy(header->map_path, map_path, MAX_FILE_NAME_LENGTH);
	// 当disk_size 不是 block_size的整数倍时，剩余小于block大小的空间也占据一个block号 
	
	int fd;	
	fd = open(img_file, O_RDWR|O_CREAT|O_TRUNC|O_BINARY);
	//fd = open(img_file, O_RDWR|O_CREAT|O_TRUNC|O_BINARY,0777); 
	if (fd < 0) 
	{
		fprintf(stderr, "Can not open %s\n", img_file);
		return 0;
	}
	int writeByets = write(fd, header, sizeof(QrowHeader)); 
	if(writeByets != sizeof(QrowHeader))
	{
		fprintf(stderr, "Can not write QrowHeader \n");
	}
	//printf("writeByets: %d\n",writeByets);
	/*
	lseek(fd, 0, SEEK_SET);
	QrowHeader *read11 = (QrowHeader*) malloc(sizeof(QrowHeader));	
	int readByets = read(fd, read11, sizeof(QrowHeader));
	printf("readByets: %d\n",readByets);
	*/
	// 将元数据头写入磁盘文件的第一个block中，需要占据一整个block么？当block比较大的时候，占据一整个会不会浪费？先按照占据一整个来设计 
	
	if(close(fd) != 0) {
		fprintf(stderr, "Can not close %s\n", img_file);
   		return 0;
   	}
   	if(header) 
   	{
   		free(header);	
	}
	/*
	if(read11)
	{
		free(read11);
	}
	*/
	return 1;
}




int Qrow_open(QrowState *qrow_state, char *img_file, int flag, char *log_file)
{	
	int fd,log_file_fd, map_file_fd;
	QrowHeader *qrow = (QrowHeader*) malloc(sizeof(QrowHeader));
	
	//fd = open(img_file, O_RDWR, 0333);//打开磁盘文件
	fd = open(img_file, O_RDWR|O_BINARY, 0333);//打开磁盘文件
	if (fd < 0) 
	{
		printf("Can not open %s\n", img_file);
		return 0;
	}
	
	//整合刘寒青的代码时，没办法使用lseek这个函数 
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//先获取文件大小
	lseek(fd, 0, SEEK_SET);//将读写位置移动到文件开头处 
	int readBytes = read(fd, qrow, sizeof(QrowHeader));
	if(readBytes != sizeof(QrowHeader))
	{
		printf("Can not read QrowHeader\n");
		return 0;
	}
	//printf("readBytes:%d\n",readBytes);
	
	map_file_fd = open(qrow->map_path, O_RDWR|O_CREAT|O_BINARY,0333);//创建或者打开map文件
	if (map_file_fd < 0) 
	{
		printf("Can not open %s\n", qrow->map_path);
		return 0;
	}
	uint64_t map_file_size = lseek(map_file_fd, 0, SEEK_END);
	//先获取map文件大小，如果为0，则证明还没有将map数组写入文件，是第一次代开map文件，否则，将map文件中的map数组读取出来，并赋值给qrow_state->map 
	lseek(map_file_fd, 0, SEEK_SET);//将读写位置移动到文件开头处 
	if(map_file_size > 0) 
	{
		if(read(map_file_fd, qrow_state->map, sizeof(qrow_state->map)) != sizeof(qrow_state->map))	
		{
			return 0;
		}
	}
	else
	{
		qrow_state->map[MAX_VM_SECTOR_NUM] = {0};
	}
	
	qrow_state->block_size = qrow->block_size;
	qrow_state->sectors_per_block = qrow->sectors_per_block;
	qrow_state->total_blocks = qrow->total_blocks;
	
	//防止 Qrow_close()执行前出现死机等情况，导致真实的 block_offset值大于元数据头中的block_offset值，所以，每次 Qrow_open（）执行到这里时需要做出判断
	//判断 qrow->block_offset是否等于当前img_file的大小，不等于的话，取img_file文件大小的值换算成block_offset的值
	
	
	uint64_t cur_block_offset = (cur_disk_size % qrow->block_size == 0) ? (cur_disk_size / qrow->block_size) : (cur_disk_size / qrow->block_size)+1;
	qrow_state->block_offset = (qrow->block_offset < cur_block_offset) ? cur_block_offset : qrow->block_offset;
	qrow_state->byte_offset = qrow_state->block_offset * qrow_state->block_size;
	qrow_state->sector_offset = qrow_state->block_offset * qrow_state->sectors_per_block;
	qrow_state->img_file = fd; 
	qrow_state->map_file_fd = map_file_fd;
	
	 
	if(flag == 0)//flag=0,表示记录阶段，1表示回放阶段,打开指定的log文件
	{
		is_record = 1;
		log_file_fd = open(log_file, O_RDWR|O_CREAT|O_BINARY|O_APPEND,0333); 
		/*
		需要考虑一个问题，当用户连续执行Qrow_open操作，并且是记录阶段时，需要采用追加 O_APPEND的方式写入数据，
		或者，可以设置log文件的offset，每次Qrow_open记录阶段时，就先将指针移动到offset处再写入，这样的方式可能更加保险 
		*/
		if (log_file_fd < 0) 
		{
			printf("Can not open %s\n", log_file);
			return 0;
		}
		
		qrow_state->log_file_fd = log_file_fd; 
	} else if(flag == 1)
		{
			is_replay = 1;
			log_file_fd = open(log_file, O_RDWR|O_BINARY, 0333);
			if (log_file_fd < 0) 
			{
				printf("Can not open %s\n", log_file);
				return 0;
			}
			qrow_state->log_file_fd = log_file_fd; 
	
		}
		else 
		{
			qrow_state->log_file_fd = -1;//表示不是记录重放阶段，没有打开记录文件 
		}
	
	if(qrow)
	{
		free(qrow);
	}
	return 1;		
}


int Qrow_close(QrowState *qrow_state)
{
		
		if(qrow_state->log_file_fd != -1)
		{
			close(qrow_state->log_file_fd);
		}
		//将map数组写入map文件中
		lseek(qrow_state->map_file_fd, 0, SEEK_SET);//将读写位置移动到文件开头处 
		if(write(qrow_state->map_file_fd, qrow_state->map, sizeof(qrow_state->map))<0) 
		{
			printf("can not write map\n");
			return -1;
		}
		if(qrow_state->map_file_fd != -1)
		{
			close(qrow_state->map_file_fd);
		}
		
		 
		//更新元数据头信息中的 block_offset值 
		QrowHeader *qrow = (QrowHeader*) malloc(sizeof(QrowHeader));
		lseek(qrow_state->img_file, 0, SEEK_SET);
		int readBytes = read(qrow_state->img_file, qrow, sizeof(QrowHeader));
		if(readBytes != sizeof(QrowHeader))
		{
			printf("Can not read QrowHeader\n");
			return 0;
		}
		qrow->block_offset = qrow_state->block_offset;    
		lseek(qrow_state->img_file, 0, SEEK_SET);
		write(qrow_state->img_file, qrow, sizeof(QrowHeader));
		if(qrow_state->img_file != -1)
		{
			close(qrow_state->img_file);
		}
		return 1;
		
}

/*
	需要记录log文件的偏移量么？每次执行完read_log函数就记录一下当前偏移量是多少 
*/
int read_log(int img_file_fd, int log_file_fd, uint8_t *tmp_data) //返回log文件中记录读取数据存储在物理磁盘对应扇区的数组 
{
	uint8_t  log_type;
	int  nb_sectors;//表示数组长度 
	//uint64_t *sector;//表示数据存储在物理磁盘扇区号的数组 
	uint64_t offset_sector = 0;
	QrowRRIo *rr_io = (QrowRRIo*) malloc(sizeof(QrowRRIo)) ;//可能不需要这个结构体 ,直接定义一个局部变量uint64_t rr_or_sector[nb_sectors*sizeof(uint64_t)]即可 
	read(log_file_fd, (void *)(&log_type), sizeof(uint8_t));
	if( log_type != RRTYPE)//判断记录类型是否为read操作 
	{
		return -1;
	}
	read(log_file_fd, (void *)(&nb_sectors), sizeof(int));
	//read(log_file_fd, rr_io, sizeof(QrowRRIo));
	read(log_file_fd, rr_io->sector, nb_sectors*sizeof(uint64_t));
	int num = 0;
	for (int i = 0; i < nb_sectors; i++) 
	{
		offset_sector = rr_io->sector[i];//从map数组中获取数据在物理磁盘上的存储扇区号 
		lseek(img_file_fd, offset_sector*512, SEEK_SET);//将读的位置移动到正确的位置；
		num = read(img_file_fd, tmp_data+i*512, 512);//读取一个扇区的数据到tmp_data指定位置 
	}
	if(rr_io)
	{
		free(rr_io);
	}	
	return 0;
	
} 

int write_log(int log_file_fd, QrowRRIo *rr_io, int nb_sectors)//也可以把log文件的I/O read事件做成一个结构体，包括记录类型，读取扇区数量和 rr_io结构体 
{
	if(nb_sectors <= 0)
	{
		return 0;
	}
	uint8_t log_type = RRTYPE;
	write(log_file_fd, (void *)(&log_type), sizeof(uint8_t));
	write(log_file_fd, (void *)(&nb_sectors), sizeof(int));
	write(log_file_fd, rr_io->sector, nb_sectors*sizeof(uint64_t));
	//write(log_file_fd, rr_io, sizeof(QrowRRIo));
	return 1;
}

int Qrow_read(QrowState *qrow_state, uint64_t sector_num, uint8_t *buf, int nb_sectors) 
	//实际磁盘读写中 sector_num从1开始还是0，假设是1的话，qrow_statemap[0]没意义，qrow_state->map从1开始一直到i (map[i] != 0)
{
	if (sector_num < 0 || sector_num >= MAX_VM_SECTOR_NUM)//vm_total_sectors这个参数还有待考虑具体如何处理 
	{
		printf("读取的扇区起始位置错误\n");
		return 0;
	} 
	if (nb_sectors <= 0 || nb_sectors > MAX_READ_SECTOR_NUM )
	{
		printf("读取的扇区数小于等于0或者大于允许的最大读取数量\n");
		return 0;
	}
	if ((sector_num + nb_sectors) > MAX_VM_SECTOR_NUM)
	{
		printf("读取的扇区结束位置超过了最大虚拟磁盘最大扇区位置\n");
		return 0;
	}
	
	uint64_t sector_offset;
	int count = 0;
	QrowRRIo *rr_io = (QrowRRIo*) malloc(sizeof(QrowRRIo)) ;//可能不需要这个结构体 ,直接定义一个局部变量uint64_t rr_or_sector[nb_sectors*sizeof(uint64_t)]即可 
	if(is_replay)//如果是重放阶段，直接读取log文件获取数据在物理磁盘中的存储扇区号，并且将物理磁盘中相应的数据复制到 buf中 
	{
		read_log(qrow_state->img_file, qrow_state->log_file_fd, buf);
		return 1;
	}
	
	if(is_record) //如果是记录阶段，把read操作读取数据在物理磁盘中的存储扇区号记录到log文件中；
	{
		rr_io->sector[MAX_READ_SECTOR_NUM] = {0};
		//int count = 0;
		for (int j = sector_num, k = 0; j < (nb_sectors+sector_num); j++) 
		{
			sector_offset = qrow_state->map[j];//从map数组中获取数据在物理磁盘上的存储扇区号 
			if(sector_offset < 4 || sector_offset >= (qrow_state->total_blocks*qrow_state->sectors_per_block) ) //该磁盘内容为空或者为header部分或者超出磁盘范围 
			{
				count++;
			 } 
			 else
			 {
			 	rr_io->sector[k] = sector_offset;
			 	k++;
			 }
			
			
		}
		write_log(qrow_state->log_file_fd, rr_io, nb_sectors-count);//将每次读操作按照type  nb_sectors rr_io->sector[0-(nb_sectors-1)]存入log文件 
	
	}
	//从物理磁盘中读取所需数据 
	for (int i = sector_num, j = 0; i < (nb_sectors+sector_num); i++) 
	{
		sector_offset = qrow_state->map[i];//从map数组中获取数据在物理磁盘上的存储扇区号 
		if(sector_offset < 4 || sector_offset >= (qrow_state->total_blocks*qrow_state->sectors_per_block) ) //该磁盘内容为空或者为header部分或者超出磁盘范围 
		{
			continue; 
		} 
		 else
		 {
		 	lseek(qrow_state->img_file, sector_offset*512, SEEK_SET);//将读的位置移动到正确的位置；
			int readBytes = read(qrow_state->img_file, buf+j*512, 512);//读取一个扇区的数据到buf指定位置 
			if (readBytes == -1)
			{
				//fprintf(stderr, "read failed \n");
				printf("read failed \n");
				return 0;
			}
			j++;
		 }
		
		
	}	
	
	if(rr_io)
	{
		free(rr_io);
	}
	//return 1;	
	return (nb_sectors-count);
}



int Qrow_write(QrowState *qrow_state, uint64_t sector_num, uint8_t *buf, int nb_sectors)// 扇区的编号从1还是0开始？ 
{	
	if (sector_num < 0 || sector_num >= MAX_VM_SECTOR_NUM)//vm_total_sectors这个参数还有待考虑具体如何处理 
	{
		printf("写入的扇区起始位置错误\n");
		return 0;
	} 
	if (nb_sectors <= 0 || nb_sectors > MAX_READ_SECTOR_NUM )
	{
		printf("写入的扇区数小于等于0或者大于允许的最大写入数量\n");
		return 0;
	}
	if ((sector_num + nb_sectors) > MAX_VM_SECTOR_NUM)
	{
		printf("写入的扇区结束位置超过了最大虚拟磁盘最大扇区位置\n");
		return 0;
	}
		int nb_block_writed = (nb_sectors % qrow_state->sectors_per_block == 0) ? (nb_sectors / qrow_state->sectors_per_block) : (nb_sectors / qrow_state->sectors_per_block + 1);
		if(qrow_state->block_offset + nb_block_writed > qrow_state->total_blocks ) //判断磁盘是否有足够的剩余空间 
		{
			fprintf(stderr, "img_file is full \n");
			return 0;
		}
		lseek(qrow_state->img_file, qrow_state->byte_offset, SEEK_SET);//将写的位置移动到正确的位置； 
		write(qrow_state->img_file, buf, nb_sectors*512);//将数据写入磁盘文件；
		uint64_t sector_offset = qrow_state->sector_offset;
		for (int i = sector_num, j = 1; j <= nb_sectors; i++, j++) //更新map数组的值，即更新虚拟磁盘和物理磁盘的数据映射关系 
		{
			qrow_state->map[i] = sector_offset;
			sector_offset++;
		}
		//更新偏移量相关的值 
		qrow_state->block_offset += nb_block_writed;
		qrow_state->byte_offset = qrow_state->block_offset * qrow_state->block_size;
		qrow_state->sector_offset = qrow_state->block_offset * qrow_state->sectors_per_block;	 	
		return 1;
}

void Qrow_get_info()
{
	
}


int main()
{
	
	char *img_file = "file/qrow3.txt";
	char *log_file ="file/log3";
	//uint64_t disk_size = 1073741824*64;//1G*64时，说超出范围，运行报错。。。 
	uint64_t disk_size = 1073741824;//1G
	uint32_t block_size = 2048;
	QrowState *qrow_state = (QrowState*) malloc(sizeof(QrowState)) ;
	
	
	if (!Qrow_create(img_file, disk_size, block_size))
	{
		printf("create img_file failed\n");
			
	}
	else
	{
		printf("create ok\n");
	}
	
		
	if(Qrow_open(qrow_state, img_file, 0, log_file))
	{
		printf("open ok\n");
	}
	else
	{
		printf("open failed\n");
	}
	
	int sector_num, nb_sectors,read_sectors,read_times;
	int total_bit=0;
	srand((unsigned) time(NULL)); //用时间做种，每次产生随机数不一样
	uint8_t str[5000];
	int fin,fout;
	
	FILE * outFile;
	if((outFile = fopen ("file/log_record2.txt", "wt"))==NULL)
    {
        printf("cant open the outfile");
        exit(0);
	}
	
	fin = open("file/test.txt", O_RDWR|O_BINARY, 0333);//打开磁盘文件
	fout = open("file/result2", O_RDWR|O_CREAT|O_TRUNC|O_BINARY); 
			
	for (int i = 0; i <= 100; i ++) 
	{
		
		memset(str,'\0',sizeof(str));
		nb_sectors = rand() % 8;  //产生0-7的随机数
		//sector_num= rand() % 1048576;
		sector_num= rand() % 30;
		if(i%2 == 0)
		{
			int num = read(fin, str, 512*(nb_sectors+1));
			total_bit += num;
			if( num == 0)
			{
				printf("test.doc已经读取至文件末尾\n");
				continue;
			}
			
			else
			{
				Qrow_write(qrow_state, sector_num , str, nb_sectors+1);
				fprintf(outFile,"write:sector_num:%d  nb_sectors:%d times:%d\n",sector_num,nb_sectors+1,i);
				
			}
		
		}
		else
		{
			read_sectors = Qrow_read(qrow_state, sector_num, str, nb_sectors+1);
			fprintf(outFile,"read:sector_num:%d  nb_sectors:%d times:%d\n",sector_num,nb_sectors+1,i);
			write(fout, str, read_sectors*512);
			if(read_sectors != 0)
			{
				read_times++;
			}
			
			
		}
		
	}
	
	
	
	printf("read_times:%d total_bit:%d\n",read_times,total_bit);
	if(fin != -1)
	{
		close(fin);
	}
	if(fout != -1)
	{
		close(fout);
	}
	
	Qrow_close(qrow_state);
	if(qrow_state )
	{
		free(qrow_state);
	}
	fclose (outFile);
	return 1;	
}


