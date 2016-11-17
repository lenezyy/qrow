#include<stdio.h>
#include <stdlib.h>
#include <string.h>    
#include <fcntl.h>
#include <malloc.h>
#include <time.h>//������������� 
#include"qrow.h"
static int get_bits_from_size(uint32_t size)
{ // ���size=2^n����ô����n�����򷵻أ�1
    int ret = 0;
    if (size == 0) {
        return -1;
    }
    while (size != 1) {
    	if (size & 1) {// ����2����
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
	char *map_path = "file/qrow3.map";//��д��������ʵ�ֺ�������irow_generate_filename()�Ż� 
	/*
	if(irow_generate_filename(meta.current_btmp, cs->meta_file, cs->time_value, "btmp") < 0)	
	{
		
	}
	*/
	//���������Ƿ�Ϸ� 
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		return 0;
	}
	if(block_size == 0) {
		fprintf(stderr, "Invalid block_size\n");
		return 0;
	}
	uint32_t block_bits = get_bits_from_size(block_size); // ��ȡblock_bits
	if ((block_bits < MIN_CLUSTER_BITS) || (block_bits > MAX_CLUSTER_BITS)) {
	   // block��С512B(���ٰ���һ��sector)�����2MB,�ұ�����2����
    	fprintf(stderr, "block size must be a power of two between %d and %dB\n",
            1 << MIN_CLUSTER_BITS,
            1 << MAX_CLUSTER_BITS);
    	return 0;
    } 
	  
	/* �����Ԫ����ͷ��Ҫ��������Ϣ*/
    
	strncpy(header->format_name, magic, 8);	
	header->version = 1;
	header->block_offset = 1;//�����ļ�block��0��ʼ��ţ���0��Ĭ�ϴ��Ԫ����ͷ��Ϣ 
	//header->block_size = 4096;//Ĭ��Ϊ4K��С ���������Ҫ�ο�һ��irow��д��������һ��Ĭ��ֵ 
	//header->block_bits = 12;//Ĭ��Ϊ12 
    header->disk_size = disk_size;
    header->block_size = block_size;
    header->sectors_per_block = block_size/512; 
    header->block_bits = block_bits;
    header->total_blocks = (disk_size + block_size -1) >> block_bits;
    strncpy(header->img_name, img_file, MAX_FILE_NAME_LENGTH);
    strncpy(header->map_path, map_path, MAX_FILE_NAME_LENGTH);
	// ��disk_size ���� block_size��������ʱ��ʣ��С��block��С�Ŀռ�Ҳռ��һ��block�� 
	
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
	// ��Ԫ����ͷд������ļ��ĵ�һ��block�У���Ҫռ��һ����blockô����block�Ƚϴ��ʱ��ռ��һ�����᲻���˷ѣ��Ȱ���ռ��һ��������� 
	
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
	
	//fd = open(img_file, O_RDWR, 0333);//�򿪴����ļ�
	fd = open(img_file, O_RDWR|O_BINARY, 0333);//�򿪴����ļ�
	if (fd < 0) 
	{
		printf("Can not open %s\n", img_file);
		return 0;
	}
	
	//����������Ĵ���ʱ��û�취ʹ��lseek������� 
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//�Ȼ�ȡ�ļ���С
	lseek(fd, 0, SEEK_SET);//����дλ���ƶ����ļ���ͷ�� 
	int readBytes = read(fd, qrow, sizeof(QrowHeader));
	if(readBytes != sizeof(QrowHeader))
	{
		printf("Can not read QrowHeader\n");
		return 0;
	}
	//printf("readBytes:%d\n",readBytes);
	
	map_file_fd = open(qrow->map_path, O_RDWR|O_CREAT|O_BINARY,0333);//�������ߴ�map�ļ�
	if (map_file_fd < 0) 
	{
		printf("Can not open %s\n", qrow->map_path);
		return 0;
	}
	uint64_t map_file_size = lseek(map_file_fd, 0, SEEK_END);
	//�Ȼ�ȡmap�ļ���С�����Ϊ0����֤����û�н�map����д���ļ����ǵ�һ�δ���map�ļ������򣬽�map�ļ��е�map�����ȡ����������ֵ��qrow_state->map 
	lseek(map_file_fd, 0, SEEK_SET);//����дλ���ƶ����ļ���ͷ�� 
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
	
	//��ֹ Qrow_close()ִ��ǰ���������������������ʵ�� block_offsetֵ����Ԫ����ͷ�е�block_offsetֵ�����ԣ�ÿ�� Qrow_open����ִ�е�����ʱ��Ҫ�����ж�
	//�ж� qrow->block_offset�Ƿ���ڵ�ǰimg_file�Ĵ�С�������ڵĻ���ȡimg_file�ļ���С��ֵ�����block_offset��ֵ
	
	
	uint64_t cur_block_offset = (cur_disk_size % qrow->block_size == 0) ? (cur_disk_size / qrow->block_size) : (cur_disk_size / qrow->block_size)+1;
	qrow_state->block_offset = (qrow->block_offset < cur_block_offset) ? cur_block_offset : qrow->block_offset;
	qrow_state->byte_offset = qrow_state->block_offset * qrow_state->block_size;
	qrow_state->sector_offset = qrow_state->block_offset * qrow_state->sectors_per_block;
	qrow_state->img_file = fd; 
	qrow_state->map_file_fd = map_file_fd;
	
	 
	if(flag == 0)//flag=0,��ʾ��¼�׶Σ�1��ʾ�طŽ׶�,��ָ����log�ļ�
	{
		is_record = 1;
		log_file_fd = open(log_file, O_RDWR|O_CREAT|O_BINARY|O_APPEND,0333); 
		/*
		��Ҫ����һ�����⣬���û�����ִ��Qrow_open�����������Ǽ�¼�׶�ʱ����Ҫ����׷�� O_APPEND�ķ�ʽд�����ݣ�
		���ߣ���������log�ļ���offset��ÿ��Qrow_open��¼�׶�ʱ�����Ƚ�ָ���ƶ���offset����д�룬�����ķ�ʽ���ܸ��ӱ��� 
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
			qrow_state->log_file_fd = -1;//��ʾ���Ǽ�¼�طŽ׶Σ�û�д򿪼�¼�ļ� 
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
		//��map����д��map�ļ���
		lseek(qrow_state->map_file_fd, 0, SEEK_SET);//����дλ���ƶ����ļ���ͷ�� 
		if(write(qrow_state->map_file_fd, qrow_state->map, sizeof(qrow_state->map))<0) 
		{
			printf("can not write map\n");
			return -1;
		}
		if(qrow_state->map_file_fd != -1)
		{
			close(qrow_state->map_file_fd);
		}
		
		 
		//����Ԫ����ͷ��Ϣ�е� block_offsetֵ 
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
	��Ҫ��¼log�ļ���ƫ����ô��ÿ��ִ����read_log�����ͼ�¼һ�µ�ǰƫ�����Ƕ��� 
*/
int read_log(int img_file_fd, int log_file_fd, uint8_t *tmp_data) //����log�ļ��м�¼��ȡ���ݴ洢��������̶�Ӧ���������� 
{
	uint8_t  log_type;
	int  nb_sectors;//��ʾ���鳤�� 
	//uint64_t *sector;//��ʾ���ݴ洢��������������ŵ����� 
	uint64_t offset_sector = 0;
	QrowRRIo *rr_io = (QrowRRIo*) malloc(sizeof(QrowRRIo)) ;//���ܲ���Ҫ����ṹ�� ,ֱ�Ӷ���һ���ֲ�����uint64_t rr_or_sector[nb_sectors*sizeof(uint64_t)]���� 
	read(log_file_fd, (void *)(&log_type), sizeof(uint8_t));
	if( log_type != RRTYPE)//�жϼ�¼�����Ƿ�Ϊread���� 
	{
		return -1;
	}
	read(log_file_fd, (void *)(&nb_sectors), sizeof(int));
	//read(log_file_fd, rr_io, sizeof(QrowRRIo));
	read(log_file_fd, rr_io->sector, nb_sectors*sizeof(uint64_t));
	int num = 0;
	for (int i = 0; i < nb_sectors; i++) 
	{
		offset_sector = rr_io->sector[i];//��map�����л�ȡ��������������ϵĴ洢������ 
		lseek(img_file_fd, offset_sector*512, SEEK_SET);//������λ���ƶ�����ȷ��λ�ã�
		num = read(img_file_fd, tmp_data+i*512, 512);//��ȡһ�����������ݵ�tmp_dataָ��λ�� 
	}
	if(rr_io)
	{
		free(rr_io);
	}	
	return 0;
	
} 

int write_log(int log_file_fd, QrowRRIo *rr_io, int nb_sectors)//Ҳ���԰�log�ļ���I/O read�¼�����һ���ṹ�壬������¼���ͣ���ȡ���������� rr_io�ṹ�� 
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
	//ʵ�ʴ��̶�д�� sector_num��1��ʼ����0��������1�Ļ���qrow_statemap[0]û���壬qrow_state->map��1��ʼһֱ��i (map[i] != 0)
{
	if (sector_num < 0 || sector_num >= MAX_VM_SECTOR_NUM)//vm_total_sectors����������д����Ǿ�����δ��� 
	{
		printf("��ȡ��������ʼλ�ô���\n");
		return 0;
	} 
	if (nb_sectors <= 0 || nb_sectors > MAX_READ_SECTOR_NUM )
	{
		printf("��ȡ��������С�ڵ���0���ߴ������������ȡ����\n");
		return 0;
	}
	if ((sector_num + nb_sectors) > MAX_VM_SECTOR_NUM)
	{
		printf("��ȡ����������λ�ó����������������������λ��\n");
		return 0;
	}
	
	uint64_t sector_offset;
	int count = 0;
	QrowRRIo *rr_io = (QrowRRIo*) malloc(sizeof(QrowRRIo)) ;//���ܲ���Ҫ����ṹ�� ,ֱ�Ӷ���һ���ֲ�����uint64_t rr_or_sector[nb_sectors*sizeof(uint64_t)]���� 
	if(is_replay)//������طŽ׶Σ�ֱ�Ӷ�ȡlog�ļ���ȡ��������������еĴ洢�����ţ����ҽ������������Ӧ�����ݸ��Ƶ� buf�� 
	{
		read_log(qrow_state->img_file, qrow_state->log_file_fd, buf);
		return 1;
	}
	
	if(is_record) //����Ǽ�¼�׶Σ���read������ȡ��������������еĴ洢�����ż�¼��log�ļ��У�
	{
		rr_io->sector[MAX_READ_SECTOR_NUM] = {0};
		//int count = 0;
		for (int j = sector_num, k = 0; j < (nb_sectors+sector_num); j++) 
		{
			sector_offset = qrow_state->map[j];//��map�����л�ȡ��������������ϵĴ洢������ 
			if(sector_offset < 4 || sector_offset >= (qrow_state->total_blocks*qrow_state->sectors_per_block) ) //�ô�������Ϊ�ջ���Ϊheader���ֻ��߳������̷�Χ 
			{
				count++;
			 } 
			 else
			 {
			 	rr_io->sector[k] = sector_offset;
			 	k++;
			 }
			
			
		}
		write_log(qrow_state->log_file_fd, rr_io, nb_sectors-count);//��ÿ�ζ���������type  nb_sectors rr_io->sector[0-(nb_sectors-1)]����log�ļ� 
	
	}
	//����������ж�ȡ�������� 
	for (int i = sector_num, j = 0; i < (nb_sectors+sector_num); i++) 
	{
		sector_offset = qrow_state->map[i];//��map�����л�ȡ��������������ϵĴ洢������ 
		if(sector_offset < 4 || sector_offset >= (qrow_state->total_blocks*qrow_state->sectors_per_block) ) //�ô�������Ϊ�ջ���Ϊheader���ֻ��߳������̷�Χ 
		{
			continue; 
		} 
		 else
		 {
		 	lseek(qrow_state->img_file, sector_offset*512, SEEK_SET);//������λ���ƶ�����ȷ��λ�ã�
			int readBytes = read(qrow_state->img_file, buf+j*512, 512);//��ȡһ�����������ݵ�bufָ��λ�� 
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



int Qrow_write(QrowState *qrow_state, uint64_t sector_num, uint8_t *buf, int nb_sectors)// �����ı�Ŵ�1����0��ʼ�� 
{	
	if (sector_num < 0 || sector_num >= MAX_VM_SECTOR_NUM)//vm_total_sectors����������д����Ǿ�����δ��� 
	{
		printf("д���������ʼλ�ô���\n");
		return 0;
	} 
	if (nb_sectors <= 0 || nb_sectors > MAX_READ_SECTOR_NUM )
	{
		printf("д���������С�ڵ���0���ߴ�����������д������\n");
		return 0;
	}
	if ((sector_num + nb_sectors) > MAX_VM_SECTOR_NUM)
	{
		printf("д�����������λ�ó����������������������λ��\n");
		return 0;
	}
		int nb_block_writed = (nb_sectors % qrow_state->sectors_per_block == 0) ? (nb_sectors / qrow_state->sectors_per_block) : (nb_sectors / qrow_state->sectors_per_block + 1);
		if(qrow_state->block_offset + nb_block_writed > qrow_state->total_blocks ) //�жϴ����Ƿ����㹻��ʣ��ռ� 
		{
			fprintf(stderr, "img_file is full \n");
			return 0;
		}
		lseek(qrow_state->img_file, qrow_state->byte_offset, SEEK_SET);//��д��λ���ƶ�����ȷ��λ�ã� 
		write(qrow_state->img_file, buf, nb_sectors*512);//������д������ļ���
		uint64_t sector_offset = qrow_state->sector_offset;
		for (int i = sector_num, j = 1; j <= nb_sectors; i++, j++) //����map�����ֵ��������������̺�������̵�����ӳ���ϵ 
		{
			qrow_state->map[i] = sector_offset;
			sector_offset++;
		}
		//����ƫ������ص�ֵ 
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
	//uint64_t disk_size = 1073741824*64;//1G*64ʱ��˵������Χ�����б������� 
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
	srand((unsigned) time(NULL)); //��ʱ�����֣�ÿ�β����������һ��
	uint8_t str[5000];
	int fin,fout;
	
	FILE * outFile;
	if((outFile = fopen ("file/log_record2.txt", "wt"))==NULL)
    {
        printf("cant open the outfile");
        exit(0);
	}
	
	fin = open("file/test.txt", O_RDWR|O_BINARY, 0333);//�򿪴����ļ�
	fout = open("file/result2", O_RDWR|O_CREAT|O_TRUNC|O_BINARY); 
			
	for (int i = 0; i <= 100; i ++) 
	{
		
		memset(str,'\0',sizeof(str));
		nb_sectors = rand() % 8;  //����0-7�������
		//sector_num= rand() % 1048576;
		sector_num= rand() % 30;
		if(i%2 == 0)
		{
			int num = read(fin, str, 512*(nb_sectors+1));
			total_bit += num;
			if( num == 0)
			{
				printf("test.doc�Ѿ���ȡ���ļ�ĩβ\n");
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


