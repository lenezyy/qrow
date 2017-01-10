/* QROW格式块设备驱动
 * zyy 2016
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "block/qrow_v8.h"

#include <linux/falloc.h>

//#define QROW_DEBUG

#ifdef QROW_DEBUG
#define QROW_DEBUG_BEGIN_STR "\n----------------------------------------\n"
#define QROW_DEBUG_END_STR "\n========================================\n"

//#define QROW_DEBUG_DETAIL

#ifdef QROW_DEBUG_DETAIL

//#define QROW_DEBUG_OPEN
//#define QROW_DEBUG_SET_BIT
#define QROW_DEBUG_ASSERT_CLUSTERS
//#define QROW_DEBUG_SNAPSHOT_DELETE
//#define QROW_DEBUG_READ
#define QROW_DEBUG_WRITE
//#define QROW_DEBUG_AIO_READV
//#define QROW_DEBUG_AIO_WRITEV



static void dump_QEMUIOVector(QEMUIOVector *qiov) {
	int i;
	printf("niov %d, nalloc %d, size %zd\n", qiov->niov, qiov->nalloc, qiov->size);
	for(i = 0; i < qiov->nalloc; i++) {
		printf("#%d I/O vector base %p, len %zd\n",i ,qiov->iov[i].iov_base, qiov->iov[i].iov_len);
		//dump_mem(qiov->iov[i].iov_base, qiov->iov[i].iov_len, "");
	}
}

#endif

#endif


static int qrow_probe(const uint8_t *buf, int buf_size, const char *filename)
{ // 检测魔数、版本并打分
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_probe()\n");
	printf("buf_size: %d, filename: %s\n", buf_size, filename);
#endif

	const QRowMeta *qrow_meta = (const void *)buf;

    if (buf_size >= sizeof(QRowMeta) &&
        be32_to_cpu(qrow_meta->magic) == QROW_MAGIC &&
        be32_to_cpu(qrow_meta->version) == QROW_VERSION){
#ifdef QROW_DEBUG
	printf("return 100" QROW_DEBUG_END_STR);
#endif
        return 100;
    }
    else {
#ifdef QROW_DEBUG
	printf("return 0" QROW_DEBUG_END_STR);
#endif
        return 0;
    }
}

static int qrow_update_map_file(BDRVQrowState *bqrows) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_update_map_file()\n");
	printf("map_is_dirty %d\n", bqrows->map_is_dirty);
#endif
	if(bqrows->map_is_dirty) {
		if(bdrv_pwrite(bqrows->qrow_map_file, 0, bqrows->map, bqrows->map_size*sizeof(uint64_t) ) != bqrows->map_size*sizeof(uint64_t)) {
			fprintf(stderr, "Failed to write the qrow map data to %s\n", bqrows->map_file);
			ret = -1;
			goto end;
		}
		bqrows->map_is_dirty = 0;
		// bdrv_pwrite是按sector写入，文件不是整sector的话需要截断
		ret = bdrv_truncate(bqrows->qrow_map_file, bqrows->map_size*sizeof(uint64_t));
		
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_update_map_file()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_update_meta_file(BlockDriverState *bs) {
	BDRVQrowState *s = bs->opaque;
	QRowMeta meta;
	int ret = 0;
	if (bdrv_pread (bs->file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
			fprintf (stderr, "Failed to read the meta data \n");
			ret = -1;
			goto end;
	}
	meta.sector_offset = cpu_to_be64(s->sector_offset);
	if(bdrv_pwrite(bs->file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to write the meta data \n");
		ret = -1;
		goto end;
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_update_meta()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}


static void qrow_close(BlockDriverState *bs) {

	BDRVQrowState *s = bs->opaque;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_close\n");
#endif
	if(s->map) {
#ifdef QROW_DEBUG
		printf("free map \n");
#endif
		qemu_free(s->map);
		s->map = NULL;
	}
	if(s->meta_file) {
#ifdef QROW_DEBUG
		printf("free meta_file (%s)\n", s->meta_file);
#endif
		qemu_free(s->meta_file);
		s->meta_file = NULL;
	}
	if(s->data_file) {
#ifdef QROW_DEBUG
		printf("free data_file (%s)\n", s->data_file);
#endif
		qemu_free(s->data_file);
		s->data_file = NULL;
	}
	if(s->map_file) {
#ifdef QROW_DEBUG
		printf("free map_file (%s)\n", s->map_file);
#endif
		qemu_free(s->map_file);
		s->map_file = NULL;
	}
	/*
	if(s->outFile)
	{
		fclose (s->outFile);
	}
	*/
	
/*  log_file
	if(s->log_file) {
#ifdef QROW_DEBUG
		printf("free log_file (%s)\n", s->log_file);
#endif
		qemu_free(s->log_file);
		s->log_file = NULL;
	}
*/
	if(s->qrow_meta_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_meta_file\n");
#endif
		bdrv_delete(s->qrow_meta_file);
		s->qrow_meta_file = NULL;
	}
	
	if(s->qrow_data_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_data_file\n");
#endif
		bdrv_delete(s->qrow_data_file);
		s->qrow_data_file = NULL;
	}
	if(s->qrow_map_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_map_file\n");
#endif
		bdrv_delete(s->qrow_map_file);
		s->qrow_map_file = NULL;
	}
	
/*
	if(s->qrow_log_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_log_file\n");
#endif
		bdrv_delete(s->qrow_log_file);
		s->qrow_log_file = NULL;
	}
*/

#ifdef QROW_DEBUG
	printf("qrow_close() return" QROW_DEBUG_END_STR);
#endif
}
static int qrow_open_data_file(BDRVQrowState *bqrows, int flags) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_data_file()\n");
#endif
	// 打开data_file文件
	if(bqrows->data_file == NULL || bqrows->data_file[0] == '\0') {
		fprintf (stderr, "Void data file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_data_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_data_file, bqrows->data_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_open_data_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
/*
static int qrow_open_log_file(BDRVQrowState *bqrows, int flags) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_data_file()\n");
#endif
	
	if(strlen(bqrows->meta_file) + strlen("log") + 1 >= MAX_FILE_NAME_LENGTH) {
		fprintf(stderr, "Invalid filename length, max is %d\n", MAX_FILE_NAME_LENGTH);
		ret = -1;
		goto end;
	}
	char *log_file = NULL;
	log_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strcpy(log_file, bqrows->meta_file);
	strcat(log_file, ".");
	strcat(log_file, "log");
	bqrows->outFile = fopen (log_file, "wt");
	if(bqrows->outFile==NULL)
    {
        printf("cant open the outfile");
        ret = -1;
		goto end;
	}
	
	
	
end:
#ifdef QROW_DEBUG
	printf("qrow_open_log_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(log_file)
	{
		qemu_free(log_file);
		log_file = NULL;
	}
	return ret;
}
*/
static int qrow_open_map_file(BDRVQrowState *bqrows, int flags) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_map_file()\n");
#endif
	// 打开map_file文件
	if(bqrows->map_file == NULL || bqrows->map_file[0] == '\0') {
		fprintf (stderr, "Void map file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_map_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_map_file, bqrows->map_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	bqrows->map = qemu_mallocz(bqrows->map_size*sizeof(uint64_t));
	if(bdrv_pread(bqrows->qrow_map_file, 0, bqrows->map, bqrows->map_size*sizeof(uint64_t)) != bqrows->map_size*sizeof(uint64_t)) {
		fprintf(stderr, "Failed to read map_file from %s\n", bqrows->map_file);
		ret = -1;
		goto end;
	}
	bqrows->map_is_dirty = 0;
	ret = 0;	
end:
#ifdef QROW_DEBUG
	printf("qrow_open_map_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open_meta_file(BlockDriverState *bs, BDRVQrowState *bqrows,int flags) {
	int ret = 0;
	QRowMeta meta;
#ifdef 	QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_meta_file()\n");
#endif

	if (bdrv_pread (bs->file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to read the QROW meta data \n");
		ret = -1;
		goto end;
	}
	be32_to_cpus(&meta.magic);
	be32_to_cpus(&meta.version);
	be64_to_cpus(&meta.total_sectors);
	be64_to_cpus(&meta.disk_size);
	be64_to_cpus(&meta.sector_offset);
	
#ifdef IROW_DEBUG_DETAIL
	printf("meta.magic: %x\n", meta.magic);
	printf("meta.version: %x\n", meta.version);
	printf("meta.total_sectors: 0x%" PRIx64 "(%" PRId64 ")\n", meta.total_sectors, meta.total_sectors);
	printf("meta.disk_size: 0x%" PRIx64 "(%" PRId64 "M)\n", meta.disk_size, meta.disk_size / (1024 * 1024));
	printf("meta.sector_offset: %x\n", meta.sector_offset);
#endif

	if(meta.magic != QROW_MAGIC || meta.version != QROW_VERSION) {
		fprintf (stderr, "Invalid magic number or version number!\n");
		ret = -1;
		goto end;
	}
	bqrows->total_sectors = meta.total_sectors;
	bqrows->disk_size = meta.disk_size;
	bs->total_sectors = meta.total_sectors;
	/* //没办法使用lseek这个函数
	int fd = open(filename, O_RDWR|O_BINARY, 0333);//打开磁盘文件
	if (fd < 0) 
	{
		printf("Can not open %s\n", filename);
		return 0;
	}
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//先获取文件大小
	lseek(fd, 0, SEEK_SET);//将读写位置移动到文件开头处 
	uint64_t cur_cluster_offset = (cur_disk_size % s->cluster_size == 0) ? (cur_disk_size / s->cluster_size) : (cur_disk_size / s->cluster_size+1);
	s->cluster_offset = (s->cluster_offset < cur_cluster_offset) ? cur_cluster_offset : s->cluster_offset;
	*/
	
	bqrows->sector_offset = meta.sector_offset;
	bqrows->byte_offset = bqrows->sector_offset * BDRV_SECTOR_SIZE;
	bqrows->map_size = meta.disk_size / BDRV_SECTOR_SIZE;
	bqrows->meta_file = NULL;
	bqrows->meta_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	pstrcpy(bqrows->meta_file, MAX_FILE_NAME_LENGTH, bs->filename);
	bqrows->map_file = NULL;
	bqrows->map_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	if(qrow_generate_filename(bqrows->map_file, bs->filename, "map") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
	
	bqrows->data_file = NULL;
	bqrows->data_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	if(qrow_generate_filename(bqrows->data_file, bs->filename, "data") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
	pstrcpy(bs->backing_file, sizeof(bs->backing_file),meta.backing_file);
	/*
	bqrows->log_file = NULL;
	bqrows->log_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	if(qrow_generate_filename(bqrows->log_file, meta.meta_file, "log") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
   	
	//log_file还没处理的，
	
	//zyy
	bqrows->read_total_sectors = 0;
	bqrows->read_sectors = 0;
	bqrows->aio_read_sectors = 0;
	//end
	*/
#ifdef QROW_DEBUG
	printf("backing_file \"%s\"\n", bs->backing_file);
#endif
end:
#ifdef QROW_DEBUG
	printf("qrow_open_meta_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open(BlockDriverState *bs, int flags) {
    BDRVQrowState *s = bs->opaque;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open()\n");
	//printf("filename: %s, flags: %d\n", filename, flags);
#endif
#ifdef QROW_DEBUG_OPEN
	printf("press Enter to continue...\n");
	getchar();
#endif
	
	s->open_flags = flags;
	//打开meta_file，获取元数据信息
	if(qrow_open_meta_file(bs,s,flags) < 0) {
    	fprintf (stderr, "Failed to open img\n");
    	goto fail;
    }

	// 再打开map_file文件
    if(qrow_open_map_file(s, flags) < 0) {
    	goto fail;
    }
    
    
    // 再打开data_file文件
    if(qrow_open_data_file(s, flags) < 0) {
    	goto fail;
    }
    // 再打开log_file文件
    /*
    if(qrow_open_log_file(s, flags) < 0) {
    	goto fail;
    }
    */
    
#ifdef QROW_DEBUG 
    printf("qrow_open return 0" QROW_DEBUG_END_STR);
#endif
    return 0;

fail:
#ifdef QROW_DEBUG 
	printf("qrow_open return -1" QROW_DEBUG_END_STR);
#endif
	qrow_close (bs);
	return -1;
}
static int bubbleSort(QrowReadState* readState, int len)
{
	int ret = 0;
    int i = 0; 
    int flag = 0;
    for (; i < len; i++)
    {
        flag = 0; //如果一趟比较下来，没有元素交换位置，证明数组已经排好序了，不用再进行后续的比较
        int j = 0;
        for (; j < len - i -1; j++)
        {
            QrowReadState  *readState_ptr1;
        	QrowReadState  *readState_ptr2;
        	readState_ptr1 = readState + j;
        	readState_ptr2 = readState + j + 1;
            if (readState_ptr1->sector_num > readState_ptr2->sector_num)
            {
                QrowReadState  *readState_ptr = readState_ptr1;
                readState_ptr1 = readState_ptr2;
                readState_ptr2 = readState_ptr;
                flag = 1;
            }
        }
        if (flag == 0)
        {
            break;
        }
    }
    ret = i;
#ifdef IROW_DEBUG
	printf("bubbleSort" QROW_DEBUG_END_STR, ret);
#endif
	return ret;

}


static int qrow_read(BlockDriverState *bs, int64_t sector_num, uint8_t *buf, int nb_sectors) {
	int ret = 0;
	BDRVQrowState *s = bs->opaque;
	//s->read_sectors += nb_sectors;
	//s->read_total_sectors += nb_sectors;
	//fprintf(s->outFile,"qrow_read: sector_num: %" PRId64 ", nb_sectors: %d\n", sector_num, nb_sectors);
	//fprintf(s->outFile,"read_sectors: %" PRId64 ", read_total_sectors: %" PRId64 "\n", s->read_sectors, s->read_total_sectors);
	//
	QrowReadState *readState = NULL;
	readState = qemu_mallocz(nb_sectors*sizeof(QrowReadState));
	QrowReadState  *readState_ptr;
	//
	
	int64_t i = sector_num;
	int j = 0;
	for (; j < nb_sectors; i++,j++) 
	{
		readState_ptr = readState + j;
		readState_ptr->sector_num = s->map[i];//从map数组中获取数据在物理磁盘上的存储扇区号
		readState_ptr->index = j;
	}
 	bubbleSort(readState,nb_sectors);//给 readState 按照 sector_num排序，增序
	 
	//按照增序sector_num从镜像中读取数据并且复制到 buf中 
	int k = 0; 
	for (; k < nb_sectors; k++) 
		{
			readState_ptr = readState + k;
			if(bdrv_pread(s->qrow_data_file, readState_ptr->sector_num*BDRV_SECTOR_SIZE, buf+readState_ptr->index*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
					fprintf (stderr, "Failed to read the  data from %s\n", s->data_file);
					ret= -1;
					goto end;
				}
			
			
		}	
end:
#ifdef IROW_DEBUG
	printf("qrow_read return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(readState != NULL) {
			qemu_free(readState);
			readState = NULL;
		}
	return ret;

}


static int qrow_write(BlockDriverState *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
	BDRVQrowState *s = bs->opaque;
	//fprintf(s->outFile,"qrow_write: sector_num: %" PRId64 ", nb_sectors: %d\n", sector_num, nb_sectors);
	int64_t sector_offset;
	int ret = 0;
	if (s->sector_offset >= s->total_sectors){ //磁盘已满
		fprintf (stderr, "img is full!\n");
		ret = -1;
		goto end;
	}
	if (s->sector_offset + nb_sectors > s->total_sectors){ //写入区域超出磁盘最大范围
		fprintf (stderr, "Invalid nb_sectors!\n");
		ret = -1;
		goto end;
	}
	if(bdrv_pwrite(s->qrow_data_file,s->byte_offset, buf, nb_sectors*BDRV_SECTOR_SIZE) != nb_sectors*BDRV_SECTOR_SIZE) {
		fprintf(stderr, "Failed to write \n");
		ret = -1;
		goto end;
	}
	sector_offset = s->sector_offset;
	
	int64_t i = sector_num;
	int j = 0;
	for ( ; j < nb_sectors; i++, j++) //更新map数组的值，即更新虚拟磁盘和物理磁盘的数据映射关系 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	// 更新map_file文件里面的map数组的值
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		ret = -1;
		goto end;
	}
	s->sector_offset += nb_sectors;
	s->byte_offset = s->sector_offset * BDRV_SECTOR_SIZE;
	
	// 更新meta_file文件里面的meta关于offset的值
	if(qrow_update_meta_file(bs) < 0) {
		fprintf (stderr, "Failed to update meta_file. (%s)\n", s->meta_file);
		ret = -1;
		goto end;
	}
end:
	
#ifdef QROW_DEBUG
	printf("qrow_write return %d" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

int qrow_generate_filename(char *dest, const char *prefix, const char *suffix) {
	// dst = prefix-body.suffix
	if(strlen(prefix) + strlen(suffix) + 1 >= MAX_FILE_NAME_LENGTH) {
		fprintf(stderr, "Invalid filename length, max is %d\n", MAX_FILE_NAME_LENGTH);
		return -1;
	}
	strcpy(dest, prefix);
	strcat(dest, ".");
	strcat(dest, suffix);
	return 0;
}

static int qrow_create(const char *filename, QEMUOptionParameter *options) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create()\n");
#endif
	QRowMeta meta;
	uint64_t disk_size;
	char *backing_file = NULL;
	int ret = 0;
	// 解析参数
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
				disk_size= options->value.n;
			}else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
	            backing_file = options->value.s;
			} 
	        options++;
	}
	//判断参数
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		ret = -1;
		goto end;
	}
	if(filename[0] == '\0') {
	   fprintf(stderr, "Void img file name\n");
	   ret = -1;
	   goto end;
   	} 
	// 计算出元数据头需要的所有信息
    memset(&meta, 0, sizeof(meta));
    meta.magic = cpu_to_be32(QROW_MAGIC);	
	meta.version = cpu_to_be32(QROW_VERSION);
	meta.disk_size = cpu_to_be64(disk_size);
   	meta.total_sectors = cpu_to_be64(disk_size/BDRV_SECTOR_SIZE); // 磁盘镜像总的sector数量
	meta.sector_offset = cpu_to_be64(0);//初始位置为0 
    //strncpy(meta.meta_file, filename, MAX_FILE_NAME_LENGTH);
    if(backing_file != NULL) {
   		strncpy(meta.backing_file, backing_file, MAX_FILE_NAME_LENGTH);//这个具体怎么用？？？ 
   	}
   	/*
	if(qrow_generate_filename(meta.map_file, meta.meta_file, "map") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
   	if(qrow_generate_filename(meta.data_file, meta.meta_file, "data") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
   	*/
	//将元数据写入到meta文件中 
	int fd;	
	//fd = open(meta.meta_file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,0644);
	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,0644);
	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create() 06 %d\n",fd);
	if (fd < 0) 
	{
		fprintf(stderr, "Can not open %s\n", filename);
		ret = -1;
		goto end;
	}

	//printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create()  07\n");
	
	uint64_t writeByets = write(fd, &meta, sizeof(meta)); 
	if(writeByets != sizeof(meta))
	{
		fprintf(stderr, "Can not write meta \n");
		ret = -1;
		goto end;
	}
	
	if(close(fd) != 0) {
		fprintf(stderr, "Can not close %s\n", filename);
   		ret = -1;
		goto end;
   	}

	//创建并初始化map_file文件
	int map_file_fd;
	
	int64_t *map = NULL;
	uint64_t map_size = disk_size/BDRV_SECTOR_SIZE;
	map = qemu_mallocz(map_size*sizeof(uint64_t));
	memset(map, 0, map_size*sizeof(uint64_t));   //这里可能需要注意下，是否应该初始化为0，
	//因为当某个扇区没有写入东西时，默认为map[n]为0，当读取这个扇区时，得到的map[n]为0.实际读取的是第0个扇区的数据 
	char *map_file = NULL;
	map_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	if(qrow_generate_filename(map_file, filename, "map") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
	map_file_fd = open(map_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(map_file_fd < 0) {
		fprintf(stderr, "Can not open %s\n", map_file);
		ret = -1;
		goto end;
	}
	write(map_file_fd, map,map_size*sizeof(uint64_t));

	if(close(map_file_fd) != 0) {
		fprintf(stderr, "Can not close %s\n", map_file);
		ret = -1;
		goto end;
	}
	
	//创建并data_file文件稀疏文件  方案一 
	int data_file_fd;
	char *data_file = NULL;
	data_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	if(qrow_generate_filename(data_file, filename, "data") < 0) { // map_file文件
   		ret = -1;
   		goto end;
   	}
	
	data_file_fd = open(data_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(data_file_fd < 0) {
		fprintf(stderr, "Can not open %s\n", data_file);
		ret = -1;
		goto end;
	}
	
	if(fallocate(data_file_fd, FALLOC_FL_KEEP_SIZE, 0, disk_size) < 0) {
		;//fprintf(stderr, "Can not preallocate disk space for %s\n(Preallocation is not supported on ext3)\n", cs->irvd_file);
	}
	if (ftruncate(data_file_fd, disk_size) != 0) {
		fprintf(stderr, "Can not truncate %s to %" PRId64 " bytes\n", data_file, disk_size);
		ret = -1;
	}

	if(close(data_file_fd) != 0) {
		fprintf(stderr, "Can not close %s\n", data_file);
		ret = -1;
		goto end;
	}
	
	// 创建并data_file文件稀疏文件  方案二
	//bdrv_create_file(meta.data_file, options); 
	
	
	
end:
#ifdef QROW_DEBUG
	printf("qrow_create() return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(map != NULL)
	{
		qemu_free(map);
		map = NULL;
	}
	if(map_file != NULL)
	{
		qemu_free(map_file);
		map_file = NULL;
	}
	if(data_file != NULL)
	{
		qemu_free(data_file);
		data_file = NULL;
	}
	
	return ret;
}

static void qrow_flush(BlockDriverState *bs) {
	BDRVQrowState *s = bs->opaque;

	//bdrv_flush(s->qrow_meta_file);
	//bdrv_flush(s->qrow_map_file);
	bdrv_flush(s->qrow_data_file);
	//bdrv_flush(s->qrow_log_file);
}

typedef struct QRowAIOCB {
    BlockDriverAIOCB common;
    int64_t sector_num;
    QEMUIOVector *qiov;
    int nb_sectors;
    BlockDriverAIOCB *irvd_aiocb;

} QRowAIOCB;

static void qrow_aio_cancel(BlockDriverAIOCB *blockacb)
{
	QRowAIOCB *acb = (QRowAIOCB *)blockacb;
    if (acb->irvd_aiocb)
        bdrv_aio_cancel(acb->irvd_aiocb);
    qemu_aio_release(acb);
}

static AIOPool qrow_aio_pool = {
    .aiocb_size         = sizeof(QRowAIOCB),
    .cancel             = qrow_aio_cancel,
};


static QRowAIOCB* qrow_aio_setup(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    QRowAIOCB *acb;

    acb = qemu_aio_get(&qrow_aio_pool, bs, cb, opaque);
    if (!acb)
        return NULL;
    acb->irvd_aiocb = NULL;
    acb->sector_num = sector_num;
    acb->qiov = qiov;
    acb->nb_sectors = nb_sectors;
    return acb;
}

static void qrow_aio_readv_cb(void *opaque, int ret) {
	QRowAIOCB *acb = opaque;
	BlockDriverState *bs = acb->common.bs;
	BDRVQrowState *bqrows = bs->opaque;
	void *buf = NULL;
	
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_readv_cb()\n");
#endif
	if(ret < 0) {
		fprintf(stderr, "aio_readv failed\n");
		goto end;
	}
	buf = qemu_mallocz(acb->qiov->size);
	qemu_iovec_to_buffer(acb->qiov, buf);
	
	QrowReadState *readState = NULL;
	readState = qemu_mallocz(acb->nb_sectors*sizeof(QrowReadState));
	QrowReadState  *readState_ptr;
	
	int64_t i = acb->sector_num;
	int j = 0;
	for (; j < acb->nb_sectors; i++,j++) 
	{
		readState_ptr = readState + j;
		readState_ptr->sector_num = bqrows->map[i];//从map数组中获取数据在物理磁盘上的存储扇区号
		readState_ptr->index = j;
	}
 	bubbleSort(readState,acb->nb_sectors);//给 readState 按照 sector_num排序，增序
	
	int k = 0; 
	for (; k < acb->nb_sectors; k++) 
		{
			readState_ptr = readState + k;
			if(bdrv_pread(bqrows->qrow_data_file, readState_ptr->sector_num*BDRV_SECTOR_SIZE, buf+readState_ptr->index*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
					fprintf (stderr, "Failed to read the  data from %s\n", bqrows->data_file);
					ret= -1;
					goto end;
				}
			
			
		}	
	
		 	
	qemu_iovec_from_buffer(acb->qiov, buf, acb->qiov->size);		
end:
		if(buf != NULL) {
			qemu_free(buf);
			buf = NULL;
		}
		if(readState != NULL) {
			qemu_free(readState);
			readState = NULL;
		}
	    acb->common.cb(acb->common.opaque, ret);
	    qemu_aio_release(acb);
#ifdef QROW_DEBUG
   printf("qrow_aio_readv_cb() return" QROW_DEBUG_END_STR);
#endif
}

static BlockDriverAIOCB *qrow_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque) {
    QRowAIOCB *acb;
    BDRVQrowState *bqrows = bs->opaque;
    BlockDriver *drv;
    //bqrows->aio_read_sectors += nb_sectors;
	//bqrows->read_total_sectors += nb_sectors;
	//fprintf(bqrows->outFile,"qrow_aio_readv: sector_num: %" PRId64 ", nb_sectors: %d\n", sector_num, nb_sectors);
	//fprintf(bqrows->outFile,"aio_read_sectors: %" PRId64 ", read_total_sectors: %" PRId64 "\n", bqrows->aio_read_sectors, bqrows->read_total_sectors);
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_readv()\n");
	printf("qrow_aio_readv:sector_num %" PRId64 ", nb_sectors %d\n", sector_num, nb_sectors);
#endif
#ifdef QROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef QROW_DEBUG_AIO_READV
	printf("press Enter to continue...\n");
	getchar();
#endif

    acb = qrow_aio_setup(bs, sector_num, qiov, nb_sectors, cb, opaque);
    if (!acb)
        return NULL;
	drv = bqrows->qrow_data_file->drv;
	//注意下面的sector_num可能是出错的主要地方
	acb->irvd_aiocb = drv->bdrv_aio_readv(bqrows->qrow_data_file, sector_num, qiov, nb_sectors, qrow_aio_readv_cb, acb);
	if(acb->irvd_aiocb == NULL){
		qemu_aio_release(acb);
#ifdef QROW_DEBUG
   printf("qrow_aio_readv() return NULL" QROW_DEBUG_END_STR);
#endif
		return NULL;
	}


#ifdef QROW_DEBUG
   printf("qrow_aio_readv() return %p" QROW_DEBUG_END_STR, &acb->common);
#endif
   return &acb->common;
}

static BlockDriverAIOCB *qrow_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVQrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;
	BlockDriver *drv;
	//将打印信息写到log_file文件 
	//fprintf(s->outFile,"qrow_aio_writev: sector_num: %" PRId64 ", nb_sectors: %d\n", sector_num, nb_sectors);
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_writev()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d", sector_num, nb_sectors);
#endif
#ifdef QROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef QROW_DEBUG_AIO_WRITEV
	printf("press Enter to continue...\n");
	getchar();
#endif
	int64_t sector_offset;
	if (s->sector_offset >= s->total_sectors){ //磁盘已满
		fprintf (stderr, "img is full!\n");
		goto end;
	}
	if (s->sector_offset + nb_sectors > s->total_sectors){ //写入区域超出磁盘最大范围
		fprintf (stderr, "Invalid nb_sectors!\n");
		goto end;
	}
	//更新map缓存
	sector_offset = s->sector_offset;
	int64_t i = sector_num;
	int j = 0;
	//for (int j = 0; j < nb_sectors; i++, j++) //更新map数组的值，即更新虚拟磁盘和物理磁盘的数据映射关系 
	for (; j < nb_sectors; i++, j++)//在linux中编译时说不能在for中进行初始化 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	
	drv = s->qrow_data_file->drv;
	ret = drv->bdrv_aio_writev(s->qrow_data_file, s->sector_offset, qiov, nb_sectors, cb, opaque );
	if(ret == NULL) {
	   goto end;
	}
	
	
	// 更新map_file文件里面的map数组的值
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		goto end;
	}
	
	s->sector_offset += nb_sectors;
	s->byte_offset = s->sector_offset * BDRV_SECTOR_SIZE;
	// 更新meta_file文件里面的meta关于offset的值
	if(qrow_update_meta_file(bs) < 0) {
		fprintf (stderr, "Failed to update meta_file. (%s)\n", s->meta_file);
		goto end;
	}
end:
	
#ifdef QROW_DEBUG
   printf("qrow_aio_writev() return %p" QROW_DEBUG_END_STR, ret);
#endif
   return ret;
}

static BlockDriverAIOCB *qrow_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVQrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_flush()\n");
#endif

	ret = bdrv_aio_flush(s->qrow_data_file, cb, opaque);

#ifdef QROW_DEBUG
	printf("qrow_aio_flush() return %p\n" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int qrow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_info()\n");
#endif
	//BDRVQrowState *s = bs->opaque;
	//bdi->cluster_size = s->cluster_size;
	//bdi->vm_state_offset = qrow_vm_state_offset(s);
#ifdef QROW_DEBUG
	printf("return from qrow_get_info()" QROW_DEBUG_END_STR);
#endif
	return 0;
}


static int64_t qrow_get_length(BlockDriverState *bs) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_lenght()\n");
#endif
	BDRVQrowState *bqrows = bs->opaque;
	int64_t ret;
	ret = bqrows->disk_size;
#ifdef QROW_DEBUG
	printf("qrow_get_lenght() return %" PRId64 QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static QEMUOptionParameter qrow_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_BACKING_FILE,
        .type = OPT_STRING,
        .help = "File name of a base image"
    },
    /*
    {
        .name = "copy_on_demand",
        .type = OPT_FLAG,
        .help = "copy clusters to current irvd when needed"
    },
	*/
    { NULL }
};

static BlockDriver bdrv_qrow = {
    .format_name	= "qrow",
    .instance_size	= sizeof(BDRVQrowState),
    .bdrv_probe		= qrow_probe,
    .bdrv_open		= qrow_open,
    .bdrv_read		= qrow_read,
    .bdrv_write		= qrow_write,
    .bdrv_close		= qrow_close,
    .bdrv_create	= qrow_create,
    .bdrv_flush		= qrow_flush,

    .bdrv_aio_readv		= qrow_aio_readv,
    .bdrv_aio_writev	= qrow_aio_writev,
    .bdrv_aio_flush		= qrow_aio_flush,
 
    .bdrv_get_info	= qrow_get_info,
    .bdrv_getlength = qrow_get_length,
    .create_options = qrow_create_options,

};

static void bdrv_qrow_init(void)
{
    bdrv_register(&bdrv_qrow);
}

block_init(bdrv_qrow_init);
