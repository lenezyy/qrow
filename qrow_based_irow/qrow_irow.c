/* qrow��Improved ROW����ʽ���豸����
 * liuhq 2012
 * qrow��ʽʹ��ROW���COW�Ķ���д�Ŀ�����ͬʱʹ��COD���ROW���ļ���Ƭ����
 * */

#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "block/qrow.h"

#include <linux/falloc.h>

BDRVqrowState **bqrows_cache = NULL; // ���ڱ���򿪵�father
ClusterCache *cluster_cache = NULL; //���ڻ��������ȡ��1��cluster

//#define QROW_DEBUG

#ifdef QROW_DEBUG
#define QROW_DEBUG_BEGIN_STR "\n----------------------------------------\n"
#define QROW_DEBUG_END_STR "\n========================================\n"

#define QROW_DEBUG_DETAIL

#ifdef QROW_DEBUG_DETAIL

//#define QROW_DEBUG_OPEN
//#define QROW_DEBUG_SET_BIT
#define QROW_DEBUG_ASSERT_CLUSTERS
//#define QROW_DEBUG_SNAPSHOT_DELETE
//#define QROW_DEBUG_READ
#define QROW_DEBUG_WRITE
//#define QROW_DEBUG_AIO_READV
//#define QROW_DEBUG_AIO_WRITEV
#define QROW_DEBUG_READ_MISSING_CLUSTSERS2

static void dump_snapshot(qrowSnapshot *snap) {
	printf("date_sec: %d\n", snap->date_sec);
	printf("date_nsec: %d\n", snap->date_nsec);
	printf("vm_clock_nsec: %ld\n", snap->vm_clock_nsec);
	printf("vm_state_size: %d\n", snap->vm_state_size);
	printf("nb_children: %d\n", snap->nb_children);
	printf("is_del: %d\n", snap->is_deleted);

	printf("id_str: %p", snap->id_str);
	if(snap->id_str) {
		printf(" (%s)", snap->id_str);
	}
	printf("\n");
	printf("name: %p", snap->name);
	if(snap->name) {
		printf(" (%s)", snap->name);
	}
	printf("\n");
	printf("btmp_file: %p", snap->btmp_file);
	if(snap->btmp_file) {
		printf(" (%s)", snap->btmp_file);
	}
	printf("\n");
	printf("irvd_file: %p", snap->irvd_file);
	if(snap->irvd_file) {
		printf(" (%s)", snap->irvd_file);
	}
	printf("\n");
	printf("father_btmp_file: %p", snap->father_btmp_file);
	if(snap->father_btmp_file) {
		printf(" (%s)", snap->father_btmp_file);
	}
	printf("\n\n");
}

static void dump_snapshots(BDRVqrowState *s) {
	qrowSnapshot *snap;
	int i;
	printf("snapshots: %p\n", s->snapshots);
	for(i = 0; i < s->nb_snapshots; i++) {
		snap = s->snapshots + i;
		printf("snapshot #%d (%p)\n", i, snap);
		dump_snapshot(snap);
		//printf("\n\n");
	}
}

static void dump_BDRVqrowState(BDRVqrowState *s) {
	printf("qrow_meta: %p\n", s->qrow_meta);
	printf("qrow_btmp: %p\n", s->qrow_btmp);
	printf("qrow_irvd: %p\n", s->qrow_irvd);
	printf("cluster_size: 0x%x(%dK) bytes\n", s->cluster_size, s->cluster_size / 1024);
	printf("cluster_bits: %d\n", s->cluster_bits);
	printf("sectors_per_cluster: %d\n", s->sectors_per_cluster);
	printf("total_clusters: %" PRIx64 "(%" PRId64 ")\n", s->total_clusters, s->total_clusters);
	printf("disk_size: 0x%" PRIx64 "(%" PRId64 "M) bytes\n", s->disk_size, s->disk_size / (1024 * 1024));
	printf("bitmap_size: 0x%" PRIx64 "(%" PRId64 "K) bytes\n", s->bitmap_size, s->bitmap_size/1024);
	printf("bitmap: %p\n" , s->bitmap);
	printf("vm_state_size: %d\n", s->vm_state_size);
	printf("nb_snapshots: %d\n", s->nb_snapshots);
	printf("copy_on_demand: %d\n", s->copy_on_demand);

	printf("meta_file: %p", s->meta_file);
	if(s->meta_file != NULL) {
		printf(" (%s)", s->meta_file);
	}
	printf("\n");

	printf("current_btmp_file: %p", s->current_btmp_file);
	if(s->current_btmp_file != NULL) {
		printf(" (%s)", s->current_btmp_file);
	}
	printf("\n");

	printf("father_btmp_file: %p", s->father_btmp_file);
	if(s->father_btmp_file != NULL) {
		printf(" (%s)", s->father_btmp_file);
	}
	printf("\n");

	printf("opened_btmp_file: %p", s->opened_btmp_file);
	if(s->opened_btmp_file != NULL) {
		printf(" (%s)", s->opened_btmp_file);
	}
	printf("\n");

	printf("irvd_file: %p", s->irvd_file);
	if(s->irvd_file != NULL) {
		printf(" (%s)", s->irvd_file);
	}
	printf("\n");

	if(s->snapshots != NULL)
		dump_snapshots(s);
}

static void dump_bqrows_cache(BDRVqrowState *s) {
	int i;
	printf("\nbqrows_cache:\n");
	if(bqrows_cache != NULL) {
		for(i = 0; i < s->nb_snapshots; i++) {
			printf("BDRVqrowState #%d ", i);
			if(bqrows_cache[i] != NULL) {
				printf("\n");
				dump_BDRVqrowState(bqrows_cache[i]);
			} else {
				printf("is NULL\n");
			}
			printf("------------------------------\n");
		}
	}
}

static void dump_mem(void *addr, unsigned int len, const char *str) {
    int i;
    unsigned char *chr_temp = (unsigned char *)addr;
    printf("%s:(%d bytes)", str, len);
    for(i = 0; i < len; i++) {
    	if(i % 16 == 0) {
    		printf("\n%p  ", addr + i);
    	}
    	else {
    		if(i % 8 == 0) {
    			printf("  ");
    		}
    	}
    	printf("%02x ", chr_temp[i]);
    }
    printf("\n");
}

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

static int get_bits_from_size(size_t size)
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

static int qrow_probe(const uint8_t *buf, int buf_size, const char *filename)
{ // ���ħ�����汾�����
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


static int qrow_check_bitmap(BDRVqrowState *bqrows) {
	uint64_t i;
	for(i = 0; i < bqrows->bitmap_size; i++) {
		if(bqrows->bitmap[i] != 0xff)
			return 0;
	}
	return 1;
}

static int qrow_update_map_file(BDRVqrowState *bqrows) {

	int ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_update_map_file()\n");
	printf("map_is_dirty %d\n", bqrows->map_is_dirty);
#endif
	if(bqrows->map_is_dirty) {
		if(bdrv_pwrite(bqrows->qrow_map_file, 0, bqrows->map, sizeof(bqrows->map)) != sizeof(bqrows->map)) {
			fprintf(stderr, "Failed to write the qrow map data to %s\n", bqrows->map_file);
			ret = -1;
			goto end;
		}
		bqrows->map_is_dirty = 0;
		// bdrv_pwrite�ǰ�sectorд�룬�ļ�������sector�Ļ���Ҫ�ض�
		ret = bdrv_truncate(bqrows->qrow_map_file, sizeof(bqrows->map));
		
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_update_map_file()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_update_img_file(BDRVqrowState *bqrows) {
	QRowMeta meta;
	if(bdrv_pread (bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
			fprintf (stderr, "Failed to read the meta data from %s\n", bqrows->qrow_img_file);
			ret = -1;
			goto end;
	}
	meta.cluster_offset = cpu_to_be64(bqrows->cluster_offset);
	if(bdrv_pwrite(bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to write the meta data to %s\n", bqrows->img_file);
		ret = -1;
		goto end;
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_update_meta()return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}


static void qrow_free_bqrows_cache(BDRVqrowState *bqrows) {
	int i;
	if(bqrows_cache != NULL) {
#ifdef QROW_DEBUG
		printf("free bqrows_cache\n");
#endif
		for(i = 0; i < bqrows->nb_snapshots; i++) {
			if(bqrows_cache[i] != NULL) {
				qrow_close_previous_state(bqrows_cache[i]);
			}
		}
		qemu_free(bqrows_cache);
		bqrows_cache = NULL;
	}
}


static void qrow_close(BlockDriverState *bs) {

	BDRVQrowState *s = bs->opaque;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_close\n");
#endif
	
	if(s->img_file) {
#ifdef QROW_DEBUG
		printf("free img_file (%s)\n", s->img_file);
#endif
		qemu_free(s->img_file);
		s->img_file = NULL;
	}
	if(s->map_file) {
#ifdef QROW_DEBUG
		printf("free map_file (%s)\n", s->map_file);
#endif
		qemu_free(s->map_file);
		s->map_file = NULL;
	}
/*  log_file
	if(s->log_file) {
#ifdef QROW_DEBUG
		printf("free log_file (%s)\n", s->log_file);
#endif
		qemu_free(s->log_file);
		s->log_file = NULL;
	}
*/
	if(s->qrow_img_file) {
#ifdef QROW_DEBUG
		printf("delete qrow_img_file\n");
#endif
		bdrv_delete(s->qrow_img_file);
		s->qrow_img_file = NULL;
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




static int qrow_find_snapshot_by_btmp(BDRVqrowState *bqrows, const char *btmp) {
	// ���ݿ��յ�id�ҵ���Ӧ�Ŀ��գ���������bqrows->snapshots�����е�����
	int i;

	for(i = 0; i < bqrows->nb_snapshots; i++) {
		if(bqrows->snapshots[i].btmp_file != NULL) {
			if(strcmp(bqrows->snapshots[i].btmp_file, btmp) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int qrow_load_info_from_snapshot(BDRVqrowState *bqrows, int snapshot_index) {
	// ��bqrows->snapshots[snapshot_index]��btmp_file, irvd_file, father_btmp_file, vm_state_size���Ƶ�bqrows����Ӧλ��
	qrowSnapshot *snap;
	int ret = 0;

	if(snapshot_index < 0) {
    	fprintf (stderr, "Invalid snapshot index.\n");
    	ret = -1;
      	goto end;
     }
    snap = bqrows->snapshots + snapshot_index;
    if(snap->btmp_file == NULL) {
    	fprintf (stderr, "Void btmp file name in snap info\n");
    	ret = -1;
    	goto end;
    }
    if(snap->irvd_file == NULL) {
    	fprintf (stderr, "Void irvd file name in snap info\n");
    	ret = -1;
    	goto end;
    }
    bqrows->opened_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    bqrows->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    strncpy(bqrows->opened_btmp_file, snap->btmp_file, MAX_FILE_NAME_LENGTH);
    strncpy(bqrows->irvd_file, snap->irvd_file, MAX_FILE_NAME_LENGTH);
    if(snap->father_btmp_file) {
    	bqrows->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    	strncpy(bqrows->father_btmp_file, snap->father_btmp_file, MAX_FILE_NAME_LENGTH);
    }
    bqrows->vm_state_size = snap->vm_state_size;
end:
	return ret;
}


static int qrow_init_bqrows_cache(BDRVqrowState *bqrows) {
	int ret = 0;
	bqrows_cache = qemu_mallocz(sizeof(BDRVqrowState *) * bqrows->nb_snapshots);
	if(bqrows_cache == NULL) {
		ret = -1;
		goto end;
	}
	/*for(i = 0; i < bqrows->nb_snapshots; i++) {
		if(bqrows->snapshots[i].name != NULL) {
			if(strcmp(bqrows->snapshots[i].name, "current state") != 0) {
				bqrows_cache[i] = qrow_open_previous_state(bqrows, i);
				if(bqrows_cache[i] == NULL) {
					ret = -1;
					goto end;
				}
			}
		}
	}*/
end:
	return ret;
}

static int qrow_open_map_file(BDRVIrowState *bqrows, int flags) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_map_file()\n");
#endif
	// ��map_file�ļ�
	if(bqrows->map_file == NULL || bqrows->map_file[0] == '\0') {
		fprintf (stderr, "Void btmp file name\n");
		ret = -1;
		goto end;
	}
	bqrows->qrow_map_file = bdrv_new ("");
	ret = bdrv_file_open(&bqrows->qrow_map_file, bqrows->map_file, flags);
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	if(bdrv_pread(bqrows->qrow_map_file, 0, bqrows->map, sizeof(bqrows->map)) != sizeof(bqrows->map)) {
		fprintf(stderr, "Failed to read map_file from %s\n", bqrows->map_file);
		ret = -1;
		goto end;
	}
	bqrows->map_is_dirty = 0;
	ret = 0;	
end:
#ifdef IROW_DEBUG
	printf("qrow_open_map_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open_img_file(BlockDriverState *bs, BDRVQrowState *bqrows, const char *filename, int flags) {
	int ret = 0;
	QRowMeta meta;


#ifdef IROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open_img_file()\n");
#endif

	bqrows->qrow_img_file = bdrv_new ("");
	//��raw�ķ�ʽ�򿪾����ļ��Ļ������յ��õľ���qemu_open() ����������open()
	ret = bdrv_file_open(&bqrows->qrow_img_file, filename, flags);
	if (ret < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		goto end;
	}
	if (bdrv_pread (bqrows->qrow_img_file, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to read the QROW meta data from %s\n", filename);
		ret = -1;
		goto end;
	}
	be32_to_cpus(&meta.magic);
	be32_to_cpus(&meta.version);
	be32_to_cpus(&meta.cluster_size);
	be32_to_cpus(&meta.cluster_bits);
	be32_to_cpus(&meta.sectors_per_cluster);
	be64_to_cpus(&meta.total_clusters);
	be64_to_cpus(&meta.disk_size);
	be64_to_cpus(&meta.cluster_offset);
#ifdef IROW_DEBUG_DETAIL
	printf("meta.magic: %x\n", meta.magic);
	printf("meta.version: %x\n", meta.version);
	printf("meta.cluster_size: 0x%x(%dK)\n", meta.cluster_size, meta.cluster_size / 1024);
	printf("meta.cluster_bits: %d\n", meta.cluster_bits);
	printf("meta.total_clusters: 0x%" PRIx64 "(%" PRId64 ")\n", meta.total_clusters, meta.total_clusters);
	printf("meta.sectors_per_cluster: %d\n", meta.sectors_per_cluster);
	printf("meta.disk_size: 0x%" PRIx64 "(%" PRId64 "M)\n", meta.disk_size, meta.disk_size / (1024 * 1024));
	printf("meta.cluster_offset: 0x%\n", meta.cluster_offset);
#endif

	if(meta.magic != IROW_MAGIC || meta.version != IROW_VERSION) {
		fprintf (stderr, "Invalid magic number or version number!\n");
		ret = -1;
		goto end;
	}
	// �ж�cluster��С�Ƿ�Ϸ�
	if((meta.cluster_bits < MIN_CLUSTER_BITS) || (meta.cluster_bits > MAX_CLUSTER_BITS)) {
		fprintf (stderr, "Invalid cluster_bits!\n");
		ret = -1;
		goto end;
	}
	// �ж�cluster_size��cluster_bits�Ƿ�ƥ��
	if(meta.cluster_bits != get_bits_from_size(meta.cluster_size)) {
		fprintf (stderr, "cluster_size and cluster_bits do not match!\n");
		ret = -1;
		goto end;
	}
	// �ж�total_clusters��disk_size�Ƿ�ƥ��
	if(meta.total_clusters != ((meta.disk_size + meta.cluster_size - 1) >> meta.cluster_bits)) {
		fprintf (stderr, "total_clusters and disk_size do not match!\n");
		ret = -1;
		goto end;
	}
	// �ж�sectors_per_cluster�Ƿ�Ϸ�
	if(meta.sectors_per_cluster != (meta.cluster_size >> BDRV_SECTOR_BITS)) {
		fprintf (stderr, "Invalid sectors_per_cluster!\n");
		ret = -1;
		goto end;
	}
	bqrows->cluster_size = meta.cluster_size;
	bqrows->cluster_bits = meta.cluster_bits;
	bqrows->total_clusters = meta.total_clusters;
	bqrows->sectors_per_cluster = meta.sectors_per_cluster;
	bqrows->disk_size = meta.disk_size;
	bs->total_sectors = meta.disk_size / BDRV_SECTOR_SIZE;
	/* //û�취ʹ��lseek�������
	int fd = open(filename, O_RDWR|O_BINARY, 0333);//�򿪴����ļ�
	if (fd < 0) 
	{
		printf("Can not open %s\n", filename);
		return 0;
	}
	uint64_t cur_disk_size = lseek(fd, 0, SEEK_END);//�Ȼ�ȡ�ļ���С
	lseek(fd, 0, SEEK_SET);//����дλ���ƶ����ļ���ͷ�� 
	uint64_t cur_cluster_offset = (cur_disk_size % s->cluster_size == 0) ? (cur_disk_size / s->cluster_size) : (cur_disk_size / s->cluster_size+1);
	s->cluster_offset = (s->cluster_offset < cur_cluster_offset) ? cur_cluster_offset : s->cluster_offset;
	*/
	bqrows->cluster_offset = meta.cluster_offset��
	bqrows->byte_offset = bqrows->cluster_offset * bqrows->cluster_size;
	bqrows->sector_offset = bqrows->cluster_offset * bqrows->sectors_per_cluster;
	bqrows->meta_cluster = if(sizeof(meta) % meta.cluster_size == 0 )? (sizeof(meta) / meta.cluster_size): (sizeof(meta) / meta.cluster_size + 1);
	bqrows->img_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->img_file, filename, MAX_FILE_NAME_LENGTH);
	bqrows->map_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(bqrows->map_file, meta.map_file, MAX_FILE_NAME_LENGTH);
	strncpy(bs->backing_file, meta.backing_file, sizeof(bs->backing_file));
	//log_file��û����ģ�
	
#ifdef IROW_DEBUG
	printf("backing_file \"%s\"\n", bs->backing_file);
#endif

	/*��Ҫ���cluster_cache
	if(cluster_cache == NULL) {
		cluster_cache = qemu_mallocz(sizeof(ClusterCache));
		if(cluster_cache != NULL) {
			cluster_cache->cache = qemu_memalign(512, birows->cluster_size);
			if(cluster_cache->cache != NULL)
				memset(cluster_cache->cache, 0, birows->cluster_size);
			else {
				fprintf(stderr, "Failed to create father cache\n");
				ret = -1;
				goto end;
			}
			cluster_cache->cluster_num = -1;
		} else {
			fprintf(stderr, "Failed to create father cache\n");
			ret = -1;
			goto end;
		}
	}
	
#ifdef IROW_DEBUG
	printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
*/
end:
#ifdef IROW_DEBUG
	printf("qrow_open_img_file() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}
static int qrow_open(BlockDriverState *bs, const char *filename, int flags) {
    BDRVQrowState *s = bs->opaque;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_open()\n");
	printf("filename: %s, flags: %d\n", filename, flags);
#endif
#ifdef QROW_DEBUG_OPEN
	printf("press Enter to continue...\n");
	getchar();
#endif

	s->open_flags = flags;
	
	//��img_file����ȡԪ������Ϣ
	if(qrow_open_img_file(bs, s, filename, flags) < 0) {
    	fprintf (stderr, "Failed to open %s\n", filename);
    	goto fail;
    }
	
	// �ٴ�map_file�ļ�
    if(qrow_open_map_file(s, flags) < 0) {
    	goto fail;
    }
	/*
	if(irow_init_birows_cache(s) < 0) {
    	fprintf (stderr, "Failed to create birows_cache\n");
    	goto fail;
	}
#ifdef IROW_DEBUG
#ifdef IROW_DEBUG_DETAIL
    dump_mem(s, sizeof(BDRVIrowState), "BDRVIrowState after irow_open_vd");
    dump_BDRVIrowState(s);

    dump_birows_cache(s);
#endif
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

static int qrow_get_bit(BDRVqrowState *bqrows, int64_t cluster_index) {
	int64_t byte_index, bit_index;

	byte_index = cluster_index >> 3;
	bit_index = cluster_index & 0x7;
	return (bqrows->bitmap[byte_index] >> bit_index) & 1;
}

static void qrow_set_bit(BDRVqrowState *bqrows, int64_t cluster_index) {
	int64_t byte_index, bit_index;
	int old_bit;

	if(cluster_cache != NULL) {
		if(cluster_index == cluster_cache->cluster_num)
			cluster_cache->cluster_num = -1; // ��Ϊcluster�Ķ��������Խ�cluster_cache����Ϊ��Ч
	}

	byte_index = cluster_index >> 3;
	bit_index = cluster_index & 0x7;
#ifdef QROW_DEBUG_DETAIL
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_set_bit()\n");
	printf("cluster_index %" PRId64 ", byte_index %" PRId64 ", bit_index %" PRId64 "\n", cluster_index, byte_index, bit_index);
	printf("byte before set bit 0x%02x\n", bqrows->bitmap[byte_index]);
#endif
	old_bit = (bqrows->bitmap[byte_index] >> bit_index) & 1;
	if(old_bit == 0) {
		bqrows->bitmap[byte_index] |= (1 <<  bit_index);
		bqrows->bitmap_is_dirty = 1;
	}
#ifdef QROW_DEBUG_DETAIL
	printf("byte after set bit 0x%02x" QROW_DEBUG_END_STR, bqrows->bitmap[byte_index]);
#endif
#ifdef QROW_DEBUG_SET_BIT
	if(cluster_index <= 256) {
	printf("press Enter to continue...");
	getchar();
	}
#endif

}



static int qrow_read_missing_clusters2(BlockDriverState *bs, BDRVqrowState *bqrows, int64_t start_cluster, int64_t nb_clusters, uint8_t *buf, uint8_t *buf_bitmap, uint64_t buf_start) {
	// �ж�cluster_index��Ӧ��cluster�Ƿ�����ڵ�ǰ�Ĵ��̾����У�������ڣ��͵ݹ�Ĵ�father�����ж�ȡ��buf��buf_index����
	//BDRVqrowState *new_bqrows = NULL;
	int64_t continuous_missing_clusters, continuous_appearing_clusters, i, cluster_index, buf_index;
	int64_t backing_len, backing_sector_num, backing_nb_sectors;
	uint8_t *backing_buf;
	int snap_index, ret = 0;
	BlockDriver *drv;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_read_missing_clusters2()\n");
	printf("start_cluster %" PRId64 ", nb_clusters %" PRId64 ",buf_start %" PRId64 "\n", start_cluster, nb_clusters, buf_start);
#endif
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(bqrows);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
	printf("press Enter to continue...\n");
	getchar();
#endif
	continuous_missing_clusters = 0;
	continuous_appearing_clusters = 0;
	for(i = 0; i < nb_clusters; i++) {
#ifdef QROW_DEBUG_DETAIL
		printf("i %" PRId64 ", continuous_missing_clusters %" PRId64 ",continuous_appearing_clusters %" PRId64 "\n",
				i, continuous_missing_clusters, continuous_appearing_clusters);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
		printf("press Enter to continue...\n");
		getchar();
#endif
		if(qrow_get_bit(bqrows, start_cluster + i) == 0) {// ���cluster���ڴ򿪵��ļ���
			buf_bitmap[buf_start + i] = 1;
			continuous_missing_clusters += 1;
			if(continuous_appearing_clusters != 0) {
				if(strcmp(bqrows->current_btmp_file, bqrows->opened_btmp_file) != 0) { // ���ڵ�ǰ�ļ��в���Ҫ��ȡ
					cluster_index = start_cluster + i - continuous_appearing_clusters;
					buf_index = buf_start + i - continuous_appearing_clusters;
#ifdef QROW_DEBUG
					printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
					if(cluster_cache != NULL) {
						if(cluster_cache->cache != NULL) {
							//����Ӧ���ټ���һ���ж��Ƿ�Ϊͬһ���ļ�
#ifdef QROW_DEBUG
							printf("cluster_index %" PRId64 ", cluster_cache->cluster_num %" PRId64 "\n",
									cluster_index, cluster_cache->cluster_num);
#endif
							if(cluster_index == cluster_cache->cluster_num) {
#ifdef QROW_DEBUG
								printf("copying from cluster_cache\nbuf_index %" PRId64 "\n", buf_index);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
								memcpy(buf + buf_index * bqrows->cluster_size, cluster_cache->cache, bqrows->cluster_size);
								cluster_index += 1;
								buf_index += 1;
								continuous_appearing_clusters -= 1;
								if(continuous_appearing_clusters == 0) {
									continue;
								}
							}
						}
					}
					drv = bqrows->qrow_irvd->drv;
#ifdef QROW_DEBUG
					printf("reading from father...\n");
#endif
#ifdef QROW_DEBUG_DETAIL
					printf("cluster_index %" PRId64 ", buf_index %" PRId64 ", continuous_appearing_clusters %" PRId64 "\n",
							cluster_index, buf_index, continuous_appearing_clusters);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
		printf("press Enter to continue...\n");
		getchar();
#endif
					if(drv->bdrv_read(bqrows->qrow_irvd,
								cluster_index * bqrows->sectors_per_cluster,
								buf + buf_index * bqrows->cluster_size,
								continuous_appearing_clusters * bqrows->sectors_per_cluster) < 0) {
							fprintf(stderr, "Failed to read clusters from %s\n", bqrows->irvd_file);
							ret = -1;
							goto end;
						}
#ifdef QROW_DEBUG
					printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
					if(cluster_cache != NULL) {
						if(cluster_cache->cache != NULL) {
#ifdef QROW_DEBUG
							printf("copying to father cache\n");
#endif
							memcpy(cluster_cache->cache, buf + (buf_start + i - 1) * bqrows->cluster_size, bqrows->cluster_size);
							cluster_cache->cluster_num = start_cluster + i - 1;
						}
					}
					} else {
#ifdef QROW_DEBUG
						printf("cluster(s) in current irvd, do nothing...\n");
#endif
				}
				continuous_appearing_clusters = 0;
			}
		} else {// ���cluster�ڴ򿪵��ļ���
			continuous_appearing_clusters += 1;
			if(continuous_missing_clusters != 0) {
				if(bqrows->father_btmp_file != NULL) { // ��father����
					snap_index = qrow_find_snapshot_by_btmp(bqrows, bqrows->father_btmp_file); // ���father�ڿ��������е�����
#ifdef QROW_DEBUG
					printf("snap_index %d\n", snap_index);
#endif
					if(bqrows_cache[snap_index] == NULL) {
						bqrows_cache[snap_index] = qrow_open_previous_state(bqrows, snap_index); // ������father
						if(bqrows_cache[snap_index] == NULL) {
							ret = -1;
							goto end;
						}
					}
#ifdef QROW_DEBUG_DETAIL
					dump_bqrows_cache(bqrows);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
#ifdef QROW_DEBUG
					printf("Recursive calling qrow_read_missing_clusters2...\n");
#endif
					ret = qrow_read_missing_clusters2(bs,
																bqrows_cache[snap_index],
																start_cluster + i - continuous_missing_clusters,
																continuous_missing_clusters,
																buf,
																buf_bitmap,
																buf_start + i - continuous_missing_clusters); // ������father��ȡ

				} else { // û��father����
					if(bs->backing_hd) { // ��base image
					    backing_len = bdrv_getlength(bs->backing_hd) / 512;
					    backing_sector_num = (start_cluster + i - continuous_missing_clusters) * bqrows->sectors_per_cluster;
					    backing_nb_sectors = continuous_missing_clusters * bqrows->sectors_per_cluster;
					    backing_buf = buf + (buf_start + i - continuous_missing_clusters) * bqrows->cluster_size;
#ifdef QROW_DEBUG
						printf("read from base image\n");
						printf("backing_len %" PRId64 ", backing_sector_num %" PRId64 ", backing_nb_sectors %" PRId64 "\nbuf %p, backing_buf %p\n",
								backing_len, backing_sector_num, backing_nb_sectors, buf, backing_buf);
#endif
					    if(backing_sector_num < backing_len) { // ��ȡ��λ����base image��
					    	if(backing_nb_sectors  > backing_len - backing_sector_num) {
					    		backing_nb_sectors = backing_len - backing_sector_num; // ȷ����ȡ��Խ��
					    	}
					    	if(bdrv_read(bs->backing_hd, backing_sector_num, backing_buf, backing_nb_sectors)<0) {
					    		fprintf(stderr, "failed to read base image: %s\n", bs->backing_file);
					    		ret = -1;
								goto end;
					    	}
					    }
					}
				}
				continuous_missing_clusters = 0;
			}
		}
	}
#ifdef QROW_DEBUG
	printf("after loop\n");
	printf("continuous_missing_clusters %ld, continuous_appearing_clusters %ld\n",
			continuous_missing_clusters, continuous_appearing_clusters);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
	if(continuous_missing_clusters != 0) {
		if(bqrows->father_btmp_file != NULL) {
			snap_index = qrow_find_snapshot_by_btmp(bqrows, bqrows->father_btmp_file); // ���father�ڿ��������е�����
#ifdef QROW_DEBUG
			printf("snap_index %d\n", snap_index);
#endif
			if(bqrows_cache[snap_index] == NULL) {
				bqrows_cache[snap_index] = qrow_open_previous_state(bqrows, snap_index); // ������father
				if(bqrows_cache[snap_index] == NULL) {
					ret = -1;
					goto end;
				}
			}
#ifdef QROW_DEBUG_DETAIL
			dump_bqrows_cache(bqrows);
#endif
#ifdef QROW_DEBUG
			printf("Recursive calling qrow_read_missing_clusters2...\n");
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			ret = qrow_read_missing_clusters2(bs,
														bqrows_cache[snap_index],
														start_cluster + i - continuous_missing_clusters,
														continuous_missing_clusters,
														buf,
														buf_bitmap,
														buf_start + i - continuous_missing_clusters); // ������father��ȡ

		} else { // û��father����
			if(bs->backing_hd) { // ��base image
			    backing_len = bdrv_getlength(bs->backing_hd) / 512;
			    backing_sector_num = (start_cluster + i - continuous_missing_clusters) * bqrows->sectors_per_cluster;
			    backing_nb_sectors = continuous_missing_clusters * bqrows->sectors_per_cluster;
			    backing_buf = buf + (buf_start + i - continuous_missing_clusters) * bqrows->cluster_size;
#ifdef QROW_DEBUG
				printf("read from base image\n");
				printf("backing_len %" PRId64 ", backing_sector_num %" PRId64 ", backing_nb_sectors %" PRId64 "\nbuf %p, backing_buf %p\n",
						backing_len, backing_sector_num, backing_nb_sectors, buf, backing_buf);
#endif
			    if(backing_sector_num  < backing_len) { // ��ȡ��λ����base image��
			    	if(backing_nb_sectors > backing_len - backing_sector_num) {
			    		backing_nb_sectors = backing_len - backing_sector_num; // ȷ����ȡ��Խ��
			    	}
			    	if(bdrv_read(bs->backing_hd, backing_sector_num, backing_buf, backing_nb_sectors)<0) {
			    		fprintf(stderr, "failed to read base image: %s\n", bs->backing_file);
			    		ret = -1;
						goto end;
			    	}
			    }
			}
		}
		continuous_missing_clusters = 0;
	}

	if(continuous_appearing_clusters != 0) {
		if(strcmp(bqrows->current_btmp_file, bqrows->opened_btmp_file) != 0) { // ���ڵ�ǰ�ļ��в���Ҫ��ȡ
			cluster_index = start_cluster + i - continuous_appearing_clusters;
			buf_index = buf_start + i - continuous_appearing_clusters;
#ifdef QROW_DEBUG
			printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(cluster_cache != NULL) {
				if(cluster_cache->cache != NULL) {
					//����Ӧ���ټ���һ���ж��Ƿ�Ϊͬһ���ļ�
#ifdef QROW_DEBUG
					printf("cluster_index %" PRId64 ", cluster_cache->cluster_num %" PRId64 "\n",
							cluster_index, cluster_cache->cluster_num);
#endif
					if(cluster_index == cluster_cache->cluster_num) {
#ifdef QROW_DEBUG
						printf("copying from cluster_cache\n");
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
						memcpy(buf + buf_index * bqrows->cluster_size, cluster_cache->cache, bqrows->cluster_size);
						cluster_index += 1;
						buf_index += 1;
						continuous_appearing_clusters -= 1;
						if(continuous_appearing_clusters == 0) {
							goto end;
						}
					}
				}
			}
			drv = bqrows->qrow_irvd->drv;
#ifdef QROW_DEBUG
			printf("Reading from father...\n");
#endif
#ifdef QROW_DEBUG_DETAIL
					printf("cluster_index %" PRId64 ", buf_index %" PRId64 ", continuous_appearing_clusters %" PRId64 "\n",
							cluster_index, buf_index, continuous_appearing_clusters);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(drv->bdrv_read(bqrows->qrow_irvd,
						cluster_index * bqrows->sectors_per_cluster,
						buf + buf_index * bqrows->cluster_size,
						continuous_appearing_clusters * bqrows->sectors_per_cluster) < 0) {
					fprintf(stderr, "Failed to read clusters from %s\n", bqrows->irvd_file);
					ret = -1;
				}
#ifdef QROW_DEBUG
			printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef QROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(cluster_cache != NULL) {
				if(cluster_cache->cache != NULL) {
#ifdef QROW_DEBUG
					printf("copying to father cache\n");
#endif
					memcpy(cluster_cache->cache, buf + (buf_start + i - 1) * bqrows->cluster_size, bqrows->cluster_size);
					cluster_cache->cluster_num = start_cluster + i - 1;
				}
			}
		} else {
#ifdef QROW_DEBUG
				printf("cluster(s) in current irvd, do nothing...\n");
	#endif
		}
		continuous_appearing_clusters = 0;
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_read_missing_clusters2() return %d\n" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_read_missing_clusters(BlockDriverState *bs, int64_t first_cluster, int64_t last_cluster, uint8_t *buf, uint8_t *buf_bitmap, int is_read) {
	// ����first_cluster��last_cluster�У����ڵ�ǰ����cluster��father�ж�ȡ��buf�е���Ӧ��λ�ã�buf_bitmap���ڼ�¼��ȡ����Щcluster
	BDRVqrowState *bqrows = bs->opaque;
	int64_t nb_clusters;
	int ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_read_missing_clusters()\n");
	printf("first_cluster %" PRId64 ", last_cluster %" PRId64 "\n", first_cluster, last_cluster);
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(bqrows);
#endif
#endif

	if(first_cluster >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid first_cluster!\n");
		ret  = -1;
		goto end;
	}
	if(last_cluster >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid last_cluster!\n");
		ret = -1;
		goto end;
	}

	if(is_read) { // ����Ƕ�����Ҫ��֤ÿһ��cluster���ڵ�ǰ������̾�����
		nb_clusters = last_cluster - first_cluster + 1;
		ret = qrow_read_missing_clusters2(bs, bqrows, first_cluster, nb_clusters, buf, buf_bitmap, 0);
		if(ret < 0)
			goto end;

	} else { // �����д���м��cluster�ᱻ��ȫ���ǣ����ֻ�豣֤��һ�������һ��cluster�ڵ�ǰ�����м��ɣ�
		ret = qrow_read_missing_clusters2(bs, bqrows, first_cluster, 1, buf, buf_bitmap, 0);
		if(ret < 0)
			goto end;
		if(first_cluster != last_cluster) {
			ret = qrow_read_missing_clusters2(bs, bqrows, last_cluster, 1, buf, buf_bitmap, 1);
		}
	}


end:
#ifdef QROW_DEBUG
	printf("qrow_read_missing_clusters() return %d\n" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

/*static int qrow_read_clusters(BDRVqrowState *bqrows, int64_t cluster_index, uint8_t *buf, int nb_clusters) {
	// ��cluster_index��ʼ��ȡnb_clusters��buf��
	// �ú������ж϶�ȡ��cluster�Ƿ��ڴ򿪵ľ����У����øú����ĵط�Ӧ����֤��һ��
	// ����Ƕ�ȡ���ٴ򿪾����е�cluster��Ӧ��ʹ�������qrow_read_missing_clusters()
	int ret = 0;
	BlockDriver *drv;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_read_clusters()\n");
	printf("cluster_index %" PRId64 ", nb_clusters %d\n", cluster_index, nb_clusters);
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(bqrows);
#endif
#endif
	if(cluster_index >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index!\n");
		ret  = -1;
		goto end;
	}
	if((cluster_index + nb_clusters -1) >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid nb_clusters!\n");
		ret = -1;
		goto end;
	}

	drv = bqrows->qrow_irvd->drv;
	ret = drv->bdrv_read(bqrows->qrow_irvd, bqrows->sectors_per_cluster * cluster_index, buf, bqrows->sectors_per_cluster * nb_clusters);

end:
#ifdef QROW_DEBUG
	printf("qrow_write_clusters() return %d\n" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}*/

static int qrow_write_clusters(BDRVqrowState *bqrows, int64_t cluster_index, const uint8_t *buf, int nb_clusters) {
	// ��buf��nb_cluster����cluster����д���cluster_index��ʼ��
	// �����ж�cluster�Ƿ��Ѿ��ڵ�ǰ���̾����У�д��ʱ�Ὣ����cluster��ȫ����
	int ret = 0;
	BlockDriver *drv;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_write_clusters()\n");
	printf("cluster_index %" PRId64 ", nb_clusters %d\n", cluster_index, nb_clusters);
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(bqrows);
#endif
#endif
	if(cluster_index >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index!\n");
		ret  = -1;
		goto end;
	}
	if((cluster_index + nb_clusters -1) >= bqrows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index or nb_clusters!\n");
		ret = -1;
		goto end;
	}
	drv = bqrows->qrow_irvd->drv;
	ret = drv->bdrv_write(bqrows->qrow_irvd, bqrows->sectors_per_cluster * cluster_index, buf, bqrows->sectors_per_cluster * nb_clusters);

end:
#ifdef QROW_DEBUG
	printf("qrow_write_clusters() return %d\n" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int64_t first_sector_in_cluster(BDRVqrowState *bqrows, int64_t cluster_index) {
	return cluster_index * bqrows->sectors_per_cluster;
}

static int64_t last_sector_in_cluster(BDRVqrowState *bqrows, int64_t cluster_index) {
	return (cluster_index + 1) * bqrows->sectors_per_cluster - 1;
}

static int qrow_assert_clusters(BlockDriverState *bs, ClusterBuffer *cbuf, int64_t sector_num, int nb_sectors, int op_type) {
	BDRVqrowState *bqrows = bs->opaque;
	int64_t nb_clusters, i, first_cluster, last_cluster, continuous_cluster, cluster_offset;
	uint8_t *buffer_offset;// *zero_buf = NULL;
	int ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_assert_clusters()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d, op_type %d\n", sector_num, nb_sectors, op_type);
#endif
#ifdef QROW_DEBUG_ASSERT_CLUSTERS
	printf("press Enter to continue...");
	getchar();
#endif

	first_cluster = sector_num / bqrows->sectors_per_cluster;
	last_cluster = (sector_num + nb_sectors - 1) / bqrows->sectors_per_cluster;
	nb_clusters = last_cluster - first_cluster + 1;
	//zero_buf = qemu_mallocz(bqrows->cluster_size);

#ifdef QROW_DEBUG
	printf("first_cluster %" PRId64 ", last_cluster %" PRId64 "\n", first_cluster, last_cluster);
#endif

	switch(op_type) {
	case qrow_READ:
	case qrow_AIO_READ:
		if(qrow_read_missing_clusters(bs, first_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 1) < 0) {
			ret = -1;
			goto end;
		}

		if(bqrows->copy_on_demand) {
			// д�����������ɸ�cluster
	#ifdef QROW_DEBUG_DETAIL
			printf("%" PRId64 ": ", nb_clusters);
			for(i = 0; i <  nb_clusters + 1; i++) {
				printf("%d ", cbuf->read_from_father[i]);
			}
			printf("\n");
	#endif
			continuous_cluster = 0;
			for(i = 0; i < nb_clusters + 1; i++) {
	#ifdef QROW_DEBUG_DETAIL
				printf("i %" PRId64 ", continuous_cluster %" PRId64 "\n", i, continuous_cluster);
	#endif
				if(cbuf->read_from_father[i] == 0) {
#ifdef QROW_DEBUG
					printf("read_from_father[%ld] is 0\n", i);
#endif
					if(continuous_cluster == 0)
						continue;
					cluster_offset = first_cluster + i - continuous_cluster;
					buffer_offset = cbuf->buf + (i - continuous_cluster) * bqrows->cluster_size;
	#ifdef QROW_DEBUG_DETAIL
					printf("copying data\n");
					printf("cluster_offset %" PRId64 ", buf %p, buffer_offset %p\n", cluster_offset, cbuf->buf, buffer_offset);
	#endif
	#ifdef QROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
					if(qrow_write_clusters(bqrows, cluster_offset, buffer_offset, continuous_cluster) < 0) {
						ret = -1;
						goto end;
					}
					continuous_cluster = 0;
	#ifdef QROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
				} else {
#ifdef QROW_DEBUG
					printf("read_from_father[%ld] is 1\n", i);
#endif
	#ifdef QROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
					/*if(memcmp(zero_buf, cbuf->buf + i * bqrows->cluster_size, bqrows->cluster_size) == 0) {
#ifdef QROW_DEBUG
					printf("cluster data is all zeros\n");
#endif
						if(continuous_cluster != 0) {
							cluster_offset = first_cluster + i - continuous_cluster;
							buffer_offset = cbuf->buf + (i - continuous_cluster) * bqrows->cluster_size;
			#ifdef QROW_DEBUG_DETAIL
							printf("copying data\n");
							printf("cluster_offset %" PRId64 ", buf %p, buffer_offset %p\n", cluster_offset, cbuf->buf, buffer_offset);
			#endif
			#ifdef QROW_DEBUG_ASSERT_CLUSTERS
							printf("press Enter to continue...");
							getchar();
			#endif
							if(qrow_write_clusters(bqrows, cluster_offset, buffer_offset, continuous_cluster) < 0) {
								ret = -1;
								goto end;
							}
							continuous_cluster = 0;
			#ifdef QROW_DEBUG_ASSERT_CLUSTERS
							printf("press Enter to continue...");
							getchar();
			#endif
						}
					} else {
						continuous_cluster += 1;
					}*/
					continuous_cluster += 1;
					qrow_set_bit(bqrows, first_cluster + i);
	#ifdef QROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
				}
			}
		}
		break;
	case qrow_WRITE:
	case qrow_AIO_WRITE:
		if(sector_num == first_sector_in_cluster(bqrows, first_cluster)) { // д�������뵽cluster���
			if((sector_num + nb_sectors - 1) == last_sector_in_cluster(bqrows, last_cluster)) { // д���յ���뵽cluster�յ�
#ifdef QROW_DEBUG
				printf("write whole clusters, do nothing.\n");
#endif
				break; // д�������cluster���ʲôҲ����Ҫ��
			} else { // д���յ�δ���뵽cluster�յ�
#ifdef QROW_DEBUG
				printf("assert last cluster.\n");
#endif
				// ��ʱ��ֻ������last_cluster����һ��������cluster������first_cluster�Ƿ���last_cluster��ͬ��
				if(qrow_read_missing_clusters(bs, last_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef QROW_DEBUG
					printf("last cluster is read from father\n");
#endif
#ifdef QROW_DEBUG_WRITE
					dump_mem(cbuf->buf, bqrows->cluster_size, "last cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(qrow_write_clusters(bqrows, last_cluster , cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					qrow_set_bit(bqrows, last_cluster);
				}
				break;
			}
		} else { // д�����δ���뵽cluster���
			if((sector_num + nb_sectors - 1) == last_sector_in_cluster(bqrows, last_cluster)) { // д���յ���뵽cluster�յ�
#ifdef QROW_DEBUG
				printf("assert first cluster.\n");
#endif
				// ��ʱ��ֻ������first_cluster����һ��������cluster������first_cluster�Ƿ���last_cluster��ͬ��
				if(qrow_read_missing_clusters(bs, first_cluster, first_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef QROW_DEBUG
					printf("first cluster is read from father\n");
#endif
#ifdef QROW_DEBUG_WRITE
					dump_mem(cbuf->buf, bqrows->cluster_size, "first cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(qrow_write_clusters(bqrows, first_cluster , cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					qrow_set_bit(bqrows, first_cluster);
				}
				break;
			} else { // д���յ�δ���뵽cluster�յ�
#ifdef QROW_DEBUG
				printf("assert first & last cluster.\n");
#endif
				// ��ʱ,first_cluster��last_cluster���п����ǲ�������cluster
				if(qrow_read_missing_clusters(bs, first_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef QROW_DEBUG
					printf("first cluster is read from father\n");
#endif
#ifdef QROW_DEBUG_WRITE
					dump_mem(cbuf->buf, bqrows->cluster_size, "first cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(qrow_write_clusters(bqrows, first_cluster, cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					qrow_set_bit(bqrows, first_cluster);
				}
				if(cbuf->read_from_father[1] == 1) {
#ifdef QROW_DEBUG
					printf("last cluster is read from father\n");
#endif
#ifdef QROW_DEBUG_WRITE
					dump_mem(cbuf->buf + bqrows->cluster_size, bqrows->cluster_size, "last cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(qrow_write_clusters(bqrows, last_cluster, cbuf->buf + bqrows->cluster_size, 1) < 0) {
						ret = -1;
						goto end;
					}
					qrow_set_bit(bqrows, last_cluster);
				}
				break;
			}
		}
	}

end:
	/*if(zero_buf != NULL) {
		printf("stub 1\n");
		qemu_free(zero_buf);
		printf("stub 2\n");
		zero_buf = NULL;
	}*/
#ifdef QROW_DEBUG
	printf("qrow_assert_clusters() return %d\n" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_read(BlockDriverState *bs, int64_t sector_num, uint8_t *buf, int nb_sectors) {

	BDRVQrowState *s = bs->opaque;
	uint64_t sector_offset;
	
	for (int64_t i = sector_num, j = 0; i < (nb_sectors+sector_num); i++) 
	{
		sector_offset = s->map[i];//��map�����л�ȡ��������������ϵĴ洢������
		//s->map[i]Ϊ0ʱ��Ҫô�Ǳ�ʾ���̾����metaԪ����ռ�ݵĵ�һ��sector��Ҫô��ʾ����������������Ϊ��
		if(sector_offset < (s->meta_cluster*s->sectors_per_cluster)) //�ô�������Ϊ��(0)����Ϊheader����
		{
			continue; 
		} 
		else
		{
		 	if(bdrv_pread(s->qrow_img_file, sector_offset*BDRV_SECTOR_SIZE, buf+j*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
				fprintf (stderr, "Failed to read the  data from %s\n", s->img_file);
				ret = -1;
				goto end;
			}
			j++;				
		}				
	}	

end:
	
#ifdef QROW_DEBUG
	printf("qrow_read return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_write(BlockDriverState *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
	BDRVQrowState *s = bs->opaque;
	int64_t nb_clusters, sector_offset;
	int ret = 0;
	
	if (s->cluster_offset >= s->total_clusters){ //��������
		fprintf (stderr, "img is full!\n");
		ret = -1;
		goto end;
	}
	nb_clusters = (nb_sectors % s->sectors_per_cluster == 0) ? (nb_sectors / s->sectors_per_cluster) : (nb_sectors / s->sectors_per_cluster + 1);
	if (s->cluster_offset + nb_clusters > s->total_clusters){ //д�����򳬳��������Χ
		fprintf (stderr, "Invalid nb_sectors!\n");
		ret = -1;
		goto end;
	}
	if(bdrv_pwrite(s->qrow_map_file,s->byte_offset, buf, nb_sectors*BDRV_SECTOR_SIZE) != nb_sectors*BDRV_SECTOR_SIZE) {
		fprintf(stderr, "Failed to write \n");
		ret = -1;
		goto end;
	}
	sector_offset = s->sector_offset;
	for (int64_t i = sector_num, j = 1; j <= nb_sectors; i++, j++) //����map�����ֵ��������������̺�������̵�����ӳ���ϵ 
	{
			s->map[i] = sector_offset;
			sector_offset++;
	}
	s->map_is_dirty = 1;
	// ����map_file�ļ������map�����ֵ
	if(qrow_update_map_file(s) < 0) {
		fprintf (stderr, "Failed to update map_file. (%s)\n", s->map_file);
		ret = -1;
		goto end;
	}
	
	s->cluster_offset += nb_clusters;
	s->byte_offset = s->cluster_offset * s->cluster_size;
	s->sector_offset = s->cluster_offset * s->sectors_per_cluster;
	// ����img_file�ļ������meta����offset��ֵ
	if(qrow_update_img_file(s) < 0) {
		fprintf (stderr, "Failed to update img_file. (%s)\n", s->img_file);
		ret = -1;
		goto end;
	}

end:
	
#ifdef QROW_DEBUG
		printf("qrow_write return %d" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int qrow_generate_filename(char *dest, const char *prefix, const char *suffix) {
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

static int qrow_create_meta(qrowCreateState *cs) {
	qrowMeta meta;
	qrowSnapshotHeader snap_header;
	uint32_t cluster_size, copy_on_demand;
	uint64_t disk_size;
	qemu_timeval tv;
	int fd, cluster_bits, ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create_meta\n");
#endif

	if(cs->disk_size == 0) {
		fprintf(stderr, "Invalid disk_size\n");
		ret = -1;
		goto end;
	}
	disk_size = cs->disk_size;

	if(cs->cluster_size == 0) {
		fprintf(stderr, "Invalid cluster_size\n");
		ret = -1;
		goto end;
	}
	cluster_size = cs->cluster_size;

   cluster_bits = get_bits_from_size(cluster_size); // cluster��С��λ������ 1 << cluster_bits == cluster_size
   cs->cluster_bits = cluster_bits;
   if ((cluster_bits < MIN_CLUSTER_BITS) || (cluster_bits > MAX_CLUSTER_BITS)) {
	   // cluster��С512B(���ٰ���һ��sector)�����2MB,�ұ�����2����
    	fprintf(stderr, "Cluster size must be a power of two between %d and %dk\n",
            1 << MIN_CLUSTER_BITS,
            1 << (MAX_CLUSTER_BITS - 10));
    	ret =  -1;
    	goto end;

    }
   copy_on_demand = cs->copy_on_demand;
#ifdef QROW_DEBUG
   printf("disk_size %" PRId64 ", cluster_size %d, cluster_bits %d\n", disk_size, cluster_size, cluster_bits);
   printf("meta_file %s\n", cs->meta_file);
   printf("backing_file %s\n", cs->backing_file);
#endif
   if(cs->meta_file[0] == '\0') {
	   fprintf(stderr, "Void meta file name\n");
	   ret = -1;
	   goto end;
   }
   fd = open(cs->meta_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		fprintf(stderr, "Can not open %s\n", cs->meta_file);
		ret = -1;
		goto end;
	}
	memset(&meta, 0, sizeof(meta));
	meta.magic = cpu_to_be32(qrow_MAGIC);
   	meta.version = cpu_to_be32(qrow_VERSION);
   	meta.copy_on_demand = cpu_to_be32(copy_on_demand);
   	meta.cluster_size = cpu_to_be32(cluster_size); // cluster�ֽ���
   	meta.cluster_bits = cpu_to_be32(cluster_bits); // clusterλ��
   	meta.total_clusters = cpu_to_be64((disk_size + cluster_size -1) >> cluster_bits); // ���̾����ܵ�cluster����
   	meta.sectors_per_cluster = cpu_to_be32(cluster_size >> BDRV_SECTOR_BITS);
   	meta.disk_size = cpu_to_be64(disk_size); // ��������ֽ���
   	meta.nb_snapshots = cpu_to_be32(1); // ������,��ǰ״̬Ҳռ��һ��������Ϣ�����Դ���ʱ������Ϊ1

   	if(qrow_generate_filename(meta.current_btmp, cs->meta_file, cs->time_value, "btmp") < 0) { // ��ǰbitmap�ļ�
   		ret = -1;
   		goto end;
   	}

   	if(qrow_generate_filename(cs->irvd_file, cs->meta_file, cs->time_value, "irvd") < 0) { // ��ǰirvd�ļ�
   	   	ret = -1;
   	   	goto end;
   	}

   	// ����base image
   	if(cs->backing_file != NULL) {
   		strncpy(meta.backing_file, cs->backing_file, MAX_FILE_NAME_LENGTH);
   	}

   	strncpy(cs->btmp_file, meta.current_btmp, MAX_FILE_NAME_LENGTH);

   	memset(&snap_header, 0, sizeof(snap_header));

   snap_header.snap_magic = cpu_to_be32(qrow_SNAPHEADER_MAGIC);
   sprintf(snap_header.id_str, "0");
   sprintf(snap_header.name, "current state");
   	strncpy(snap_header.btmp_file, cs->btmp_file, MAX_FILE_NAME_LENGTH);
   	strncpy(snap_header.irvd_file, cs->irvd_file, MAX_FILE_NAME_LENGTH);
   	qemu_gettimeofday(&tv); // ��ȡ��ǰʱ��
   	snap_header.date_sec = tv.tv_sec;
   	snap_header.date_nsec = tv.tv_usec * 1000;
   	snap_header.nb_children = 0; // û�к��ӿ���
   	snap_header.is_deleted = 0; // û�б�ɾ��

    // д��meta�ļ�
   	write(fd, &meta, sizeof(meta)); // д��metaͷ
   	write(fd, &snap_header, sizeof(snap_header)); // д�뵱ǰ״̬��snapshot header

   	if(close(fd) != 0) {
   		ret = -1;
   	}


end:
#ifdef QROW_DEBUG
	printf("qrow_create_meta() return %d\n", ret);
#endif
	return ret;
}



static int qrow_create(const char *filename, QEMUOptionParameter *options) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_create()\n");
#endif
	QRowMeta meta;
	uint64_t disk_size;
	uint32_t cluster_size = 4096;
	char *backing_file = NULL;
	char *map_file = NULL;
	uint64_t meta_size;
	uint64_t cluster_offset;
	
	// ��������
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
				disk_size= options->value.n;
			} else if (!strcmp(options->name, BLOCK_OPT_CLUSTER_SIZE)) {
				cluster_size = options->value.n;	
			} else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
	            backing_file = options->value.s;
			} 
	        options++;
	}
	
	//�жϲ���
	if (disk_size == 0) 
	{
		fprintf(stderr, "Invalid disk_size\n");
		ret = -1;
		goto end;
	}
	if(cluster_size == 0) {
		fprintf(stderr, "Invalid cluster_size\n");
		ret = -1;
		goto end;
	}
	if(filename[0] == '\0') {
	   fprintf(stderr, "Void img file name\n");
	   ret = -1;
	   goto end;
   	} 
	
	uint32_t cluster_bits = get_bits_from_size(cluster_size); // ��ȡcluster_bits
	if ((cluster_bits < MIN_CLUSTER_BITS) || (cluster_bits > MAX_CLUSTER_BITS)) {
    	fprintf(stderr, "cluster size must be a power of two between %d and %dB\n",
            1 << MIN_CLUSTER_BITS,
            1 << MAX_CLUSTER_BITS);
        ret =  -1;
    	goto end;
    	
    } 
	  
	// �����Ԫ����ͷ��Ҫ��������Ϣ
    memset(&meta, 0, sizeof(meta));
    meta.magic = cpu_to_be32(QROW_MAGIC);	
	meta.version = cpu_to_be32(QROW_VERSION);
	meta.disk_size = cpu_to_be64(disk_size);
	meta.cluster_size = cpu_to_be32(cluster_size);
    meta.cluster_bits = cpu_to_be32(cluster_bits);
   	meta.total_clusters = cpu_to_be64((disk_size + cluster_size -1) >> cluster_bits); // ���̾����ܵ�cluster����
   	meta.sectors_per_cluster = cpu_to_be32(cluster_size >> BDRV_SECTOR_BITS);
	meta_size = sizeof(meta);
	if( meta_size > 0 )
	{
		cluster_offset = if(meta_size % cluster_size == 0) ? (meta_size / cluster_size) : (meta_size / cluster_size + 1);
	}
	meta.cluster_offset = cpu_to_be64(cluster_offset);//Ԫ���ݴ���ھ�����ʼλ�� 
    strncpy(meta.img_file, filename, MAX_FILE_NAME_LENGTH);
    strncpy(meta.backing_file, backing_file, MAX_FILE_NAME_LENGTH);//���������ô�ã����� 
	if(qrow_generate_filename(meta.map_file, meta.img_file, "map") < 0) { // map_file�ļ�
   		ret = -1;
   		goto end;
   	}
   	
	//��Ԫ����д�뵽�����ļ��� 
	int fd;	
	fd = open(meta.img_file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,0644);
	
	if (fd < 0) 
	{
		fprintf(stderr, "Can not open %s\n", meta.img_file);
		ret = -1;
		goto end;
	}
	//��������if���ʵ����Ϊϡ���ļ�meta.img_fileԤ����disk_size��С�Ŀռ�
	if(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, disk_size) < 0) {
		fprintf(stderr, "Can not preallocate disk space for %s\n", meta.img_file);
		ret = -1;
		goto end;
	}
	if (ftruncate(fd, disk_size) != 0) {
		fprintf(stderr, "Can not truncate %s to %" PRId64 " bytes\n", meta.img_file, disk_size);
		ret = -1;
		goto end;
	}
	
	uint64_t writeByets = write(fd, &meta, sizeof(meta)); 
	if(writeByets != sizeof(meta))
	{
		fprintf(stderr, "Can not write meta \n");
		ret = -1;
		goto end;
	}
	
	if(close(fd) != 0) {
		fprintf(stderr, "Can not close %s\n", img_file);
   		ret = -1;
		goto end;
   	}
	
	//��������ʼ��map_file�ļ�
	int map_file_fd;
	uint64_t map[MAX_VM_SECTOR_NUM];
	memset(map, 0, sizeof(map));
	map_file_fd = open(meta.map_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
   	if(fd < 0) {
		fprintf(stderr, "Can not open %s\n", meta.map_file);
		ret = -1;
		goto end;
	}
	write(map_file_fd, map,sizeof(map));

	if(close(map_file_fd) != 0) {
		fprintf(stderr, "Can not close %s\n", meta.map_file);
		ret = -1;
		goto end;
	}
	
end:
#ifdef QROW_DEBUG
	printf("qrow_create() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static void qrow_flush(BlockDriverState *bs) {
	BDRVQrowState *s = bs->opaque;

	bdrv_flush(s->qrow_img_file);
	bdrv_flush(s->qrow_map_file);
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


static qrowAIOCB *qrow_aio_setup(BlockDriverState *bs,
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
	uint64_t sector_offset;
	buf = qemu_malloc(acb->qiov->size);
	qemu_iovec_to_buffer(acb->qiov, buf);
	for (int64_t i = acb->sector_num, j = 0; i < (acb->nb_sectors + acb->sector_num); i++) 
	{
		sector_offset = bqrows->map[i];//��map�����л�ȡ��������������ϵĴ洢������
		//bqrows->map[i]Ϊ0ʱ��Ҫô�Ǳ�ʾ���̾����metaԪ����ռ�ݵĵ�һ��sector��Ҫô��ʾ����������������Ϊ��
		if(sector_offset < (bqrows->meta_cluster*bqrows->sectors_per_cluster)) //�ô�������Ϊ��(0)����Ϊheader����
		{
			continue; 
		} 
		else
		{
		 	if(bdrv_pread(bqrows->qrow_img_file, sector_offset*BDRV_SECTOR_SIZE, buf+j*BDRV_SECTOR_SIZE, BDRV_SECTOR_SIZE) != BDRV_SECTOR_SIZE) {
				fprintf (stderr, "Failed to read the  data from %s\n", bqrows->img_file);
				ret = -1;
				goto end;
			}
			j++;				
		}				
	}		
	qemu_iovec_from_buffer(acb->qiov, buf, acb->qiov->size);		
	end:
		if(buf != NULL) {
			qemu_free(buf);
			buf = NULL;
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

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_readv()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d\n", sector_num, nb_sectors);
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
	// ����cluster�Ƿ�����ڵ�ǰ�����У����Ƚ����ȡ�������ٽ����ھ����е�����������
	drv = bqrows->qrow_img_file->drv;
	acb->irvd_aiocb = drv->bdrv_aio_readv(bqrows->qrow_img_file, sector_num, qiov, nb_sectors, qrow_aio_readv_cb, acb);
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
	BDRVqrowState *s = bs->opaque;
	int64_t first_cluster, last_cluster, current_cluster;
	ClusterBuffer cbuf;
	BlockDriver *drv;
	BlockDriverAIOCB *ret = NULL;

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

   first_cluster = sector_num / s->sectors_per_cluster; // ��ʼcluster����
   last_cluster = (sector_num + nb_sectors - 1) / s->sectors_per_cluster; // ����cluster����

	if(first_cluster >= s->total_clusters) { // ��ʼ��cluster�����������Χ
		fprintf (stderr, "Invalid sector_num!\n");
		goto end;
	}
	if(last_cluster >= s->total_clusters) { // ����cluster�����������Χ
		fprintf (stderr, "Invalid nb_sectors!\n");
		goto end;
	}
	cbuf.buf = NULL;
	cbuf.read_from_father = NULL;
	if(s->complete_image != 1) {
		// ��������
		cbuf.buf = qemu_memalign(512, 2  * s->cluster_size); // ���ڴ洢��father��ȡ������
		cbuf.read_from_father = qemu_mallocz(2); //���ڱ�ʾbuf���ĸ�cluster�Ǵ�father�ж�ȡ��
		// ȷ��ͷβcluster���ڵ�ǰ������̾�����
		if(qrow_assert_clusters(bs, &cbuf, sector_num, nb_sectors, qrow_AIO_WRITE) < 0) {
			fprintf (stderr, "qrow_assert_clusters() failed.\n");
			goto end;
		}
	}

	// ����bitmap����
	for(current_cluster = first_cluster; current_cluster <= last_cluster; current_cluster++) {
		//if(qrow_get_bit(s, current_cluster) == 0)
			qrow_set_bit(s, current_cluster);
	}

	// ͷβcluster���ڵ�ǰ������̾����У���˿���ֱ�Ӱ�sectorд��
	drv = s->qrow_irvd->drv;
   ret = drv->bdrv_aio_writev(s->qrow_irvd, sector_num, qiov, nb_sectors, cb, opaque );
   if(ret == NULL) {
	   goto end;
   }

	// ����btmp�ļ�
	if(qrow_update_btmp(s) < 0) {
		fprintf (stderr, "Failed to update btmp file. (%s)\n", s->opened_btmp_file);
		ret = NULL;
		goto end;
	}

end:
	if(cbuf.buf != NULL) {
		qemu_free(cbuf.buf);
		cbuf.buf = NULL;
	}
	if(cbuf.read_from_father != NULL) {
		qemu_free(cbuf.read_from_father);
		cbuf.read_from_father = NULL;
	}
#ifdef QROW_DEBUG
   printf("qrow_aio_writev() return %p" QROW_DEBUG_END_STR, ret);
#endif
   return ret;
}

static BlockDriverAIOCB *qrow_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVqrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_aio_flush()\n");
#endif

	ret = bdrv_aio_flush(s->qrow_irvd, cb, opaque);

#ifdef QROW_DEBUG
	printf("qrow_aio_flush() return %p\n" QROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static void qrow_new_snapshot_id(BDRVqrowState *bqrows, char *id_str, int id_str_size) {
	qrowSnapshot *snap_ptr;
   uint i, id, found;

   /*for(i = 0; i < bqrows->nb_snapshots; i++) { // �ҵ����п�������id�����ֵ
	   snap_ptr = bqrows->snapshots + i;
	   if(snap_ptr->id_str != NULL) {
		   id = strtoul(snap_ptr->id_str, NULL, 10); // ��id��ת��Ϊ��Ӧ������
		   if (id > max)
			   max = id;
	   }
    }
   snprintf(id_str, id_str_size, "%d", max + 1); // ��idΪ��ǰid���ֵ��1*/
   for(id = 1; id < 0xffffffff; id++) {
	   found = 1;
	   for(i = 0; i < bqrows->nb_snapshots; i++) {
		   snap_ptr = bqrows->snapshots + i;
		   if(snap_ptr->id_str != NULL) {
			   if(id == strtoul(snap_ptr->id_str, NULL, 10)) {
				   found = 0;
				   break;
			   }
		   }
	   }
	   if(found)
		   break;
   }
  snprintf(id_str, id_str_size, "%d", id);
}

static int qrow_find_snapshot_by_id(BDRVqrowState *bqrows, const char *id_str) {
	// ���ݿ��յ�id�ҵ���Ӧ�Ŀ��գ���������bqrows->snapshots�����е�����
	int i;

	for(i = 0; i < bqrows->nb_snapshots; i++) {
		if(bqrows->snapshots[i].id_str != NULL) {
			if(strcmp(bqrows->snapshots[i].id_str, id_str) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int qrow_find_snapshot_by_name(BDRVqrowState *bqrows, const char *name) {
	// ���ݿ��յ�name�ҵ���Ӧ�Ŀ��գ���������bqrows->snapshots�����е�����
	int i;

	for(i = 0; i < bqrows->nb_snapshots; i++) {
		if(bqrows->snapshots[i].name != NULL) {
			if(strcmp(bqrows->snapshots[i].name, name) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int qrow_find_free_snapshot(BDRVqrowState *bqrows) {
	// �ҵ����еĿ��գ���������bqrows->snapshots�����е�����
	int i;

	for(i = 0; i < bqrows->nb_snapshots; i++) {
		// ��ɾ���Һ��ӿ�����Ϊ0�Ŀ���Ϊ���п���
		if(bqrows->snapshots[i].nb_children == 0 && bqrows->snapshots[i].is_deleted == 1) {
			return i;
		}
	}
	return -1;
}

static int qrow_update_nb_children(BDRVqrowState *bqrows, qrowSnapshot *snap, int value) {
	qrowSnapshot *father_snap;
	int snap_index, ret = 0;
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_update_nb_children()\n");
#endif
#ifdef QROW_DEBUG_DETAIL
	printf("snap: %p, value: %d, btmp: %s\n", snap, value, snap->btmp_file);
#endif
	snap->nb_children += value;
	if(snap->nb_children == 0 && snap->is_deleted == 1) {
		// ����û�к��ӣ����Ѿ���ɾ��
		if(snap->father_btmp_file) {
			snap_index = qrow_find_snapshot_by_btmp(bqrows, snap->father_btmp_file);
			if(snap_index < 0) {
				fprintf(stderr, "Failed to find father snapshot\n");
				ret = -1;
				goto end;
			}
			father_snap = bqrows->snapshots + snap_index;
	#ifdef QROW_DEBUG
			printf("recursive calling qrow_update_nb_children...\n");
	#endif
			qrow_update_nb_children(bqrows, father_snap, value);
		}
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_update_nb_children() return 0" QROW_DEBUG_END_STR);
#endif
	return ret;
}

static int qrow_snapshot_add(BDRVqrowState *bqrows, qrowCreateState *cs, QEMUSnapshotInfo *sn_info) {
	// ��bqrows->snapshotsβ������һ���µ��ڴ��е�snapshot��Ϣ��qrowSnapshot��

	qrowSnapshot *new_snap, *snap;
	qemu_timeval tv;
	int snap_index;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_snapshot_add()\n");
#endif
	bqrows->snapshots = qemu_realloc(bqrows->snapshots, (bqrows->nb_snapshots + 1) * sizeof(qrowSnapshot));

	snap_index = qrow_find_snapshot_by_btmp(bqrows, bqrows->current_btmp_file);
	if(snap_index < 0) {
		return -1;
	}
	snap = bqrows->snapshots + snap_index; // �ϵ�ǰ״̬�Ŀ�����Ϣ

	new_snap = bqrows->snapshots + bqrows->nb_snapshots; // �µĿ�����Ϣ
	memset(new_snap, 0, sizeof(qrowSnapshot));

	// ��Ϊ�ǽ��ϵĵ�ǰ״̬��Ϊ���գ�����sn_info�е���ϢӦ���浽�ϵĵ�ǰ״̬�Ŀ�����Ϣ��
	snap->date_sec = sn_info->date_sec;
	snap->date_nsec = sn_info->date_nsec;
	snap->vm_clock_nsec = sn_info->vm_clock_nsec;
	snap->vm_state_size = sn_info->vm_state_size;
	qrow_update_nb_children(bqrows, snap, 1);

	if(snap->id_str == NULL) {
		snap->id_str = qemu_mallocz(128);
	} else {
		memset(snap->id_str, 0, 128);
	}
	strncpy(snap->id_str, sn_info->id_str, 128);

	if(snap->name == NULL) {
		snap->name = qemu_mallocz(256);
	} else {
		memset(snap->name, 0, 256);
	}
	strncpy(snap->name, sn_info->name, 256);

	// �µĵ�ǰ״̬
	new_snap->id_str = qemu_mallocz(128);
	sprintf(new_snap->id_str, "0");
	new_snap->name = qemu_mallocz(256);
	sprintf(new_snap->name, "current state");
	new_snap->btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strncpy(new_snap->btmp_file, cs->btmp_file, MAX_FILE_NAME_LENGTH);
	new_snap->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strncpy(new_snap->irvd_file, cs->irvd_file, MAX_FILE_NAME_LENGTH);
	if(cs->father_btmp_file != NULL) {
		new_snap->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(new_snap->father_btmp_file, cs->father_btmp_file, MAX_FILE_NAME_LENGTH);
	}
	qemu_gettimeofday(&tv); // ��ȡ��ǰʱ��
	new_snap->date_sec = tv.tv_sec;
	new_snap->date_nsec = tv.tv_usec * 1000;

	bqrows->nb_snapshots += 1;
	bqrows_cache = qemu_realloc(bqrows_cache, sizeof(BDRVqrowState *) * bqrows->nb_snapshots);
	memset(bqrows_cache, 0, sizeof(BDRVqrowState *) * bqrows->nb_snapshots);
	bqrows->snapshots_is_dirty = 1;

#ifdef QROW_DEBUG
	printf("qrow_snapshot_add() return 0\n" QROW_DEBUG_END_STR);
#endif
	return 0;
}

static void qrow_snapshot_copy(qrowSnapshot *dst, qrowSnapshot *src) {

	if(src->id_str) {
		dst->id_str = qemu_mallocz(128);
		strncpy(dst->id_str, src->id_str, 128);
	}
	if(src->name) {
		dst->name = qemu_mallocz(256);
		strncpy(dst->name, src->name, 256);
	}
	if(src->btmp_file) {
		dst->btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(dst->btmp_file, src->btmp_file, MAX_FILE_NAME_LENGTH);
	}
	if(src->irvd_file) {
		dst->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(dst->irvd_file, src->irvd_file, MAX_FILE_NAME_LENGTH);
	}
	if(src->father_btmp_file) {
		dst->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(dst->father_btmp_file, src->father_btmp_file, MAX_FILE_NAME_LENGTH);
	}
	dst->date_sec = src->date_sec;
	dst->date_nsec = src->date_nsec;
	dst->vm_clock_nsec = src->vm_clock_nsec;
	dst->vm_state_size = src->vm_state_size;
	dst->nb_children = src->nb_children;
	dst->is_deleted = src->is_deleted;
}

static int qrow_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info) {
    // Ŀǰ���õķ������ô����ļ���ʱ����Ϊ�ļ�����һ���֣������ļ�����Ψһ��
	// �������ļ�������ֱ��
	BDRVqrowState *s = bs->opaque;
	qrowCreateState *cs = NULL;
	qrowSnapshot *free_snap, *old_snap, *snap;
	int snap_index, offset, ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_snapshot_create()\n");
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(s);
#endif
#endif

	if(sn_info->id_str[0] == '\0') { // ���û��ָ��id�����Զ�����һ��
		qrow_new_snapshot_id(s, sn_info->id_str, sizeof(sn_info->id_str));
	}

	if(qrow_find_snapshot_by_id(s, sn_info->id_str) >= 0) { // �ж�id�Ƿ�Ψһ
		fprintf(stderr, "Duplicated snapshot id\n");
		ret = -1;
		goto end;
	}

	if(qrow_find_snapshot_by_name(s, sn_info->name) >= 0) { // �ж�name�Ƿ�Ψһ����ʵname����ҪΨһ����Ϊ�˱�����������ж�һ��
		fprintf(stderr, "Duplicated snapshot name\n");
		ret = -1;
		goto end;
	}

	cs = qrow_create_state_new();
	cs->cluster_bits = s->cluster_bits;
	cs->cluster_size = s->cluster_size;
	cs->disk_size = s->disk_size;
	strncpy(cs->meta_file, s->meta_file, MAX_FILE_NAME_LENGTH);
	strncpy(cs->father_btmp_file, s->current_btmp_file, MAX_FILE_NAME_LENGTH); // ��father�ļ�Ϊ�ϵĵ�ǰ����

	snap_index = qrow_find_free_snapshot(s);
#ifdef QROW_DEBUG
	printf("free snapshot index: %d\n", snap_index);
#endif
	if(snap_index >= 0) { // �ҵ����п���
		// ʹ�ÿ��п��յ�btmp��irvd�ļ�
		free_snap = s->snapshots + snap_index;
		strcpy(cs->btmp_file, free_snap->btmp_file);
		strcpy(cs->irvd_file, free_snap->irvd_file);
		// �����ڴ��еĿ�������
		old_snap = s->snapshots;
		s->snapshots = qemu_mallocz((s->nb_snapshots - 1) * sizeof(qrowSnapshot));
		offset = 0;
		for(snap_index = 0; snap_index < s->nb_snapshots; snap_index++) {
			snap = old_snap + snap_index;
#ifdef QROW_DEBUG_DETAIL
			printf("old_snap: %p, snap_index: %d, free_snap: %p, snap: %p\n", old_snap, snap_index, free_snap, snap);
			dump_snapshot(snap);
#endif
			if(snap != free_snap) {
				qrow_snapshot_copy(s->snapshots + offset, snap);
				offset += 1;
			}
		}

		qrow_close_snapshots2(old_snap, s->nb_snapshots);
		s->nb_snapshots -= 1;
#ifdef QROW_DEBUG_DETAIL
		printf("snapshots after delete free snapshot:\n");
		dump_snapshots(s);
#endif
	} else { // δ�ҵ����п���
		// �����µĵ�ǰbtmp��irvd�ļ�
		qrow_generate_filename(cs->btmp_file, cs->meta_file, cs->time_value, "btmp"); // ������btmp�ļ���
		qrow_generate_filename(cs->irvd_file, cs->meta_file, cs->time_value, "irvd"); // ������irvd�ļ���

		if(qrow_create_btmp(cs) < 0) {// �����µ�bitmap�ļ�
			fprintf(stderr, "Failed to create new btmp file (%s)\n", cs->btmp_file);
			ret = -1;
			goto end;
		}

		if(qrow_create_vd(cs) < 0) { // �����µ�irvd�ļ�
			fprintf(stderr, "Failed to create new irvd file (%s)\n", cs->irvd_file);
			ret = -1;
			goto end;
		}
	}

	// ���µ�snapshot��Ϣ��ӵ�bqrows->snapshotsβ��
	if(qrow_snapshot_add(s, cs, sn_info) < 0) {
		fprintf(stderr, "Failed to add new snapshot in mem\n");
		ret = -1;
		goto end;
	}

#ifdef QROW_DEBUG_DETAIL
	printf("snapshots after qrow_snapshot_add():\n");
	dump_snapshots(s);
#endif

	// ����meta�ļ�
	if(qrow_update_meta(s, cs->btmp_file, 0) < 0) {
		fprintf(stderr, "Failed to update meta file (%s)\n", s->meta_file);
		ret = -1;
		goto end;
	}

	// ����btmp�ļ�����Ϊ�п���д����vm state��Ϣ��
	s->vm_state_size = sn_info->vm_state_size;
	qrow_update_btmp(s);

	// �ر��ϵ�btmp��irvd
	qrow_close_btmp(s);
	qrow_close_irvd(s);


	// ���µ�btmp��irvd
	strncpy(s->current_btmp_file, cs->btmp_file, MAX_FILE_NAME_LENGTH);
	snap_index = qrow_find_snapshot_by_btmp(s, s->current_btmp_file);
	if(qrow_load_info_from_snapshot(s, snap_index) < 0) {
		ret = -1;
		goto end;
	}
	ret = qrow_open_data(s, s->open_flags);
	// ���ԭ��btmp�ļ�
	memset(s->bitmap, 0, s->bitmap_size);
	s->bitmap_is_dirty = 1;
	if(qrow_update_btmp(s) < 0) {
		fprintf(stderr, "Failed to update btmp file\n");
		ret = -1;
		goto end;
	}

end:
#ifdef QROW_DEBUG
	printf("BDRVqrowState after create snapshot %s\n", sn_info->name);
	printf("qrow_snapshot_create() return %d" QROW_DEBUG_END_STR, ret);
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(s);
#endif
#endif

	if(cs != NULL) {
		qrow_create_state_delete(cs);
		cs = NULL;
	}
	return ret;
}

static int64_t qrow_vm_state_offset(BDRVqrowState *bqrows) {
	// vm״̬������ btmp �ļ������bitmap���棩
	return bqrows->bitmap_size;
}

static int qrow_load_vmstate2(BDRVqrowState *bqrows, uint8_t *buf, int64_t pos, int size) {

	return bdrv_pread(bqrows->qrow_btmp, qrow_vm_state_offset(bqrows) + pos, buf, size);

}

static int qrow_save_vmstate2(BDRVqrowState *bqrows, const uint8_t *buf, int64_t pos, int size) {
	bqrows->vmstate_is_saved = 1;
	return bdrv_pwrite(bqrows->qrow_btmp, qrow_vm_state_offset(bqrows) + pos, buf, size);

}

/*static int qrow_copy_vmstate(BDRVqrowState *bqrows, int snapshot_index) {
	// ��snapshot_indexָ���Ŀ����н�vmstate��Ϣ���Ƶ���ǰ��btmp�ļ���

	BDRVqrowState *target_bqrows = NULL;
	uint8_t *buf = NULL;
	int ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_copy_vmstate()\n");
#endif

	target_bqrows = qrow_open_previous_state(bqrows, snapshot_index);
	if(target_bqrows == NULL) {
		fprintf(stderr, "Failed to open snapshot target snapshot\n");
		ret = -1;
		goto end;
	}

	bqrows->vm_state_size = target_bqrows->vm_state_size;

	if(target_bqrows->vm_state_size == 0) {// û��vm״̬
		goto end;
	}

	buf = qemu_mallocz(bqrows->vm_state_size);

	// ��Ŀ������ж�ȡvm״̬
	if(qrow_load_vmstate2(target_bqrows, buf, 0, bqrows->vm_state_size) < 0) {
		fprintf(stderr, "Failed to read vmstate from %s\n", target_bqrows->opened_btmp_file);
		ret = -1;
		goto end;
	}

	// д�뵱ǰbtmp�ļ���
	if(qrow_save_vmstate2(bqrows, buf, 0, bqrows->vm_state_size) < 0) {
		fprintf(stderr, "Failed to write vmstate to %s\n", bqrows->opened_btmp_file);
		ret = -1;
		goto end;
	}

end:
#ifdef QROW_DEBUG
	printf("qrow_copy_vmstate() return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(target_bqrows != NULL) {
		qrow_close_previous_state(target_bqrows);
		target_bqrows = NULL;
	}
	if(buf != NULL) {
		qemu_free(buf);
		buf = NULL;
	}
	return ret;

}*/

static int qrow_snapshot_goto(BlockDriverState *bs, const char *snapshot_id) {

	BDRVqrowState *s = bs->opaque;
	qrowSnapshot *target_snap, *current_snap, *father_snap;
	int snap_index, ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_snapshot_goto()\n");
#endif

	if(strcmp(snapshot_id, "0") == 0 || strcmp(snapshot_id, "current state") == 0) {
		fprintf(stderr, "No need to goto current state.\n");
		goto end;
	}

	// �ҵ�Ŀ�����
	snap_index = qrow_find_snapshot_by_id(s, snapshot_id);
	if(snap_index < 0) {
		snap_index = qrow_find_snapshot_by_name(s, snapshot_id);
		if(snap_index < 0) {
			fprintf(stderr, "Failed to find snapshot %s\n", snapshot_id);
			ret = -1;
			goto end;
		}
	}
	target_snap = s->snapshots + snap_index;

	if(target_snap->is_deleted) {
		fprintf(stderr, "Can not go to deleted snapshot %s\n", snapshot_id);
		ret = -1;
		goto end;
	}

	// !!!��Ϊ�Ѿ���qrow_load_vmstate()�и�Ϊ��fatherװ��vm״̬��Ϣ�����Բ�����Ҫ����vm״̬����ǰbtmp��
	// ����Ŀ�����vm״̬
	/*if(qrow_copy_vmstate(s, snap_index) < 0) {
		fprintf(stderr, "Failed to copy vmstate from %s\n", target_snap->name);
		ret = -1;
		goto end;
	}*/

	// �ҵ���ǰ״̬��Ӧ�Ŀ���
	snap_index = qrow_find_snapshot_by_btmp(s, s->current_btmp_file);
	if(snap_index < 0) {
		fprintf(stderr, "Failed to find current state.\n");
		ret = -1;
		goto end;
	}
	current_snap = s->snapshots + snap_index;

	// �ҵ���ǰ״̬��father����
	snap_index = qrow_find_snapshot_by_btmp(s, s->father_btmp_file);
	if(snap_index < 0) {
		fprintf(stderr, "Failed to find father snapshot.\n");
		ret = -1;
		goto end;
	}
	father_snap = s->snapshots + snap_index;

	// ����ǰ״̬��father����ΪĿ����ն�Ӧ��btmp
	strncpy(s->father_btmp_file, target_snap->btmp_file, MAX_FILE_NAME_LENGTH);
	strncpy(current_snap->father_btmp_file, target_snap->btmp_file, MAX_FILE_NAME_LENGTH);

	// ����father���պ�Ŀ����պ�����
	qrow_update_nb_children(s, father_snap, -1);
	qrow_update_nb_children(s, target_snap, 1);

	current_snap->date_sec = target_snap->date_sec;
	current_snap->date_nsec = target_snap->date_nsec;
	current_snap->vm_clock_nsec = target_snap->vm_clock_nsec;
	current_snap->vm_state_size = 0;

	// ��յ�ǰ״̬��bitmap
	memset(s->bitmap, 0, s->bitmap_size);
	s->bitmap_is_dirty = 1;
	if(qrow_update_btmp(s) < 0) {
		fprintf(stderr, "Failed to update btmp file\n");
		ret = -1;
		goto end;
	}
	/*// ���irvd�ļ�
	bdrv_truncate(s->qrow_irvd, 0);
	bdrv_truncate(s->qrow_irvd, s->disk_size);*/

	// ����meta�ļ�
	s->snapshots_is_dirty = 1;
	if(qrow_update_meta(s, NULL, 0) < 0) {
		fprintf(stderr, "Failed to update meta file\n");
		ret = -1;
	}


end:
#ifdef QROW_DEBUG
	printf("qrow_snapshot_goto() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_snapshot_delete(BlockDriverState *bs, const char *snapshot_id) {

	BDRVqrowState *s = bs->opaque;
	qrowSnapshot *target_snap, *father_snap;
	int snap_index, ret = 0;


#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_snapshot_delete()\n");
	printf("snapshot_id: %s\n", snapshot_id);
#ifdef QROW_DEBUG_DETAIL
	dump_BDRVqrowState(s);
#endif
#endif

	if(strcmp(snapshot_id, "0") == 0 || strcmp(snapshot_id, "current state") == 0) {
		fprintf(stderr, "Can not delete current state.\n");
		goto end;
	}

	// �ҵ�Ŀ�����
	snap_index = qrow_find_snapshot_by_id(s, snapshot_id);
	if(snap_index < 0) {
		snap_index = qrow_find_snapshot_by_name(s, snapshot_id);
		if(snap_index < 0) {
			fprintf(stderr, "Failed to find snapshot %s\n", snapshot_id);
			ret = -1;
			goto end;
		}
	}
	target_snap = s->snapshots + snap_index;

	if(target_snap->is_deleted) {
		fprintf(stderr, "Can not delete deleted snapshot %s\n", snapshot_id);
		ret = -1;
		goto end;
	}

	// ��Ŀ����ձ��Ϊ��ɾ��
	target_snap->is_deleted = 1;
	strncat(target_snap->name, "_del", 255-strlen(target_snap->name));

	if(target_snap->nb_children == 0) { // ���Ŀ�����û�к���
		if(target_snap->father_btmp_file) {
			snap_index = qrow_find_snapshot_by_btmp(s, target_snap->father_btmp_file);
			if(snap_index < 0) {
				fprintf(stderr, "Failed to find father snapshot\n");
				ret = -1;
				goto end;
			}
			father_snap = s->snapshots + snap_index;
			qrow_update_nb_children(s, father_snap, -1);
		}
	}

#ifdef QROW_DEBUG
	printf("\ntarget snapshot index: %d, target_snap: %p\n", snap_index, target_snap);
#endif

	s->snapshots_is_dirty = 1;
	// ����meta�еĿ�����Ϣ
	qrow_update_meta(s, NULL, 0);
#ifdef QROW_DEBUG_DETAIL
	printf("BDRVqrowState after delete snapshot %s\n", snapshot_id);
	dump_BDRVqrowState(s);
#endif

end:
#ifdef QROW_DEBUG
	printf("qrow_snapshot_delete() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab) {

	BDRVqrowState *s = bs->opaque;
   QEMUSnapshotInfo *snap_tab, *snap_info;
   qrowSnapshot *snap;
   int i, offset, nb_del_snapshots = 0;

   if (s->nb_snapshots == 0) {
	   *psn_tab = NULL;
      return s->nb_snapshots;
   }

   for(i = 0; i < s->nb_snapshots; i++) {
	   snap = s->snapshots + i;
	   if(snap->is_deleted)
		   nb_del_snapshots += 1;
   }
   snap_tab = qemu_mallocz((s->nb_snapshots - nb_del_snapshots) * sizeof(QEMUSnapshotInfo));
   offset = 0;
   for(i = 0; i < s->nb_snapshots; i++) {
	   snap_info = snap_tab + offset;
	   snap = s->snapshots + i;
	   if(snap->is_deleted != 1) {
		   if(snap->id_str != NULL) {
			   pstrcpy(snap_info->id_str, sizeof(snap_info->id_str), snap->id_str);
		   }
		   if(snap->name != NULL) {
			   pstrcpy(snap_info->name, sizeof(snap_info->name), snap->name);
		   }
		   snap_info->vm_state_size = snap->vm_state_size;
		   snap_info->date_sec = snap->date_sec;
		   snap_info->date_nsec = snap->date_nsec;
		   snap_info->vm_clock_nsec = snap->vm_clock_nsec;

		   offset += 1;
	   }
   }
   *psn_tab = snap_tab;
   return s->nb_snapshots - nb_del_snapshots;
}

static int qrow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_info()\n");
#endif
	BDRVqrowState *s = bs->opaque;
	bdi->cluster_size = s->cluster_size;
	bdi->vm_state_offset = qrow_vm_state_offset(s);
#ifdef QROW_DEBUG
	printf("return from qrow_get_info()" QROW_DEBUG_END_STR);
#endif
	return 0;
}

static int qrow_save_vmstate(BlockDriverState *bs, const uint8_t *buf, int64_t pos, int size) {

	BDRVqrowState *bqrows = bs->opaque;
	int ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_save_vmstate()\n");
	printf("vm_state_size %d, pos %" PRId64 ", size %d\n", bqrows->vm_state_size, pos, size);
#endif

	// savevm.c 1670��do_savevm()�У���1735���ȵ���qemu_savevm_state()����vm״̬������1750�е���bdrv_snapshot_create()
	// ����vm״̬ʱ����vm״̬��Ϣ���浽��ǰ��btmp�ļ��У���������ʱ�ϵĵ�ǰ״̬��Ϊ���ձ���
	// ���������qrow_load_vmstate()��������

	ret = qrow_save_vmstate2(bqrows, buf, pos, size);

#ifdef QROW_DEBUG
	printf("qrow_save_vmstate() return %d" QROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int qrow_load_vmstate(BlockDriverState *bs, uint8_t *buf, int64_t pos, int size) {

	BDRVqrowState *target_bqrows = NULL, *bqrows = bs->opaque;
	int target_index, ret = 0;

#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_load_vmstate()\n");
	printf("vm_state_size %d, pos %" PRId64 ", size %d\n", bqrows->vm_state_size, pos, size);
#endif
	// savevm.c 1777��load_vmstate()�У���1797���ȵ���bdrv_snapshot_goto()������״̬�ع�,Ȼ����1875�е���qemu_loadvm_state()����vm״̬
	// bdrv_snapshot_goto()���ջ����qrow_snapshot_goto()��qrow_snapshot_goto()�лὫĿ���������Ϊ��ǰ״̬��father
	// vm״̬�Ǳ�����Ŀ������е�,������Ҫ�ӵ�ǰ���յ�father����vm״̬

	// �ҵ���ǰ״̬��father
	target_index = qrow_find_snapshot_by_btmp(bqrows, bqrows->father_btmp_file);
	if(target_index < 0) {
		ret = -1;
		goto end;
	}

	// �򿪵�ǰ״̬��father
	target_bqrows = qrow_open_previous_state(bqrows, target_index);
	if(target_bqrows == NULL) {
		ret = -1;
		goto end;
	}

	// �ӵ�ǰ״̬��fatherװ��vm״̬
	ret = qrow_load_vmstate2(target_bqrows, buf, pos, size);

end:
#ifdef QROW_DEBUG
	printf("qrow_load_vmstate() return %d" QROW_DEBUG_END_STR, ret);
#endif
	if(target_bqrows != NULL) {
		qrow_close_previous_state(target_bqrows);
		target_bqrows = NULL;
	}
	return ret;
}

static int qrow_check(BlockDriverState *bs) {
	BDRVqrowState *bqrows = bs->opaque;
	char user_input[100];
	printf("current copy_on_demand state is ");
	if(bqrows->copy_on_demand) {
		printf("ON\n");
	} else {
		printf("OFF\n");
	}
	while(1) {
		printf("do you want to change copy_on_demand state? (y/n)");
		scanf("%s", user_input);
		user_input[0] = tolower(user_input[0]);
		if(user_input[0] == 'y') {
			bqrows->copy_on_demand = bqrows->copy_on_demand ? 0 : 1;
			qrow_update_meta(bqrows, NULL, 1);
			break;
		}
		if(user_input[0] == 'n')
			break;
	}
	return 0;
}

static int64_t qrow_get_length(BlockDriverState *bs) {
#ifdef QROW_DEBUG
	printf(QROW_DEBUG_BEGIN_STR "We are in qrow_get_lenght()\n");
#endif
	BDRVqrowState *bqrows = bs->opaque;
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
        .name = BLOCK_OPT_CLUSTER_SIZE,
        .type = OPT_SIZE,
        .help = "qrow cluster size"
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

    .bdrv_snapshot_create   = qrow_snapshot_create,
    .bdrv_snapshot_goto     = qrow_snapshot_goto,
    .bdrv_snapshot_delete   = qrow_snapshot_delete,
    .bdrv_snapshot_list     = qrow_snapshot_list,

    .bdrv_get_info	= qrow_get_info,
    .bdrv_getlength = qrow_get_length,

    .bdrv_save_vmstate    = qrow_save_vmstate,
    .bdrv_load_vmstate    = qrow_load_vmstate,

    .create_options = qrow_create_options,
    .bdrv_check = qrow_check,
};

static void bdrv_qrow_init(void)
{
    bdrv_register(&bdrv_qrow);
}

block_init(bdrv_qrow_init);
