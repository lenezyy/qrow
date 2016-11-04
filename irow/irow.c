/* IROW��Improved ROW����ʽ���豸����
 * liuhq 2012
 * IROW��ʽʹ��ROW���COW�Ķ���д�Ŀ�����ͬʱʹ��COD���ROW���ļ���Ƭ����
 * */

#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "block/irow.h"

#include <linux/falloc.h>

BDRVIrowState **birows_cache = NULL; // ���ڱ���򿪵�father
ClusterCache *cluster_cache = NULL; //���ڻ��������ȡ��1��cluster

//#define IROW_DEBUG

#ifdef IROW_DEBUG
#define IROW_DEBUG_BEGIN_STR "\n----------------------------------------\n"
#define IROW_DEBUG_END_STR "\n========================================\n"

#define IROW_DEBUG_DETAIL

#ifdef IROW_DEBUG_DETAIL

//#define IROW_DEBUG_OPEN
//#define IROW_DEBUG_SET_BIT
#define IROW_DEBUG_ASSERT_CLUSTERS
//#define IROW_DEBUG_SNAPSHOT_DELETE
//#define IROW_DEBUG_READ
#define IROW_DEBUG_WRITE
//#define IROW_DEBUG_AIO_READV
//#define IROW_DEBUG_AIO_WRITEV
#define IROW_DEBUG_READ_MISSING_CLUSTSERS2

static void dump_snapshot(IRowSnapshot *snap) {
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

static void dump_snapshots(BDRVIrowState *s) {
	IRowSnapshot *snap;
	int i;
	printf("snapshots: %p\n", s->snapshots);
	for(i = 0; i < s->nb_snapshots; i++) {
		snap = s->snapshots + i;
		printf("snapshot #%d (%p)\n", i, snap);
		dump_snapshot(snap);
		//printf("\n\n");
	}
}

static void dump_BDRVIrowState(BDRVIrowState *s) {
	printf("irow_meta: %p\n", s->irow_meta);
	printf("irow_btmp: %p\n", s->irow_btmp);
	printf("irow_irvd: %p\n", s->irow_irvd);
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

static void dump_birows_cache(BDRVIrowState *s) {
	int i;
	printf("\nbirows_cache:\n");
	if(birows_cache != NULL) {
		for(i = 0; i < s->nb_snapshots; i++) {
			printf("BDRVIrowState #%d ", i);
			if(birows_cache[i] != NULL) {
				printf("\n");
				dump_BDRVIrowState(birows_cache[i]);
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

static int irow_probe(const uint8_t *buf, int buf_size, const char *filename)
{ // ���ħ�����汾�����
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_probe()\n");
	printf("buf_size: %d, filename: %s\n", buf_size, filename);
#endif

	const IRowMeta *irow_meta = (const void *)buf;

    if (buf_size >= sizeof(IRowMeta) &&
        be32_to_cpu(irow_meta->magic) == IROW_MAGIC &&
        be32_to_cpu(irow_meta->version) == IROW_VERSION){
#ifdef IROW_DEBUG
	printf("return 100" IROW_DEBUG_END_STR);
#endif
        return 100;
    }
    else {
#ifdef IROW_DEBUG
	printf("return 0" IROW_DEBUG_END_STR);
#endif
        return 0;
    }
}

static void irow_close_btmp(BDRVIrowState *s) {
	if(s->bitmap) {
#ifdef IROW_DEBUG
		printf("free bitmap cache\n");
#endif
		qemu_free(s->bitmap);
		s->bitmap = NULL;
	}

	if(s->irow_btmp) {
#ifdef IROW_DEBUG
		printf("delete irow_btmp\n");
#endif
		bdrv_delete(s->irow_btmp);
		s->irow_btmp = NULL;
	}
}

static void irow_close_irvd(BDRVIrowState *s) {
	if(s->irow_irvd) {
#ifdef IROW_DEBUG
		printf("delete irow_irvd\n");
#endif
		bdrv_delete(s->irow_irvd);
		s->irow_irvd = NULL;
	}
}

static void irow_close_snapshots2(IRowSnapshot *snapshots, int nb_snapshots) {
	int i;
	IRowSnapshot *snap_ptr;

	if(snapshots == NULL)
		return;

	for(i = 0; i < nb_snapshots; i++) {
		snap_ptr = snapshots + i;
		if(snap_ptr->btmp_file) {
			qemu_free(snap_ptr->btmp_file);
			snap_ptr->btmp_file = NULL;
		}

		if(snap_ptr->irvd_file) {
			qemu_free(snap_ptr->irvd_file);
			snap_ptr->irvd_file = NULL;
		}

		if(snap_ptr->father_btmp_file) {
			qemu_free(snap_ptr->father_btmp_file);
			snap_ptr->father_btmp_file = NULL;
		}

		if(snap_ptr->id_str) {
			qemu_free(snap_ptr->id_str);
			snap_ptr->id_str = NULL;
		}

		if(snap_ptr->name) {
			qemu_free(snap_ptr->name);
			snap_ptr->name = NULL;
		}
	}
	qemu_free(snapshots);
}

static void irow_close_snapshots(BDRVIrowState *birows) {
	// �ر��ڴ��е�snapshot����
	irow_close_snapshots2(birows->snapshots, birows->nb_snapshots);
	birows->snapshots = NULL;
}

static void irow_close_meta(BDRVIrowState *s) {
	if(s->meta_file) {
#ifdef IROW_DEBUG
		printf("free meta_file (%s)\n", s->meta_file);
#endif
		qemu_free(s->meta_file);
		s->meta_file = NULL;
	}

	if(s->current_btmp_file) {
#ifdef IROW_DEBUG
		printf("free current_btmp_file (%s)\n", s->current_btmp_file);
#endif
		qemu_free(s->current_btmp_file);
		s->current_btmp_file = NULL;
	}

	if(s->father_btmp_file) {
#ifdef IROW_DEBUG
		printf("free father_btmp_file (%s)\n", s->father_btmp_file);
#endif
		qemu_free(s->father_btmp_file);
		s->father_btmp_file = NULL;
	}

	if(s->irvd_file) {
#ifdef IROW_DEBUG
		printf("free irvd_file (%s)\n", s->irvd_file);
#endif
		qemu_free(s->irvd_file);
		s->irvd_file = NULL;
	}

	if(s->opened_btmp_file) {
#ifdef IROW_DEBUG
		printf("free opened_btmp_file (%s)\n", s->opened_btmp_file);
#endif
		qemu_free(s->opened_btmp_file);
		s->opened_btmp_file = NULL;
	}

	if(s->irow_meta) {
#ifdef IROW_DEBUG
		printf("delete irow_meta\n");
#endif
		bdrv_delete(s->irow_meta);
		s->irow_meta = NULL;
	}
	if(s->snapshots) {
#ifdef IROW_DEBUG
		printf("close snapshots\n");
#endif
		irow_close_snapshots(s);
	}
}

static void irow_close_state(BDRVIrowState *s) {

	irow_close_meta(s);
	irow_close_btmp(s);
	irow_close_irvd(s);

}

static int irow_check_bitmap(BDRVIrowState *birows) {
	uint64_t i;
	for(i = 0; i < birows->bitmap_size; i++) {
		if(birows->bitmap[i] != 0xff)
			return 0;
	}
	return 1;
}

static int irow_update_btmp(BDRVIrowState *birows) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_update_btmp()\n");
	printf("bitmap_is_dirty %d, vmstate_is_saved %d\n", birows->bitmap_is_dirty, birows->vmstate_is_saved);
#endif
	if(birows->bitmap_is_dirty) {
		if(bdrv_pwrite(birows->irow_btmp, 0, birows->bitmap, birows->bitmap_size) != birows->bitmap_size) {
			fprintf(stderr, "Failed to write the IROW bitmap data to %s\n", birows->opened_btmp_file);
			ret = -1;
			goto end;
		}
		birows->bitmap_is_dirty = 0;
		ret = bdrv_truncate(birows->irow_btmp, birows->bitmap_size + birows->vm_state_size);
		if(irow_check_bitmap(birows)) {
			birows->complete_image = 1;
		}
	}
	if(birows->vmstate_is_saved) {
		birows->vmstate_is_saved = 0;
		ret = bdrv_truncate(birows->irow_btmp, birows->bitmap_size + birows->vm_state_size);
	}

end:
#ifdef IROW_DEBUG
	printf("irow_update_btmp()return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_update_meta(BDRVIrowState *birows, const char *current_btmp, int change_copy_on_demand_state) {
	// ���´����ϵ�snapshot��Ϣ���Լ���ǰbtmp�ļ�ָ��
	// ע�⣬�������current_btmp��Ҫ����NULL�����������ַ�������Ѵ����ϵ���Ӧλ�����
	int i,  ret = 0;
	uint32_t copy_on_demand;
	IRowMeta meta;
	IRowSnapshotHeader snap_header;
	IRowSnapshot *snap_ptr;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_update_meta()\n");
	printf("snapshots_is_dirty: %d, change_copy_on_demand_state %d\n", birows->snapshots_is_dirty, change_copy_on_demand_state);
#endif
	if(change_copy_on_demand_state == 0 && birows->snapshots_is_dirty == 0 && current_btmp == NULL)
		goto end;

	if(bdrv_pread (birows->irow_meta, 0, &meta, sizeof(meta)) != sizeof(meta)) {
			fprintf (stderr, "Failed to read the meta data from %s\n", birows->meta_file);
			ret = -1;
			goto end;
	}
	if(change_copy_on_demand_state) {
		copy_on_demand = meta.copy_on_demand;
		be32_to_cpus(&copy_on_demand);
		copy_on_demand = copy_on_demand ? 0 : 1;
		meta.copy_on_demand = cpu_to_be32(copy_on_demand);
	}
	if(current_btmp != NULL) {
		memset(meta.current_btmp, 0, MAX_FILE_NAME_LENGTH);
		strncpy(meta.current_btmp, current_btmp, MAX_FILE_NAME_LENGTH);
	}

	if(birows->snapshots_is_dirty) { // ��Ҫ����meta�е�snapshot��Ϣ
		meta.nb_snapshots = cpu_to_be32(birows->nb_snapshots);
		for(i = 0; i < birows->nb_snapshots; i++) {
			memset(&snap_header, 0, sizeof(snap_header));
			snap_ptr = birows->snapshots + i;
			snap_header.snap_magic = cpu_to_be32(IROW_SNAPHEADER_MAGIC);
			snap_header.date_sec = snap_ptr->date_sec;
			snap_header.date_nsec = snap_ptr->date_nsec;
			snap_header.vm_clock_nsec = snap_ptr->vm_clock_nsec;
			snap_header.vm_state_size = snap_ptr->vm_state_size;
			snap_header.nb_children = snap_ptr->nb_children;
			snap_header.is_deleted = snap_ptr->is_deleted;
			if(snap_ptr->id_str != NULL)
				strncpy(snap_header.id_str, snap_ptr->id_str, 128);
			if(snap_ptr->name != NULL)
				strncpy(snap_header.name, snap_ptr->name, 256);
			if(snap_ptr->btmp_file == NULL) {
				fprintf(stderr, "Void btmp filename\n");
				ret = -1;
				goto end;
			}
			strncpy(snap_header.btmp_file, snap_ptr->btmp_file, MAX_FILE_NAME_LENGTH);
			if(snap_ptr->irvd_file == NULL) {
				fprintf(stderr, "Void irvd filename\n");
				ret = -1;
				goto end;
			}
			strncpy(snap_header.irvd_file, snap_ptr->irvd_file, MAX_FILE_NAME_LENGTH);
			if(snap_ptr->father_btmp_file != NULL)
				strncpy(snap_header.father_btmp_file, snap_ptr->father_btmp_file, MAX_FILE_NAME_LENGTH);

			if(bdrv_pwrite(birows->irow_meta, sizeof(meta) + i * sizeof(IRowSnapshotHeader), &snap_header, sizeof(snap_header)) != sizeof(snap_header)) {
				fprintf (stderr, "Failed to write the snapshot #%d info to %s\n", i, birows->meta_file);
				ret = -1;
				goto end;
			}
		}
		birows->snapshots_is_dirty = 0;
	}

	if(bdrv_pwrite(birows->irow_meta, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to write the meta data to %s\n", birows->meta_file);
		ret = -1;
		goto end;
	}

	// bdrv_pwrite�ǰ�sectorд�룬��Ϊmeta�ļ�������sector��������Ҫ�ض�
	ret = bdrv_truncate(birows->irow_meta, sizeof(meta) + (birows->nb_snapshots) * sizeof(IRowSnapshotHeader)); // �ض��ļ�β�����������

end:
#ifdef IROW_DEBUG
	printf("irow_update_meta()return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static void irow_close_previous_state(BDRVIrowState *birows) {
	// ��Ϊ��irow_open_previous_state��birows->irow_metaΪ����
	// ����һ��Ҫ��գ�����irow_close_state�Ὣ��ָ��ָ��������ͷ�
	birows->irow_meta = NULL;
	irow_close_state(birows);
	qemu_free(birows);
}

static void irow_free_birows_cache(BDRVIrowState *birows) {
	int i;
	if(birows_cache != NULL) {
#ifdef IROW_DEBUG
		printf("free birows_cache\n");
#endif
		for(i = 0; i < birows->nb_snapshots; i++) {
			if(birows_cache[i] != NULL) {
				irow_close_previous_state(birows_cache[i]);
			}
		}
		qemu_free(birows_cache);
		birows_cache = NULL;
	}
}

static void irow_close(BlockDriverState *bs) {

	BDRVIrowState *s = bs->opaque;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_close\n");
#endif
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(s);
	dump_birows_cache(s);
#endif
	irow_free_birows_cache(s);
	irow_close_state(s);

#ifdef IROW_DEBUG
	printf("irow_close() return" IROW_DEBUG_END_STR);
#endif
}

static int irow_open_snapshots(BDRVIrowState *birows) {
	// �������ϴ洢������snapshot��Ϣ��ȡ��birows->snapshots������
	int i, ret = 0;
	IRowSnapshotHeader snap_header;
	IRowSnapshot *snap_ptr;
	int64_t offset;

	// nb_snapshotsΪ���յĸ�������ǰ״̬ռ�õ�snap_headerҲ��������
	birows->snapshots = qemu_mallocz(sizeof(IRowSnapshot) * birows->nb_snapshots);
	offset = IROW_SNAPSHOT_OFFSET;
	for(i = 0; i < birows->nb_snapshots; i++) {
		if(bdrv_pread(birows->irow_meta, offset, &snap_header, sizeof(snap_header)) != sizeof(snap_header)) {
			fprintf(stderr, "Failed to read snapshot #%d info from %s\n", i, birows->meta_file);
			ret = -1;
			goto fail;
		}
		snap_ptr = birows->snapshots + i;
		snap_ptr->date_sec = snap_header.date_sec;
		snap_ptr->date_nsec = snap_header.date_nsec;
		snap_ptr->vm_clock_nsec = snap_header.vm_clock_nsec;
		snap_ptr->vm_state_size = snap_header.vm_state_size;
		snap_ptr->nb_children = snap_header.nb_children;
		snap_ptr->is_deleted = snap_header.is_deleted;

		if(snap_header.id_str[0] != '\0') {
			snap_ptr->id_str = qemu_mallocz(128);
			strncpy(snap_ptr->id_str, snap_header.id_str, 128);
		}
		if(snap_header.name[0] != '\0') {
			snap_ptr->name = qemu_mallocz(256);
			strncpy(snap_ptr->name, snap_header.name, 256);
		}
		if(snap_header.btmp_file == '\0') {
			fprintf(stderr, "Invalid btmp file name. (snapshot #%d)\n", i);
			ret = -1;
			goto fail;
		}
		snap_ptr->btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(snap_ptr->btmp_file, snap_header.btmp_file, MAX_FILE_NAME_LENGTH);
		if(snap_header.irvd_file == '\0') {
			fprintf(stderr, "Invalid irvd file name. (snapshot #%d)\n", i);
			ret = -1;
			goto fail;
		}
		snap_ptr->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
		strncpy(snap_ptr->irvd_file, snap_header.irvd_file, MAX_FILE_NAME_LENGTH);
		if(snap_header.father_btmp_file[0] != '\0') {
			snap_ptr->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
			strncpy(snap_ptr->father_btmp_file, snap_header.father_btmp_file, MAX_FILE_NAME_LENGTH);
		}
		offset += sizeof(snap_header);
	}
	birows->snapshots_is_dirty = 0;

	return ret;
fail:
	irow_close_snapshots(birows);
	return ret;

}

static int irow_open_meta(BlockDriverState *bs, BDRVIrowState *birows, const char *filename, int flags) {
	int ret = 0;
	IRowMeta meta;


#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_open_meta()\n");
#endif

	birows->irow_meta = bdrv_new ("");
	ret = bdrv_file_open(&birows->irow_meta, filename, flags);
	if (ret < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		goto end;
	}
	if (bdrv_pread (birows->irow_meta, 0, &meta, sizeof(meta)) != sizeof(meta)) {
		fprintf (stderr, "Failed to read the IROW meta data from %s\n", filename);
		ret = -1;
		goto end;
	}
	be32_to_cpus(&meta.magic);
	be32_to_cpus(&meta.version);
	be32_to_cpus(&meta.copy_on_demand);
	be32_to_cpus(&meta.cluster_size);
	be32_to_cpus(&meta.cluster_bits);
	be64_to_cpus(&meta.total_clusters);
	be32_to_cpus(&meta.sectors_per_cluster);
	be64_to_cpus(&meta.disk_size);
	be32_to_cpus(&meta.nb_snapshots);
#ifdef IROW_DEBUG_DETAIL
	printf("meta.magic: %x\n", meta.magic);
	printf("meta.version: %x\n", meta.version);
	printf("meta.cluster_size: 0x%x(%dK)\n", meta.cluster_size, meta.cluster_size / 1024);
	printf("meta.cluster_bits: %d\n", meta.cluster_bits);
	printf("meta.total_clusters: 0x%" PRIx64 "(%" PRId64 ")\n", meta.total_clusters, meta.total_clusters);
	printf("meta.sectors_per_cluster: %d\n", meta.sectors_per_cluster);
	printf("meta.disk_size: 0x%" PRIx64 "(%" PRId64 "M)\n", meta.disk_size, meta.disk_size / (1024 * 1024));
	printf("meta.nb_snapshots: %x\n", meta.nb_snapshots);
	printf("meta.current_btmp: %s\n", meta.current_btmp);
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
	birows->copy_on_demand = meta.copy_on_demand;
	birows->cluster_size = meta.cluster_size;
	birows->cluster_bits = meta.cluster_bits;
	birows->total_clusters = meta.total_clusters;
	birows->sectors_per_cluster = meta.sectors_per_cluster;
	birows->disk_size = meta.disk_size;
	bs->total_sectors = meta.disk_size / BDRV_SECTOR_SIZE;
	birows->bitmap_size = (birows->total_clusters + 7) >> 3; // ÿ��cluster��Ӧbitmap�е�1λ
	birows->nb_snapshots = meta.nb_snapshots;
	birows->meta_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(birows->meta_file, filename, MAX_FILE_NAME_LENGTH);
	birows->current_btmp_file = qemu_malloc(MAX_FILE_NAME_LENGTH);
	strncpy(birows->current_btmp_file, meta.current_btmp, MAX_FILE_NAME_LENGTH);
	strncpy(bs->backing_file, meta.backing_file, sizeof(bs->backing_file));

#ifdef IROW_DEBUG
	printf("backing_file \"%s\"\n", bs->backing_file);
#endif


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

	if(irow_open_snapshots(birows) < 0) {
		fprintf(stderr, "Failed to read snapshots info from %s\n", birows->meta_file);
		ret = -1;
		goto end;
	}

end:
#ifdef IROW_DEBUG
	printf("irow_open_meta() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_open_btmp(BDRVIrowState *birows,  const char *filename, int flags) {
	int ret;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_open_btmp()\n");
	printf("filename %s\n", filename);
#endif
	birows->irow_btmp = bdrv_new ("");
	ret = bdrv_file_open(&birows->irow_btmp, filename, flags);
	if (ret < 0) {
		return ret;
	}
	birows->bitmap = qemu_memalign(512, birows->bitmap_size);
	if(bdrv_pread(birows->irow_btmp, 0, birows->bitmap, birows->bitmap_size) != birows->bitmap_size) {
		fprintf(stderr, "Failed to read bitmap from %s\n", filename);
		return -1;
	}
	birows->bitmap_is_dirty = 0;
	birows->vmstate_is_saved = 0;
	if(irow_check_bitmap(birows)) {
		birows->complete_image = 1;
#ifdef IROW_DEBUG
		printf("complete_image\n");
#endif
	} else {
		birows->complete_image = 0;
	}

#ifdef IROW_DEBUG
	printf("irow_open_btmp() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_open_vd(BDRVIrowState *birows, const char *filename, int flags) {
	int ret;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_open_vd()\n");
	printf("filename %s\n", filename);
#endif
	birows->irow_irvd =  bdrv_new ("");
   ret = bdrv_file_open(&birows->irow_irvd, filename, flags);
#ifdef IROW_DEBUG
	printf("irow_open_vd() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_open_data(BDRVIrowState *birows, int flags) {

	int ret = 0;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_open_data()\n");
#endif
	// ��bitmap�ļ�
	if(birows->opened_btmp_file == NULL || birows->opened_btmp_file[0] == '\0') {
		fprintf (stderr, "Void btmp file name\n");
		ret = -1;
		goto end;
	}
	if(irow_open_btmp(birows, birows->opened_btmp_file, flags) < 0) {
		fprintf (stderr, "Failed to open %s\n", birows->opened_btmp_file);
		ret = -1;
		goto end;
	}

	// ��������̾����ļ�
	if(birows->irvd_file == NULL || birows->irvd_file[0] == '\0') {
		fprintf (stderr, "Void irvd file name\n");
		ret = -1;
		goto end;
	}
	if(irow_open_vd(birows, birows->irvd_file, flags) < 0) {
		fprintf (stderr, "Failed to open %s\n", birows->irvd_file);
		ret = -1;
		goto end;
	}

end:
#ifdef IROW_DEBUG
	printf("irow_open_data() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_find_snapshot_by_btmp(BDRVIrowState *birows, const char *btmp) {
	// ���ݿ��յ�id�ҵ���Ӧ�Ŀ��գ���������birows->snapshots�����е�����
	int i;

	for(i = 0; i < birows->nb_snapshots; i++) {
		if(birows->snapshots[i].btmp_file != NULL) {
			if(strcmp(birows->snapshots[i].btmp_file, btmp) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int irow_load_info_from_snapshot(BDRVIrowState *birows, int snapshot_index) {
	// ��birows->snapshots[snapshot_index]��btmp_file, irvd_file, father_btmp_file, vm_state_size���Ƶ�birows����Ӧλ��
	IRowSnapshot *snap;
	int ret = 0;

	if(snapshot_index < 0) {
    	fprintf (stderr, "Invalid snapshot index.\n");
    	ret = -1;
      	goto end;
     }
    snap = birows->snapshots + snapshot_index;
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
    birows->opened_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    birows->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    strncpy(birows->opened_btmp_file, snap->btmp_file, MAX_FILE_NAME_LENGTH);
    strncpy(birows->irvd_file, snap->irvd_file, MAX_FILE_NAME_LENGTH);
    if(snap->father_btmp_file) {
    	birows->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
    	strncpy(birows->father_btmp_file, snap->father_btmp_file, MAX_FILE_NAME_LENGTH);
    }
    birows->vm_state_size = snap->vm_state_size;
end:
	return ret;
}

static BDRVIrowState *irow_open_previous_state(BDRVIrowState *birows, int snap_index) {
	// ��snap_indexָ���Ŀ��ն�Ӧ��btmp��irvd�ļ�
	BDRVIrowState *new_birows = qemu_mallocz(sizeof(BDRVIrowState));

	// ���ƻ�����Ϣ
	new_birows->cluster_size = birows->cluster_size;
	new_birows->cluster_bits = birows->cluster_bits;
	new_birows->total_clusters = birows->total_clusters;
	new_birows->sectors_per_cluster = birows->sectors_per_cluster;
	new_birows->disk_size = birows->disk_size;
	new_birows->bitmap_size = birows->bitmap_size;
	new_birows->current_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	strcpy(new_birows->current_btmp_file, birows->current_btmp_file);

	// ��ȡ������Ϣ
	new_birows->nb_snapshots = birows->nb_snapshots;
	new_birows->irow_meta = birows->irow_meta; // �����Ѵ򿪵�irow_meta������
	irow_open_snapshots(new_birows);


	// ���snap_index��btmp_file, irvd_file, father_btmp_file, vm_state_size
	if(irow_load_info_from_snapshot(new_birows, snap_index) < 0) {
		goto fail;
	}
	new_birows->open_flags = birows->open_flags; //
	if(irow_open_data(new_birows, new_birows->open_flags) < 0) {
		goto fail;
	}

	return new_birows;

fail:
	if(new_birows != NULL) {
		irow_close_previous_state(new_birows);
		new_birows = NULL;
	}

	return NULL;
}

static int irow_init_birows_cache(BDRVIrowState *birows) {
	int ret = 0;
	birows_cache = qemu_mallocz(sizeof(BDRVIrowState *) * birows->nb_snapshots);
	if(birows_cache == NULL) {
		ret = -1;
		goto end;
	}
	/*for(i = 0; i < birows->nb_snapshots; i++) {
		if(birows->snapshots[i].name != NULL) {
			if(strcmp(birows->snapshots[i].name, "current state") != 0) {
				birows_cache[i] = irow_open_previous_state(birows, i);
				if(birows_cache[i] == NULL) {
					ret = -1;
					goto end;
				}
			}
		}
	}*/
end:
	return ret;
}

static int irow_open(BlockDriverState *bs, const char *filename, int flags) {
    BDRVIrowState *s = bs->opaque;

    int snap_index;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_open()\n");
	printf("filename: %s, flags: %d\n", filename, flags);
#endif
#ifdef IROW_DEBUG_OPEN
	printf("press Enter to continue...\n");
	getchar();
#endif

	s->open_flags = flags;
	// ���ȴ�meta�ļ�
    if(irow_open_meta(bs, s, filename, flags) < 0) {
    	fprintf (stderr, "Failed to open %s\n", filename);
    	goto fail;
    }



    // �ҵ���ǰ״̬��snap��Ϣ�����л�ȡirvd��father����
    snap_index = irow_find_snapshot_by_btmp(s, s->current_btmp_file);
    if(irow_load_info_from_snapshot(s, snap_index) < 0) {
    	fprintf (stderr, "Failed to load filename from snapshot\n");
    	goto fail;
    }

    // �ٴ�data�ļ�(btmp��irvd�ļ�)
    if(irow_open_data(s, flags) < 0) {
    	goto fail;
    }

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
    printf("irow_open return 0" IROW_DEBUG_END_STR);
#endif
    return 0;

fail:
#ifdef IROW_DEBUG
	printf("irow_open return -1" IROW_DEBUG_END_STR);
#endif
	irow_close (bs);
	return -1;
}

static int irow_get_bit(BDRVIrowState *birows, int64_t cluster_index) {
	int64_t byte_index, bit_index;

	byte_index = cluster_index >> 3;
	bit_index = cluster_index & 0x7;
	return (birows->bitmap[byte_index] >> bit_index) & 1;
}

static void irow_set_bit(BDRVIrowState *birows, int64_t cluster_index) {
	int64_t byte_index, bit_index;
	int old_bit;

	if(cluster_cache != NULL) {
		if(cluster_index == cluster_cache->cluster_num)
			cluster_cache->cluster_num = -1; // ��Ϊcluster�Ķ��������Խ�cluster_cache����Ϊ��Ч
	}

	byte_index = cluster_index >> 3;
	bit_index = cluster_index & 0x7;
#ifdef IROW_DEBUG_DETAIL
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_set_bit()\n");
	printf("cluster_index %" PRId64 ", byte_index %" PRId64 ", bit_index %" PRId64 "\n", cluster_index, byte_index, bit_index);
	printf("byte before set bit 0x%02x\n", birows->bitmap[byte_index]);
#endif
	old_bit = (birows->bitmap[byte_index] >> bit_index) & 1;
	if(old_bit == 0) {
		birows->bitmap[byte_index] |= (1 <<  bit_index);
		birows->bitmap_is_dirty = 1;
	}
#ifdef IROW_DEBUG_DETAIL
	printf("byte after set bit 0x%02x" IROW_DEBUG_END_STR, birows->bitmap[byte_index]);
#endif
#ifdef IROW_DEBUG_SET_BIT
	if(cluster_index <= 256) {
	printf("press Enter to continue...");
	getchar();
	}
#endif

}

static int irow_read_missing_clusters2(BlockDriverState *bs, BDRVIrowState *birows, int64_t start_cluster, int64_t nb_clusters, uint8_t *buf, uint8_t *buf_bitmap, uint64_t buf_start) {
	// �ж�cluster_index��Ӧ��cluster�Ƿ�����ڵ�ǰ�Ĵ��̾����У�������ڣ��͵ݹ�Ĵ�father�����ж�ȡ��buf��buf_index����
	//BDRVIrowState *new_birows = NULL;
	int64_t continuous_missing_clusters, continuous_appearing_clusters, i, cluster_index, buf_index;
	int64_t backing_len, backing_sector_num, backing_nb_sectors;
	uint8_t *backing_buf;
	int snap_index, ret = 0;
	BlockDriver *drv;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_read_missing_clusters2()\n");
	printf("start_cluster %" PRId64 ", nb_clusters %" PRId64 ",buf_start %" PRId64 "\n", start_cluster, nb_clusters, buf_start);
#endif
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(birows);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
	printf("press Enter to continue...\n");
	getchar();
#endif
	continuous_missing_clusters = 0;
	continuous_appearing_clusters = 0;
	for(i = 0; i < nb_clusters; i++) {
#ifdef IROW_DEBUG_DETAIL
		printf("i %" PRId64 ", continuous_missing_clusters %" PRId64 ",continuous_appearing_clusters %" PRId64 "\n",
				i, continuous_missing_clusters, continuous_appearing_clusters);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
		printf("press Enter to continue...\n");
		getchar();
#endif
		if(irow_get_bit(birows, start_cluster + i) == 0) {// ���cluster���ڴ򿪵��ļ���
			buf_bitmap[buf_start + i] = 1;
			continuous_missing_clusters += 1;
			if(continuous_appearing_clusters != 0) {
				if(strcmp(birows->current_btmp_file, birows->opened_btmp_file) != 0) { // ���ڵ�ǰ�ļ��в���Ҫ��ȡ
					cluster_index = start_cluster + i - continuous_appearing_clusters;
					buf_index = buf_start + i - continuous_appearing_clusters;
#ifdef IROW_DEBUG
					printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
					if(cluster_cache != NULL) {
						if(cluster_cache->cache != NULL) {
							//����Ӧ���ټ���һ���ж��Ƿ�Ϊͬһ���ļ�
#ifdef IROW_DEBUG
							printf("cluster_index %" PRId64 ", cluster_cache->cluster_num %" PRId64 "\n",
									cluster_index, cluster_cache->cluster_num);
#endif
							if(cluster_index == cluster_cache->cluster_num) {
#ifdef IROW_DEBUG
								printf("copying from cluster_cache\nbuf_index %" PRId64 "\n", buf_index);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
								memcpy(buf + buf_index * birows->cluster_size, cluster_cache->cache, birows->cluster_size);
								cluster_index += 1;
								buf_index += 1;
								continuous_appearing_clusters -= 1;
								if(continuous_appearing_clusters == 0) {
									continue;
								}
							}
						}
					}
					drv = birows->irow_irvd->drv;
#ifdef IROW_DEBUG
					printf("reading from father...\n");
#endif
#ifdef IROW_DEBUG_DETAIL
					printf("cluster_index %" PRId64 ", buf_index %" PRId64 ", continuous_appearing_clusters %" PRId64 "\n",
							cluster_index, buf_index, continuous_appearing_clusters);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
		printf("press Enter to continue...\n");
		getchar();
#endif
					if(drv->bdrv_read(birows->irow_irvd,
								cluster_index * birows->sectors_per_cluster,
								buf + buf_index * birows->cluster_size,
								continuous_appearing_clusters * birows->sectors_per_cluster) < 0) {
							fprintf(stderr, "Failed to read clusters from %s\n", birows->irvd_file);
							ret = -1;
							goto end;
						}
#ifdef IROW_DEBUG
					printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
					if(cluster_cache != NULL) {
						if(cluster_cache->cache != NULL) {
#ifdef IROW_DEBUG
							printf("copying to father cache\n");
#endif
							memcpy(cluster_cache->cache, buf + (buf_start + i - 1) * birows->cluster_size, birows->cluster_size);
							cluster_cache->cluster_num = start_cluster + i - 1;
						}
					}
					} else {
#ifdef IROW_DEBUG
						printf("cluster(s) in current irvd, do nothing...\n");
#endif
				}
				continuous_appearing_clusters = 0;
			}
		} else {// ���cluster�ڴ򿪵��ļ���
			continuous_appearing_clusters += 1;
			if(continuous_missing_clusters != 0) {
				if(birows->father_btmp_file != NULL) { // ��father����
					snap_index = irow_find_snapshot_by_btmp(birows, birows->father_btmp_file); // ���father�ڿ��������е�����
#ifdef IROW_DEBUG
					printf("snap_index %d\n", snap_index);
#endif
					if(birows_cache[snap_index] == NULL) {
						birows_cache[snap_index] = irow_open_previous_state(birows, snap_index); // ������father
						if(birows_cache[snap_index] == NULL) {
							ret = -1;
							goto end;
						}
					}
#ifdef IROW_DEBUG_DETAIL
					dump_birows_cache(birows);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
					printf("press Enter to continue...\n");
					getchar();
#endif
#ifdef IROW_DEBUG
					printf("Recursive calling irow_read_missing_clusters2...\n");
#endif
					ret = irow_read_missing_clusters2(bs,
																birows_cache[snap_index],
																start_cluster + i - continuous_missing_clusters,
																continuous_missing_clusters,
																buf,
																buf_bitmap,
																buf_start + i - continuous_missing_clusters); // ������father��ȡ

				} else { // û��father����
					if(bs->backing_hd) { // ��base image
					    backing_len = bdrv_getlength(bs->backing_hd) / 512;
					    backing_sector_num = (start_cluster + i - continuous_missing_clusters) * birows->sectors_per_cluster;
					    backing_nb_sectors = continuous_missing_clusters * birows->sectors_per_cluster;
					    backing_buf = buf + (buf_start + i - continuous_missing_clusters) * birows->cluster_size;
#ifdef IROW_DEBUG
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
#ifdef IROW_DEBUG
	printf("after loop\n");
	printf("continuous_missing_clusters %ld, continuous_appearing_clusters %ld\n",
			continuous_missing_clusters, continuous_appearing_clusters);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
	if(continuous_missing_clusters != 0) {
		if(birows->father_btmp_file != NULL) {
			snap_index = irow_find_snapshot_by_btmp(birows, birows->father_btmp_file); // ���father�ڿ��������е�����
#ifdef IROW_DEBUG
			printf("snap_index %d\n", snap_index);
#endif
			if(birows_cache[snap_index] == NULL) {
				birows_cache[snap_index] = irow_open_previous_state(birows, snap_index); // ������father
				if(birows_cache[snap_index] == NULL) {
					ret = -1;
					goto end;
				}
			}
#ifdef IROW_DEBUG_DETAIL
			dump_birows_cache(birows);
#endif
#ifdef IROW_DEBUG
			printf("Recursive calling irow_read_missing_clusters2...\n");
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			ret = irow_read_missing_clusters2(bs,
														birows_cache[snap_index],
														start_cluster + i - continuous_missing_clusters,
														continuous_missing_clusters,
														buf,
														buf_bitmap,
														buf_start + i - continuous_missing_clusters); // ������father��ȡ

		} else { // û��father����
			if(bs->backing_hd) { // ��base image
			    backing_len = bdrv_getlength(bs->backing_hd) / 512;
			    backing_sector_num = (start_cluster + i - continuous_missing_clusters) * birows->sectors_per_cluster;
			    backing_nb_sectors = continuous_missing_clusters * birows->sectors_per_cluster;
			    backing_buf = buf + (buf_start + i - continuous_missing_clusters) * birows->cluster_size;
#ifdef IROW_DEBUG
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
		if(strcmp(birows->current_btmp_file, birows->opened_btmp_file) != 0) { // ���ڵ�ǰ�ļ��в���Ҫ��ȡ
			cluster_index = start_cluster + i - continuous_appearing_clusters;
			buf_index = buf_start + i - continuous_appearing_clusters;
#ifdef IROW_DEBUG
			printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(cluster_cache != NULL) {
				if(cluster_cache->cache != NULL) {
					//����Ӧ���ټ���һ���ж��Ƿ�Ϊͬһ���ļ�
#ifdef IROW_DEBUG
					printf("cluster_index %" PRId64 ", cluster_cache->cluster_num %" PRId64 "\n",
							cluster_index, cluster_cache->cluster_num);
#endif
					if(cluster_index == cluster_cache->cluster_num) {
#ifdef IROW_DEBUG
						printf("copying from cluster_cache\n");
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
						memcpy(buf + buf_index * birows->cluster_size, cluster_cache->cache, birows->cluster_size);
						cluster_index += 1;
						buf_index += 1;
						continuous_appearing_clusters -= 1;
						if(continuous_appearing_clusters == 0) {
							goto end;
						}
					}
				}
			}
			drv = birows->irow_irvd->drv;
#ifdef IROW_DEBUG
			printf("Reading from father...\n");
#endif
#ifdef IROW_DEBUG_DETAIL
					printf("cluster_index %" PRId64 ", buf_index %" PRId64 ", continuous_appearing_clusters %" PRId64 "\n",
							cluster_index, buf_index, continuous_appearing_clusters);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(drv->bdrv_read(birows->irow_irvd,
						cluster_index * birows->sectors_per_cluster,
						buf + buf_index * birows->cluster_size,
						continuous_appearing_clusters * birows->sectors_per_cluster) < 0) {
					fprintf(stderr, "Failed to read clusters from %s\n", birows->irvd_file);
					ret = -1;
				}
#ifdef IROW_DEBUG
			printf("cluster_cache %p, cluster_cache->cache %p\n", cluster_cache, cluster_cache->cache);
#endif
#ifdef IROW_DEBUG_READ_MISSING_CLUSTSERS2
			printf("press Enter to continue...\n");
			getchar();
#endif
			if(cluster_cache != NULL) {
				if(cluster_cache->cache != NULL) {
#ifdef IROW_DEBUG
					printf("copying to father cache\n");
#endif
					memcpy(cluster_cache->cache, buf + (buf_start + i - 1) * birows->cluster_size, birows->cluster_size);
					cluster_cache->cluster_num = start_cluster + i - 1;
				}
			}
		} else {
#ifdef IROW_DEBUG
				printf("cluster(s) in current irvd, do nothing...\n");
	#endif
		}
		continuous_appearing_clusters = 0;
	}

end:
#ifdef IROW_DEBUG
	printf("irow_read_missing_clusters2() return %d\n" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_read_missing_clusters(BlockDriverState *bs, int64_t first_cluster, int64_t last_cluster, uint8_t *buf, uint8_t *buf_bitmap, int is_read) {
	// ����first_cluster��last_cluster�У����ڵ�ǰ����cluster��father�ж�ȡ��buf�е���Ӧ��λ�ã�buf_bitmap���ڼ�¼��ȡ����Щcluster
	BDRVIrowState *birows = bs->opaque;
	int64_t nb_clusters;
	int ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_read_missing_clusters()\n");
	printf("first_cluster %" PRId64 ", last_cluster %" PRId64 "\n", first_cluster, last_cluster);
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(birows);
#endif
#endif

	if(first_cluster >= birows->total_clusters) {
			fprintf (stderr, "Invalid first_cluster!\n");
		ret  = -1;
		goto end;
	}
	if(last_cluster >= birows->total_clusters) {
			fprintf (stderr, "Invalid last_cluster!\n");
		ret = -1;
		goto end;
	}

	if(is_read) { // ����Ƕ�����Ҫ��֤ÿһ��cluster���ڵ�ǰ������̾�����
		nb_clusters = last_cluster - first_cluster + 1;
		ret = irow_read_missing_clusters2(bs, birows, first_cluster, nb_clusters, buf, buf_bitmap, 0);
		if(ret < 0)
			goto end;

	} else { // �����д���м��cluster�ᱻ��ȫ���ǣ����ֻ�豣֤��һ�������һ��cluster�ڵ�ǰ�����м��ɣ�
		ret = irow_read_missing_clusters2(bs, birows, first_cluster, 1, buf, buf_bitmap, 0);
		if(ret < 0)
			goto end;
		if(first_cluster != last_cluster) {
			ret = irow_read_missing_clusters2(bs, birows, last_cluster, 1, buf, buf_bitmap, 1);
		}
	}


end:
#ifdef IROW_DEBUG
	printf("irow_read_missing_clusters() return %d\n" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

/*static int irow_read_clusters(BDRVIrowState *birows, int64_t cluster_index, uint8_t *buf, int nb_clusters) {
	// ��cluster_index��ʼ��ȡnb_clusters��buf��
	// �ú������ж϶�ȡ��cluster�Ƿ��ڴ򿪵ľ����У����øú����ĵط�Ӧ����֤��һ��
	// ����Ƕ�ȡ���ٴ򿪾����е�cluster��Ӧ��ʹ�������irow_read_missing_clusters()
	int ret = 0;
	BlockDriver *drv;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_read_clusters()\n");
	printf("cluster_index %" PRId64 ", nb_clusters %d\n", cluster_index, nb_clusters);
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(birows);
#endif
#endif
	if(cluster_index >= birows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index!\n");
		ret  = -1;
		goto end;
	}
	if((cluster_index + nb_clusters -1) >= birows->total_clusters) {
			fprintf (stderr, "Invalid nb_clusters!\n");
		ret = -1;
		goto end;
	}

	drv = birows->irow_irvd->drv;
	ret = drv->bdrv_read(birows->irow_irvd, birows->sectors_per_cluster * cluster_index, buf, birows->sectors_per_cluster * nb_clusters);

end:
#ifdef IROW_DEBUG
	printf("irow_write_clusters() return %d\n" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}*/

static int irow_write_clusters(BDRVIrowState *birows, int64_t cluster_index, const uint8_t *buf, int nb_clusters) {
	// ��buf��nb_cluster����cluster����д���cluster_index��ʼ��
	// �����ж�cluster�Ƿ��Ѿ��ڵ�ǰ���̾����У�д��ʱ�Ὣ����cluster��ȫ����
	int ret = 0;
	BlockDriver *drv;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_write_clusters()\n");
	printf("cluster_index %" PRId64 ", nb_clusters %d\n", cluster_index, nb_clusters);
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(birows);
#endif
#endif
	if(cluster_index >= birows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index!\n");
		ret  = -1;
		goto end;
	}
	if((cluster_index + nb_clusters -1) >= birows->total_clusters) {
			fprintf (stderr, "Invalid cluster_index or nb_clusters!\n");
		ret = -1;
		goto end;
	}
	drv = birows->irow_irvd->drv;
	ret = drv->bdrv_write(birows->irow_irvd, birows->sectors_per_cluster * cluster_index, buf, birows->sectors_per_cluster * nb_clusters);

end:
#ifdef IROW_DEBUG
	printf("irow_write_clusters() return %d\n" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int64_t first_sector_in_cluster(BDRVIrowState *birows, int64_t cluster_index) {
	return cluster_index * birows->sectors_per_cluster;
}

static int64_t last_sector_in_cluster(BDRVIrowState *birows, int64_t cluster_index) {
	return (cluster_index + 1) * birows->sectors_per_cluster - 1;
}

static int irow_assert_clusters(BlockDriverState *bs, ClusterBuffer *cbuf, int64_t sector_num, int nb_sectors, int op_type) {
	BDRVIrowState *birows = bs->opaque;
	int64_t nb_clusters, i, first_cluster, last_cluster, continuous_cluster, cluster_offset;
	uint8_t *buffer_offset;// *zero_buf = NULL;
	int ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_assert_clusters()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d, op_type %d\n", sector_num, nb_sectors, op_type);
#endif
#ifdef IROW_DEBUG_ASSERT_CLUSTERS
	printf("press Enter to continue...");
	getchar();
#endif

	first_cluster = sector_num / birows->sectors_per_cluster;
	last_cluster = (sector_num + nb_sectors - 1) / birows->sectors_per_cluster;
	nb_clusters = last_cluster - first_cluster + 1;
	//zero_buf = qemu_mallocz(birows->cluster_size);

#ifdef IROW_DEBUG
	printf("first_cluster %" PRId64 ", last_cluster %" PRId64 "\n", first_cluster, last_cluster);
#endif

	switch(op_type) {
	case IROW_READ:
	case IROW_AIO_READ:
		if(irow_read_missing_clusters(bs, first_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 1) < 0) {
			ret = -1;
			goto end;
		}

		if(birows->copy_on_demand) {
			// д�����������ɸ�cluster
	#ifdef IROW_DEBUG_DETAIL
			printf("%" PRId64 ": ", nb_clusters);
			for(i = 0; i <  nb_clusters + 1; i++) {
				printf("%d ", cbuf->read_from_father[i]);
			}
			printf("\n");
	#endif
			continuous_cluster = 0;
			for(i = 0; i < nb_clusters + 1; i++) {
	#ifdef IROW_DEBUG_DETAIL
				printf("i %" PRId64 ", continuous_cluster %" PRId64 "\n", i, continuous_cluster);
	#endif
				if(cbuf->read_from_father[i] == 0) {
#ifdef IROW_DEBUG
					printf("read_from_father[%ld] is 0\n", i);
#endif
					if(continuous_cluster == 0)
						continue;
					cluster_offset = first_cluster + i - continuous_cluster;
					buffer_offset = cbuf->buf + (i - continuous_cluster) * birows->cluster_size;
	#ifdef IROW_DEBUG_DETAIL
					printf("copying data\n");
					printf("cluster_offset %" PRId64 ", buf %p, buffer_offset %p\n", cluster_offset, cbuf->buf, buffer_offset);
	#endif
	#ifdef IROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
					if(irow_write_clusters(birows, cluster_offset, buffer_offset, continuous_cluster) < 0) {
						ret = -1;
						goto end;
					}
					continuous_cluster = 0;
	#ifdef IROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
				} else {
#ifdef IROW_DEBUG
					printf("read_from_father[%ld] is 1\n", i);
#endif
	#ifdef IROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
					/*if(memcmp(zero_buf, cbuf->buf + i * birows->cluster_size, birows->cluster_size) == 0) {
#ifdef IROW_DEBUG
					printf("cluster data is all zeros\n");
#endif
						if(continuous_cluster != 0) {
							cluster_offset = first_cluster + i - continuous_cluster;
							buffer_offset = cbuf->buf + (i - continuous_cluster) * birows->cluster_size;
			#ifdef IROW_DEBUG_DETAIL
							printf("copying data\n");
							printf("cluster_offset %" PRId64 ", buf %p, buffer_offset %p\n", cluster_offset, cbuf->buf, buffer_offset);
			#endif
			#ifdef IROW_DEBUG_ASSERT_CLUSTERS
							printf("press Enter to continue...");
							getchar();
			#endif
							if(irow_write_clusters(birows, cluster_offset, buffer_offset, continuous_cluster) < 0) {
								ret = -1;
								goto end;
							}
							continuous_cluster = 0;
			#ifdef IROW_DEBUG_ASSERT_CLUSTERS
							printf("press Enter to continue...");
							getchar();
			#endif
						}
					} else {
						continuous_cluster += 1;
					}*/
					continuous_cluster += 1;
					irow_set_bit(birows, first_cluster + i);
	#ifdef IROW_DEBUG_ASSERT_CLUSTERS
					printf("press Enter to continue...");
					getchar();
	#endif
				}
			}
		}
		break;
	case IROW_WRITE:
	case IROW_AIO_WRITE:
		if(sector_num == first_sector_in_cluster(birows, first_cluster)) { // д�������뵽cluster���
			if((sector_num + nb_sectors - 1) == last_sector_in_cluster(birows, last_cluster)) { // д���յ���뵽cluster�յ�
#ifdef IROW_DEBUG
				printf("write whole clusters, do nothing.\n");
#endif
				break; // д�������cluster���ʲôҲ����Ҫ��
			} else { // д���յ�δ���뵽cluster�յ�
#ifdef IROW_DEBUG
				printf("assert last cluster.\n");
#endif
				// ��ʱ��ֻ������last_cluster����һ��������cluster������first_cluster�Ƿ���last_cluster��ͬ��
				if(irow_read_missing_clusters(bs, last_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef IROW_DEBUG
					printf("last cluster is read from father\n");
#endif
#ifdef IROW_DEBUG_WRITE
					dump_mem(cbuf->buf, birows->cluster_size, "last cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(irow_write_clusters(birows, last_cluster , cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					irow_set_bit(birows, last_cluster);
				}
				break;
			}
		} else { // д�����δ���뵽cluster���
			if((sector_num + nb_sectors - 1) == last_sector_in_cluster(birows, last_cluster)) { // д���յ���뵽cluster�յ�
#ifdef IROW_DEBUG
				printf("assert first cluster.\n");
#endif
				// ��ʱ��ֻ������first_cluster����һ��������cluster������first_cluster�Ƿ���last_cluster��ͬ��
				if(irow_read_missing_clusters(bs, first_cluster, first_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef IROW_DEBUG
					printf("first cluster is read from father\n");
#endif
#ifdef IROW_DEBUG_WRITE
					dump_mem(cbuf->buf, birows->cluster_size, "first cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(irow_write_clusters(birows, first_cluster , cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					irow_set_bit(birows, first_cluster);
				}
				break;
			} else { // д���յ�δ���뵽cluster�յ�
#ifdef IROW_DEBUG
				printf("assert first & last cluster.\n");
#endif
				// ��ʱ,first_cluster��last_cluster���п����ǲ�������cluster
				if(irow_read_missing_clusters(bs, first_cluster, last_cluster, cbuf->buf, cbuf->read_from_father, 0) < 0) {
					ret = -1;
					goto end;
				}
				if(cbuf->read_from_father[0] == 1) {
#ifdef IROW_DEBUG
					printf("first cluster is read from father\n");
#endif
#ifdef IROW_DEBUG_WRITE
					dump_mem(cbuf->buf, birows->cluster_size, "first cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(irow_write_clusters(birows, first_cluster, cbuf->buf, 1) < 0) {
						ret = -1;
						goto end;
					}
					irow_set_bit(birows, first_cluster);
				}
				if(cbuf->read_from_father[1] == 1) {
#ifdef IROW_DEBUG
					printf("last cluster is read from father\n");
#endif
#ifdef IROW_DEBUG_WRITE
					dump_mem(cbuf->buf + birows->cluster_size, birows->cluster_size, "last cluster");
					printf("press Enter to continue...");
					getchar();
#endif
					if(irow_write_clusters(birows, last_cluster, cbuf->buf + birows->cluster_size, 1) < 0) {
						ret = -1;
						goto end;
					}
					irow_set_bit(birows, last_cluster);
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
#ifdef IROW_DEBUG
	printf("irow_assert_clusters() return %d\n" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_read(BlockDriverState *bs, int64_t sector_num, uint8_t *buf, int nb_sectors) {

	BDRVIrowState *s = bs->opaque;
	int64_t first_cluster, last_cluster, nb_clusters, sector_index, cluster_index, buf_offset, temp_buf_offset, temp_buf_index;
	int first_cluster_copied = 0;
	BlockDriver *drv;
	ClusterBuffer cbuf;
	int remain_sectors, cbuf_offset, len, ret = 0;
	uint8_t *temp_buf = NULL;

	first_cluster = sector_num / s->sectors_per_cluster;
	last_cluster = (sector_num + nb_sectors - 1) / s->sectors_per_cluster;
	nb_clusters = last_cluster - first_cluster + 1;
	temp_buf_offset = (sector_num & (s->sectors_per_cluster - 1)) * BDRV_SECTOR_SIZE;
	temp_buf_index = 0;
	cbuf.buf = NULL;
	cbuf.read_from_father = NULL;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_read()\n");
	printf("sector_num: %" PRId64 "\n", sector_num);
	printf("nb_sectors: %d\n", nb_sectors);
	printf("sectors_per_cluster: %d\n", s->sectors_per_cluster);
	printf("first_cluster: %" PRId64 "\n", first_cluster);
	printf("last_cluster: %" PRId64 "\n", last_cluster);
#endif

	if(first_cluster >= s->total_clusters) { // ��ʼ��cluster�����������Χ
		fprintf (stderr, "Invalid sector_num.\n");
		ret = -1;
		goto end;
	}
	if(last_cluster >= s->total_clusters) { // ����cluster�����������Χ
		fprintf (stderr, "Invalid nb_sectors.\n");
		ret = -1;
		goto end;
	}

	// ����cluster�Ƿ�����ڵ�ǰ�����У����Ƚ����ȡ�������ٽ����ھ����е�����������
	temp_buf = qemu_memalign(512, nb_clusters * s->cluster_size);
	memset(temp_buf, 0, nb_clusters * s->cluster_size);
	if(temp_buf == NULL) {
		fprintf (stderr, "Failed to create temp_buf.\n");
		ret = -1;
		goto end;
	}
	if(cluster_cache != NULL) {
		if(cluster_cache->cache != NULL) {
			if(first_cluster == cluster_cache->cluster_num) {
#ifdef IROW_DEBUG
			printf("copying from cluster_cache\n");
#endif
				memcpy(temp_buf, cluster_cache->cache, s->cluster_size);
				first_cluster_copied = 1;
				first_cluster += 1;
				nb_clusters -= 1;
				temp_buf_index += 1;
			}
		}
	}
#ifdef IROW_DEBUG
	printf("nb_clusters: %" PRId64 "\n", nb_clusters);
#endif
#ifdef IROW_DEBUG_READ
	printf("Press Enter to continue...\n");
	getchar();
#endif

	if(nb_clusters != 0) {
#ifdef IROW_DEBUG
			printf("read from image file\n");
#endif
		drv = s->irow_irvd->drv;
		ret = drv->bdrv_read(s->irow_irvd, first_cluster * s->sectors_per_cluster, temp_buf + temp_buf_index * s->cluster_size,  nb_clusters * s->sectors_per_cluster);
		if(ret < 0) {
			goto end;
		}
	}

	memcpy(buf, temp_buf + temp_buf_offset, nb_sectors * BDRV_SECTOR_SIZE);

	if(first_cluster_copied) {
		first_cluster -= 1;
		nb_clusters += 1;
	}
	if(nb_clusters != 0) {
		if(cluster_cache != NULL) {
			if(cluster_cache->cache != NULL) {
				if(irow_get_bit(s, last_cluster)) {
#ifdef IROW_DEBUG
			printf("copying to cluster_cache\n");
#endif
				memcpy(cluster_cache->cache, temp_buf + (nb_clusters - 1) * s->cluster_size, s->cluster_size);
				cluster_cache->cluster_num = last_cluster;
				}
			}
		}

#ifdef IROW_DEBUG
		printf("\nfather_btmp_file %s\n", s->father_btmp_file);
		printf("complete_image %d\n\n", s->complete_image);
#endif
#ifdef IROW_DEBUG_READ
				printf("Press Enter to continue...\n");
				getchar();
#endif
		if(s->complete_image != 1) {
			// ��������
			cbuf.buf = qemu_memalign(512, nb_clusters * s->cluster_size); // ���ڴ洢��father��ȡ������
			memset(cbuf.buf, 0, nb_clusters * s->cluster_size);
			cbuf.read_from_father = qemu_mallocz(nb_clusters  + 1); //���ڱ�ʾbuf���ĸ�cluster�Ǵ�father�ж�ȡ�ģ��������һ���ռ������ں����ж�����cluster����
			// ��ȡ���ٵ�ǰ�����е�cluster��cbuf��
			if(irow_assert_clusters(bs, &cbuf, first_sector_in_cluster(s, first_cluster), nb_clusters * s->sectors_per_cluster, IROW_READ) < 0) {
				fprintf (stderr, "irow_assert_clusters() failed.\n");
				ret = -1;
				goto end;
			}
			// ����btmp
			irow_update_btmp(s);

#ifdef IROW_DEBUG_DETAIL
			int64_t i;
			remain_sectors = nb_sectors;
			printf("read_from_father[]: ");
			for(i = 0; i < nb_clusters; i++) {
				printf("%d, ", cbuf.read_from_father[i]);
			}
			printf("\n");
#endif

			sector_index = sector_num;
			remain_sectors = nb_sectors;
			buf_offset = 0;
#ifdef IROW_DEBUG_READ
			dump_mem(buf, nb_sectors * BDRV_SECTOR_SIZE, "read buffer before cbuf copy");
#endif
			while(remain_sectors > 0) {
				cluster_index = sector_index / s->sectors_per_cluster;
				len = last_sector_in_cluster(s, cluster_index) - sector_index + 1;
				if(len > remain_sectors)
					len = remain_sectors;
#ifdef IROW_DEBUG_DETAIL
				printf("sector_index %" PRId64 ", cluster_index %" PRId64 ", first_cluster %" PRId64 ", buf_offset %" PRId64 ", len %d\n", sector_index, cluster_index, first_cluster, buf_offset, len);
#endif
#ifdef IROW_DEBUG_READ
				printf("read_from_father %d\n", cbuf.read_from_father[cluster_index - first_cluster]);
				printf("Press Enter to continue...\n");
				getchar();
#endif
				if(cbuf.read_from_father[cluster_index - first_cluster] == 1) {
#ifdef IROW_DEBUG
					printf("copying from cbuf\n");
#endif
					cbuf_offset = (sector_index & (s->sectors_per_cluster - 1)) + (cluster_index - first_cluster) * s->sectors_per_cluster;
#ifdef IROW_DEBUG_DETAIL
				printf("cbuf_offset %d\n", cbuf_offset);
#endif
					memcpy(buf + buf_offset, cbuf.buf + cbuf_offset * BDRV_SECTOR_SIZE, len * BDRV_SECTOR_SIZE);
#ifdef IROW_DEBUG_READ
				dump_mem(buf, nb_sectors * BDRV_SECTOR_SIZE, "read buffer");
				printf("Press Enter to continue...\n");
				getchar();
#endif
				}
				sector_index = first_sector_in_cluster(s, cluster_index + 1);
				remain_sectors -= len;
				buf_offset += len * BDRV_SECTOR_SIZE;
			}
		}

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
	if(temp_buf != NULL) {
		qemu_free(temp_buf);
		temp_buf = NULL;
	}
#ifdef IROW_DEBUG
	printf("irow_read return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_write(BlockDriverState *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
	BDRVIrowState *s = bs->opaque;
	int64_t first_cluster, last_cluster, current_cluster;
	ClusterBuffer cbuf;
	BlockDriver *drv;
	int ret = 0;

	first_cluster = sector_num / s->sectors_per_cluster;
	last_cluster = (sector_num + nb_sectors - 1) / s->sectors_per_cluster;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_write()\n");
	printf("sector_num: %" PRId64 "\n", sector_num);
	printf("nb_sectors: %d\n", nb_sectors);
	printf("sectors_per_cluster: %d\n", s->sectors_per_cluster);
	printf("first_cluster: %" PRId64 "\n", first_cluster);
	printf("last_cluster: %" PRId64 "\n", last_cluster);
#endif

	if(first_cluster >= s->total_clusters) { // ��ʼ��cluster�����������Χ
		fprintf (stderr, "Invalid sector_num!\n");
		ret = -1;
		goto end;
	}
	if(last_cluster >= s->total_clusters) { // ����cluster�����������Χ
		fprintf (stderr, "Invalid nb_sectors!\n");
		ret = -1;
		goto end;
	}

	cbuf.buf = NULL;
	cbuf.read_from_father = NULL;
	if(s->complete_image != 1) {
		// ��������
		cbuf.buf = qemu_memalign(512, 2 * s->cluster_size); // ���ڴ洢��father��ȡ������
		memset(cbuf.buf, 0, 2 * s->cluster_size);
		cbuf.read_from_father = qemu_mallocz(2); //���ڱ�ʾbuf���ĸ�cluster�Ǵ�father�ж�ȡ��
		// ȷ��ͷβ��cluster�ڵ�ǰ������̾�����
		if(irow_assert_clusters(bs, &cbuf, sector_num, nb_sectors, IROW_WRITE) < 0) {
			ret = -1;
			goto end;
		}
	}

	// ����bitmap����
	for(current_cluster = first_cluster; current_cluster <= last_cluster; current_cluster++) {
		//if(irow_get_bit(s, current_cluster) == 0)
			irow_set_bit(s, current_cluster);
	}

	// ͷβ��cluster�ڵ�ǰ������̾����У����ֱ�Ӱ�sectorд�뼴��
	drv = s->irow_irvd->drv;
	ret = drv->bdrv_write(s->irow_irvd, sector_num, buf, nb_sectors);
	if(ret < 0) {
		goto end;
	}

	// ����btmp�ļ�
	if(irow_update_btmp(s) < 0) {
		fprintf (stderr, "Failed to update btmp file. (%s)\n", s->opened_btmp_file);
		ret = -1;
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
#ifdef IROW_DEBUG
		printf("irow_write return %d" IROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static int irow_generate_filename(char *dest, const char *prefix, const char *body, const char *suffix) {
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

static int irow_create_meta(IRowCreateState *cs) {
	IRowMeta meta;
	IRowSnapshotHeader snap_header;
	uint32_t cluster_size, copy_on_demand;
	uint64_t disk_size;
	qemu_timeval tv;
	int fd, cluster_bits, ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_create_meta\n");
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
#ifdef IROW_DEBUG
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
	meta.magic = cpu_to_be32(IROW_MAGIC);
   	meta.version = cpu_to_be32(IROW_VERSION);
   	meta.copy_on_demand = cpu_to_be32(copy_on_demand);
   	meta.cluster_size = cpu_to_be32(cluster_size); // cluster�ֽ���
   	meta.cluster_bits = cpu_to_be32(cluster_bits); // clusterλ��
   	meta.total_clusters = cpu_to_be64((disk_size + cluster_size -1) >> cluster_bits); // ���̾����ܵ�cluster����
   	meta.sectors_per_cluster = cpu_to_be32(cluster_size >> BDRV_SECTOR_BITS);
   	meta.disk_size = cpu_to_be64(disk_size); // ��������ֽ���
   	meta.nb_snapshots = cpu_to_be32(1); // ������,��ǰ״̬Ҳռ��һ��������Ϣ�����Դ���ʱ������Ϊ1

   	if(irow_generate_filename(meta.current_btmp, cs->meta_file, cs->time_value, "btmp") < 0) { // ��ǰbitmap�ļ�
   		ret = -1;
   		goto end;
   	}

   	if(irow_generate_filename(cs->irvd_file, cs->meta_file, cs->time_value, "irvd") < 0) { // ��ǰirvd�ļ�
   	   	ret = -1;
   	   	goto end;
   	}

   	// ����base image
   	if(cs->backing_file != NULL) {
   		strncpy(meta.backing_file, cs->backing_file, MAX_FILE_NAME_LENGTH);
   	}

   	strncpy(cs->btmp_file, meta.current_btmp, MAX_FILE_NAME_LENGTH);

   	memset(&snap_header, 0, sizeof(snap_header));

   snap_header.snap_magic = cpu_to_be32(IROW_SNAPHEADER_MAGIC);
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
#ifdef IROW_DEBUG
	printf("irow_create_meta() return %d\n", ret);
#endif
	return ret;
}

static int irow_create_btmp(IRowCreateState *cs) {

	char *bitmap = NULL;
	int fd,  bitmap_size, ret = 0;

	if(cs->btmp_file[0] == '\0') {
		fprintf(stderr, "Void btmp file name\n");
		ret = -1;
		goto end;
	}
	fd = open(cs->btmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if(fd < 0) {
		fprintf(stderr, "Can not open %s\n", cs->btmp_file);
		ret = -1;
		goto end;
	}

	// (size + cluster_size - 1) >> cluster_bits: ����size�ֽ�ռ�ü���cluster
	// (n + 7) >> 3: ����n����ռ�ö����ֽ�
	bitmap_size = (((cs->disk_size + cs->cluster_size - 1) >> cs->cluster_bits) + 7) >> 3;
	bitmap = qemu_malloc(bitmap_size);
	/*if(cs->father_btmp_file[0] == '\0') { // û��father�ļ��������Ǹ�
		memset(bitmap, 0xff, bitmap_size);
	} else {
		memset(bitmap, 0, bitmap_size);
	}*/
	memset(bitmap, 0, bitmap_size);

	write(fd, bitmap, bitmap_size);

	if(close(fd) != 0) {
		ret = -1;
	}

end:
	if(bitmap != NULL)
		qemu_free(bitmap);
	return ret;
}

static int irow_create_vd(IRowCreateState *cs) {
	int fd, ret = 0;

	if(cs->irvd_file[0] == '\0') {
		fprintf(stderr, "Void irvd file name\n");
		ret = -1;
		goto end;
	}

	fd = open(cs->irvd_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if(fd < 0) {
		fprintf(stderr, "Can not open %s\n", cs->irvd_file);
		ret = -1;
		goto end;
	}
	if(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, cs->disk_size) < 0) {
		;//fprintf(stderr, "Can not preallocate disk space for %s\n(Preallocation is not supported on ext3)\n", cs->irvd_file);
	}
	if (ftruncate(fd, cs->disk_size) != 0) {
		fprintf(stderr, "Can not truncate %s to %" PRId64 " bytes\n", cs->irvd_file, cs->disk_size);
		ret = -1;
	}
	if (close(fd) != 0) {
		ret = -1;
	}


end:
	return ret;
}

static IRowCreateState *irow_create_state_new(void) {
	IRowCreateState *cs = qemu_mallocz(sizeof(IRowCreateState));
	qemu_timeval tv;

	cs->meta_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	cs->btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	cs->irvd_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	cs->time_value = qemu_mallocz(MAX_FILE_NAME_LENGTH);
	cs->father_btmp_file = qemu_mallocz(MAX_FILE_NAME_LENGTH);

	qemu_gettimeofday(&tv); // ��ȡ��ǰʱ��
	sprintf(cs->time_value, "%lx%lx", tv.tv_sec, tv.tv_usec); // ��16�����ַ������浽time_value�У��Ա�����ʹ��
	return cs;
}

static void irow_create_state_delete(IRowCreateState *cs) {
	if(cs->meta_file != NULL)
		qemu_free(cs->meta_file);
	if(cs->btmp_file != NULL)
		qemu_free(cs->btmp_file);
	if(cs->irvd_file != NULL)
		qemu_free(cs->irvd_file);
	if(cs->time_value != NULL)
		qemu_free(cs->time_value);
	if(cs->father_btmp_file != NULL)
		qemu_free(cs->father_btmp_file);
	qemu_free(cs);
}

static int irow_create(const char *filename, QEMUOptionParameter *options) {
	// ��������Ĳ���
	//
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_create()\n");
#endif

	IRowCreateState *cs = irow_create_state_new();
	int ret = 0;

	if(cs == NULL) {
		ret = -1;
		goto end;
	}
	cs->cluster_size = 4096; // clusterĬ�ϴ�СΪ4KB
	cs->copy_on_demand = 0; // Ĭ�Ϲرհ��追������
	cs->backing_file = NULL;
	strncpy(cs->meta_file, filename, MAX_FILE_NAME_LENGTH);
	// ��������
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
			cs->disk_size= options->value.n;
			} else if (!strcmp(options->name, BLOCK_OPT_CLUSTER_SIZE)) {
				if (options->value.n) {
					cs->cluster_size = options->value.n;
				}
			} else if (!strcmp(options->name, BLOCK_OPT_BACKING_FILE)) {
	            cs->backing_file = options->value.s;
			} else if(!strcmp(options->name, "copy_on_demand")) {
				cs->copy_on_demand = options->value.n;
			}
	        options++;
	}

	// ����meta�ļ�
    if(irow_create_meta(cs) < 0) {
    	fprintf(stderr, "Fail to create meta file of %s\n", filename);
    	ret = -1;
    	goto end;
    }

	//����������̾���bitmap�ļ�
    if(irow_create_btmp(cs) < 0) {
    	fprintf(stderr, "Fail to create bitmap file of %s\n", filename);
    	ret = -1;
    	goto end;
    }

	// ����������̾����ļ�
    if(irow_create_vd(cs) < 0) {
    	fprintf(stderr, "Fail to create virtual machine disk file of %s\n", filename);
    	ret = -1;
    	goto end;
    }

end:
#ifdef IROW_DEBUG
	printf("irow_create() return %d" IROW_DEBUG_END_STR, ret);
#endif
	if(cs != NULL) {
		irow_create_state_delete(cs);
	}
	return ret;
}

static void irow_flush(BlockDriverState *bs) {
	BDRVIrowState *s = bs->opaque;

	//bdrv_flush(s->irow_meta);
	//bdrv_flush(s->irow_btmp);
	bdrv_flush(s->irow_irvd);
}

typedef struct IRowAIOCB {
    BlockDriverAIOCB common;
    int64_t sector_num;
    QEMUIOVector *qiov;
    int nb_sectors;
    BlockDriverAIOCB *irvd_aiocb;

} IRowAIOCB;

static void irow_aio_cancel(BlockDriverAIOCB *blockacb)
{
	IRowAIOCB *acb = (IRowAIOCB *)blockacb;
    if (acb->irvd_aiocb)
        bdrv_aio_cancel(acb->irvd_aiocb);
    qemu_aio_release(acb);
}

static AIOPool irow_aio_pool = {
    .aiocb_size         = sizeof(IRowAIOCB),
    .cancel             = irow_aio_cancel,
};


static IRowAIOCB *irow_aio_setup(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    IRowAIOCB *acb;

    acb = qemu_aio_get(&irow_aio_pool, bs, cb, opaque);
    if (!acb)
        return NULL;
    acb->irvd_aiocb = NULL;
    acb->sector_num = sector_num;
    acb->qiov = qiov;
    acb->nb_sectors = nb_sectors;
    return acb;
}

static void irow_aio_readv_cb(void *opaque, int ret) {
	IRowAIOCB *acb = opaque;
	BlockDriverState *bs = acb->common.bs;
	BDRVIrowState *birows = bs->opaque;
	int64_t first_cluster, last_cluster, nb_clusters, sector_index, cluster_index, buf_offset;
	ClusterBuffer cbuf;
	void *buf = NULL;
	int remain_sectors, cbuf_offset, len;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_aio_readv_cb()\n");
#endif
	if(ret < 0) {
		fprintf(stderr, "aio_readv failed\n");
		goto end;
	}
	   first_cluster = acb->sector_num / birows->sectors_per_cluster; // ��ʼcluster����
	   last_cluster = (acb->sector_num + acb->nb_sectors - 1) / birows->sectors_per_cluster; // ����cluster����

		if(first_cluster >= birows->total_clusters) { // ��ʼ��cluster�����������Χ
			fprintf (stderr, "Invalid sector_num.\n");
			ret = -1;
			goto end;
		}
		if(last_cluster >= birows->total_clusters) { // ����cluster�����������Χ
			fprintf (stderr, "Invalid nb_sectors.\n");
			ret = -1;
			goto end;
		}

		cbuf.buf = NULL;
		cbuf.read_from_father = NULL;
		if(birows->complete_image != 1) {
			// ��������
			nb_clusters = last_cluster - first_cluster + 1;
			cbuf.buf = qemu_memalign(512, nb_clusters * birows->cluster_size); // ���ڴ洢��father��ȡ������
			memset(cbuf.buf, 0, nb_clusters * birows->cluster_size);
			cbuf.read_from_father = qemu_mallocz(nb_clusters  + 1); // ���ڱ�ʾbuf���ĸ�cluster�Ǵ�father�ж�ȡ�ģ��������һ���ռ������ں����ж�����cluster����
			// ȷ�����е�cluster���ڵ�ǰ������̾�����
		   if(irow_assert_clusters(bs, &cbuf, acb->sector_num, acb->nb_sectors, IROW_AIO_READ) < 0) {
			   fprintf (stderr, "irow_assert_clusters() failed.\n");
			   ret = -1;
			   goto end;
		   }
			// ����btmp
			irow_update_btmp(birows);

		   buf = qemu_malloc(acb->qiov->size);
		   qemu_iovec_to_buffer(acb->qiov, buf);

			sector_index = acb->sector_num;
			remain_sectors = acb->nb_sectors;
			buf_offset = 0;
			while(remain_sectors > 0) {
				cluster_index = sector_index / birows->sectors_per_cluster;
				len = last_sector_in_cluster(birows, cluster_index) - sector_index + 1;
				if(len > remain_sectors)
					len = remain_sectors;
	#ifdef IROW_DEBUG_DETAIL
				printf("sector_index %" PRId64 ", cluster_index %" PRId64 ", buf_offset %" PRId64 ", len %d\n", sector_index, cluster_index, buf_offset, len);
				//dump_mem(buf, nb_sectors * BDRV_SECTOR_SIZE, "read buffer");
	#endif
	#ifdef IROW_DEBUG_READ
				printf("Press Enter to continue...\n");
				getchar();
	#endif
				if(cbuf.read_from_father[cluster_index - first_cluster] == 1) {
	#ifdef IROW_DEBUG
					printf("copying from cbuf\n");
	#endif
					cbuf_offset = (sector_index & (birows->sectors_per_cluster - 1)) + (cluster_index - first_cluster) * birows->sectors_per_cluster;
	#ifdef IROW_DEBUG_DETAIL
				printf("cbuf_offset %d\n", cbuf_offset);
	#endif
	#ifdef IROW_DEBUG_READ
				printf("Press Enter to continue...\n");
				getchar();
	#endif
					memcpy(buf + buf_offset, cbuf.buf + cbuf_offset * BDRV_SECTOR_SIZE, len * BDRV_SECTOR_SIZE);
				}
				sector_index = first_sector_in_cluster(birows, cluster_index + 1);
				remain_sectors -= len;
				buf_offset += len * BDRV_SECTOR_SIZE;
			}

			qemu_iovec_from_buffer(acb->qiov, buf, acb->qiov->size);
		}

	end:
		if(buf != NULL) {
			qemu_free(buf);
			buf = NULL;
		}
		if(cbuf.buf != NULL) {
			qemu_free(cbuf.buf);
			cbuf.buf = NULL;
		}
		if(cbuf.read_from_father != NULL) {
			qemu_free(cbuf.read_from_father);
			cbuf.read_from_father = NULL;
		}
	    acb->common.cb(acb->common.opaque, ret);
	    qemu_aio_release(acb);
#ifdef IROW_DEBUG
   printf("irow_aio_readv_cb() return" IROW_DEBUG_END_STR);
#endif
}

static BlockDriverAIOCB *irow_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque) {
    IRowAIOCB *acb;
    BDRVIrowState *birows = bs->opaque;
    BlockDriver *drv;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_aio_readv()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d\n", sector_num, nb_sectors);
#endif
#ifdef IROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef IROW_DEBUG_AIO_READV
	printf("press Enter to continue...\n");
	getchar();
#endif

    acb = irow_aio_setup(bs, sector_num, qiov, nb_sectors, cb, opaque);
    if (!acb)
        return NULL;
	// ����cluster�Ƿ�����ڵ�ǰ�����У����Ƚ����ȡ�������ٽ����ھ����е�����������
	drv = birows->irow_irvd->drv;
	acb->irvd_aiocb = drv->bdrv_aio_readv(birows->irow_irvd, sector_num, qiov, nb_sectors, irow_aio_readv_cb, acb);
	if(acb->irvd_aiocb == NULL){
		qemu_aio_release(acb);
#ifdef IROW_DEBUG
   printf("irow_aio_readv() return NULL" IROW_DEBUG_END_STR);
#endif
		return NULL;
	}


#ifdef IROW_DEBUG
   printf("irow_aio_readv() return %p" IROW_DEBUG_END_STR, &acb->common);
#endif
   return &acb->common;
}

static BlockDriverAIOCB *irow_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVIrowState *s = bs->opaque;
	int64_t first_cluster, last_cluster, current_cluster;
	ClusterBuffer cbuf;
	BlockDriver *drv;
	BlockDriverAIOCB *ret = NULL;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_aio_writev()\n");
	printf("sector_num %" PRId64 ", nb_sectors %d", sector_num, nb_sectors);
#endif
#ifdef IROW_DEBUG_DETAIL
	dump_QEMUIOVector(qiov);
#endif
#ifdef IROW_DEBUG_AIO_WRITEV
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
		if(irow_assert_clusters(bs, &cbuf, sector_num, nb_sectors, IROW_AIO_WRITE) < 0) {
			fprintf (stderr, "irow_assert_clusters() failed.\n");
			goto end;
		}
	}

	// ����bitmap����
	for(current_cluster = first_cluster; current_cluster <= last_cluster; current_cluster++) {
		//if(irow_get_bit(s, current_cluster) == 0)
			irow_set_bit(s, current_cluster);
	}

	// ͷβcluster���ڵ�ǰ������̾����У���˿���ֱ�Ӱ�sectorд��
	drv = s->irow_irvd->drv;
   ret = drv->bdrv_aio_writev(s->irow_irvd, sector_num, qiov, nb_sectors, cb, opaque );
   if(ret == NULL) {
	   goto end;
   }

	// ����btmp�ļ�
	if(irow_update_btmp(s) < 0) {
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
#ifdef IROW_DEBUG
   printf("irow_aio_writev() return %p" IROW_DEBUG_END_STR, ret);
#endif
   return ret;
}

static BlockDriverAIOCB *irow_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque) {
	BDRVIrowState *s = bs->opaque;
	BlockDriverAIOCB *ret = NULL;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_aio_flush()\n");
#endif

	ret = bdrv_aio_flush(s->irow_irvd, cb, opaque);

#ifdef IROW_DEBUG
	printf("irow_aio_flush() return %p\n" IROW_DEBUG_END_STR, ret);
#endif

	return ret;
}

static void irow_new_snapshot_id(BDRVIrowState *birows, char *id_str, int id_str_size) {
	IRowSnapshot *snap_ptr;
   uint i, id, found;

   /*for(i = 0; i < birows->nb_snapshots; i++) { // �ҵ����п�������id�����ֵ
	   snap_ptr = birows->snapshots + i;
	   if(snap_ptr->id_str != NULL) {
		   id = strtoul(snap_ptr->id_str, NULL, 10); // ��id��ת��Ϊ��Ӧ������
		   if (id > max)
			   max = id;
	   }
    }
   snprintf(id_str, id_str_size, "%d", max + 1); // ��idΪ��ǰid���ֵ��1*/
   for(id = 1; id < 0xffffffff; id++) {
	   found = 1;
	   for(i = 0; i < birows->nb_snapshots; i++) {
		   snap_ptr = birows->snapshots + i;
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

static int irow_find_snapshot_by_id(BDRVIrowState *birows, const char *id_str) {
	// ���ݿ��յ�id�ҵ���Ӧ�Ŀ��գ���������birows->snapshots�����е�����
	int i;

	for(i = 0; i < birows->nb_snapshots; i++) {
		if(birows->snapshots[i].id_str != NULL) {
			if(strcmp(birows->snapshots[i].id_str, id_str) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int irow_find_snapshot_by_name(BDRVIrowState *birows, const char *name) {
	// ���ݿ��յ�name�ҵ���Ӧ�Ŀ��գ���������birows->snapshots�����е�����
	int i;

	for(i = 0; i < birows->nb_snapshots; i++) {
		if(birows->snapshots[i].name != NULL) {
			if(strcmp(birows->snapshots[i].name, name) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static int irow_find_free_snapshot(BDRVIrowState *birows) {
	// �ҵ����еĿ��գ���������birows->snapshots�����е�����
	int i;

	for(i = 0; i < birows->nb_snapshots; i++) {
		// ��ɾ���Һ��ӿ�����Ϊ0�Ŀ���Ϊ���п���
		if(birows->snapshots[i].nb_children == 0 && birows->snapshots[i].is_deleted == 1) {
			return i;
		}
	}
	return -1;
}

static int irow_update_nb_children(BDRVIrowState *birows, IRowSnapshot *snap, int value) {
	IRowSnapshot *father_snap;
	int snap_index, ret = 0;
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_update_nb_children()\n");
#endif
#ifdef IROW_DEBUG_DETAIL
	printf("snap: %p, value: %d, btmp: %s\n", snap, value, snap->btmp_file);
#endif
	snap->nb_children += value;
	if(snap->nb_children == 0 && snap->is_deleted == 1) {
		// ����û�к��ӣ����Ѿ���ɾ��
		if(snap->father_btmp_file) {
			snap_index = irow_find_snapshot_by_btmp(birows, snap->father_btmp_file);
			if(snap_index < 0) {
				fprintf(stderr, "Failed to find father snapshot\n");
				ret = -1;
				goto end;
			}
			father_snap = birows->snapshots + snap_index;
	#ifdef IROW_DEBUG
			printf("recursive calling irow_update_nb_children...\n");
	#endif
			irow_update_nb_children(birows, father_snap, value);
		}
	}

end:
#ifdef IROW_DEBUG
	printf("irow_update_nb_children() return 0" IROW_DEBUG_END_STR);
#endif
	return ret;
}

static int irow_snapshot_add(BDRVIrowState *birows, IRowCreateState *cs, QEMUSnapshotInfo *sn_info) {
	// ��birows->snapshotsβ������һ���µ��ڴ��е�snapshot��Ϣ��IRowSnapshot��

	IRowSnapshot *new_snap, *snap;
	qemu_timeval tv;
	int snap_index;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_snapshot_add()\n");
#endif
	birows->snapshots = qemu_realloc(birows->snapshots, (birows->nb_snapshots + 1) * sizeof(IRowSnapshot));

	snap_index = irow_find_snapshot_by_btmp(birows, birows->current_btmp_file);
	if(snap_index < 0) {
		return -1;
	}
	snap = birows->snapshots + snap_index; // �ϵ�ǰ״̬�Ŀ�����Ϣ

	new_snap = birows->snapshots + birows->nb_snapshots; // �µĿ�����Ϣ
	memset(new_snap, 0, sizeof(IRowSnapshot));

	// ��Ϊ�ǽ��ϵĵ�ǰ״̬��Ϊ���գ�����sn_info�е���ϢӦ���浽�ϵĵ�ǰ״̬�Ŀ�����Ϣ��
	snap->date_sec = sn_info->date_sec;
	snap->date_nsec = sn_info->date_nsec;
	snap->vm_clock_nsec = sn_info->vm_clock_nsec;
	snap->vm_state_size = sn_info->vm_state_size;
	irow_update_nb_children(birows, snap, 1);

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

	birows->nb_snapshots += 1;
	birows_cache = qemu_realloc(birows_cache, sizeof(BDRVIrowState *) * birows->nb_snapshots);
	memset(birows_cache, 0, sizeof(BDRVIrowState *) * birows->nb_snapshots);
	birows->snapshots_is_dirty = 1;

#ifdef IROW_DEBUG
	printf("irow_snapshot_add() return 0\n" IROW_DEBUG_END_STR);
#endif
	return 0;
}

static void irow_snapshot_copy(IRowSnapshot *dst, IRowSnapshot *src) {

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

static int irow_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info) {
    // Ŀǰ���õķ������ô����ļ���ʱ����Ϊ�ļ�����һ���֣������ļ�����Ψһ��
	// �������ļ�������ֱ��
	BDRVIrowState *s = bs->opaque;
	IRowCreateState *cs = NULL;
	IRowSnapshot *free_snap, *old_snap, *snap;
	int snap_index, offset, ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_snapshot_create()\n");
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(s);
#endif
#endif

	if(sn_info->id_str[0] == '\0') { // ���û��ָ��id�����Զ�����һ��
		irow_new_snapshot_id(s, sn_info->id_str, sizeof(sn_info->id_str));
	}

	if(irow_find_snapshot_by_id(s, sn_info->id_str) >= 0) { // �ж�id�Ƿ�Ψһ
		fprintf(stderr, "Duplicated snapshot id\n");
		ret = -1;
		goto end;
	}

	if(irow_find_snapshot_by_name(s, sn_info->name) >= 0) { // �ж�name�Ƿ�Ψһ����ʵname����ҪΨһ����Ϊ�˱�����������ж�һ��
		fprintf(stderr, "Duplicated snapshot name\n");
		ret = -1;
		goto end;
	}

	cs = irow_create_state_new();
	cs->cluster_bits = s->cluster_bits;
	cs->cluster_size = s->cluster_size;
	cs->disk_size = s->disk_size;
	strncpy(cs->meta_file, s->meta_file, MAX_FILE_NAME_LENGTH);
	strncpy(cs->father_btmp_file, s->current_btmp_file, MAX_FILE_NAME_LENGTH); // ��father�ļ�Ϊ�ϵĵ�ǰ����

	snap_index = irow_find_free_snapshot(s);
#ifdef IROW_DEBUG
	printf("free snapshot index: %d\n", snap_index);
#endif
	if(snap_index >= 0) { // �ҵ����п���
		// ʹ�ÿ��п��յ�btmp��irvd�ļ�
		free_snap = s->snapshots + snap_index;
		strcpy(cs->btmp_file, free_snap->btmp_file);
		strcpy(cs->irvd_file, free_snap->irvd_file);
		// �����ڴ��еĿ�������
		old_snap = s->snapshots;
		s->snapshots = qemu_mallocz((s->nb_snapshots - 1) * sizeof(IRowSnapshot));
		offset = 0;
		for(snap_index = 0; snap_index < s->nb_snapshots; snap_index++) {
			snap = old_snap + snap_index;
#ifdef IROW_DEBUG_DETAIL
			printf("old_snap: %p, snap_index: %d, free_snap: %p, snap: %p\n", old_snap, snap_index, free_snap, snap);
			dump_snapshot(snap);
#endif
			if(snap != free_snap) {
				irow_snapshot_copy(s->snapshots + offset, snap);
				offset += 1;
			}
		}

		irow_close_snapshots2(old_snap, s->nb_snapshots);
		s->nb_snapshots -= 1;
#ifdef IROW_DEBUG_DETAIL
		printf("snapshots after delete free snapshot:\n");
		dump_snapshots(s);
#endif
	} else { // δ�ҵ����п���
		// �����µĵ�ǰbtmp��irvd�ļ�
		irow_generate_filename(cs->btmp_file, cs->meta_file, cs->time_value, "btmp"); // ������btmp�ļ���
		irow_generate_filename(cs->irvd_file, cs->meta_file, cs->time_value, "irvd"); // ������irvd�ļ���

		if(irow_create_btmp(cs) < 0) {// �����µ�bitmap�ļ�
			fprintf(stderr, "Failed to create new btmp file (%s)\n", cs->btmp_file);
			ret = -1;
			goto end;
		}

		if(irow_create_vd(cs) < 0) { // �����µ�irvd�ļ�
			fprintf(stderr, "Failed to create new irvd file (%s)\n", cs->irvd_file);
			ret = -1;
			goto end;
		}
	}

	// ���µ�snapshot��Ϣ��ӵ�birows->snapshotsβ��
	if(irow_snapshot_add(s, cs, sn_info) < 0) {
		fprintf(stderr, "Failed to add new snapshot in mem\n");
		ret = -1;
		goto end;
	}

#ifdef IROW_DEBUG_DETAIL
	printf("snapshots after irow_snapshot_add():\n");
	dump_snapshots(s);
#endif

	// ����meta�ļ�
	if(irow_update_meta(s, cs->btmp_file, 0) < 0) {
		fprintf(stderr, "Failed to update meta file (%s)\n", s->meta_file);
		ret = -1;
		goto end;
	}

	// ����btmp�ļ�����Ϊ�п���д����vm state��Ϣ��
	s->vm_state_size = sn_info->vm_state_size;
	irow_update_btmp(s);

	// �ر��ϵ�btmp��irvd
	irow_close_btmp(s);
	irow_close_irvd(s);


	// ���µ�btmp��irvd
	strncpy(s->current_btmp_file, cs->btmp_file, MAX_FILE_NAME_LENGTH);
	snap_index = irow_find_snapshot_by_btmp(s, s->current_btmp_file);
	if(irow_load_info_from_snapshot(s, snap_index) < 0) {
		ret = -1;
		goto end;
	}
	ret = irow_open_data(s, s->open_flags);
	// ���ԭ��btmp�ļ�
	memset(s->bitmap, 0, s->bitmap_size);
	s->bitmap_is_dirty = 1;
	if(irow_update_btmp(s) < 0) {
		fprintf(stderr, "Failed to update btmp file\n");
		ret = -1;
		goto end;
	}

end:
#ifdef IROW_DEBUG
	printf("BDRVIrowState after create snapshot %s\n", sn_info->name);
	printf("irow_snapshot_create() return %d" IROW_DEBUG_END_STR, ret);
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(s);
#endif
#endif

	if(cs != NULL) {
		irow_create_state_delete(cs);
		cs = NULL;
	}
	return ret;
}

static int64_t irow_vm_state_offset(BDRVIrowState *birows) {
	// vm״̬������ btmp �ļ������bitmap���棩
	return birows->bitmap_size;
}

static int irow_load_vmstate2(BDRVIrowState *birows, uint8_t *buf, int64_t pos, int size) {

	return bdrv_pread(birows->irow_btmp, irow_vm_state_offset(birows) + pos, buf, size);

}

static int irow_save_vmstate2(BDRVIrowState *birows, const uint8_t *buf, int64_t pos, int size) {
	birows->vmstate_is_saved = 1;
	return bdrv_pwrite(birows->irow_btmp, irow_vm_state_offset(birows) + pos, buf, size);

}

/*static int irow_copy_vmstate(BDRVIrowState *birows, int snapshot_index) {
	// ��snapshot_indexָ���Ŀ����н�vmstate��Ϣ���Ƶ���ǰ��btmp�ļ���

	BDRVIrowState *target_birows = NULL;
	uint8_t *buf = NULL;
	int ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_copy_vmstate()\n");
#endif

	target_birows = irow_open_previous_state(birows, snapshot_index);
	if(target_birows == NULL) {
		fprintf(stderr, "Failed to open snapshot target snapshot\n");
		ret = -1;
		goto end;
	}

	birows->vm_state_size = target_birows->vm_state_size;

	if(target_birows->vm_state_size == 0) {// û��vm״̬
		goto end;
	}

	buf = qemu_mallocz(birows->vm_state_size);

	// ��Ŀ������ж�ȡvm״̬
	if(irow_load_vmstate2(target_birows, buf, 0, birows->vm_state_size) < 0) {
		fprintf(stderr, "Failed to read vmstate from %s\n", target_birows->opened_btmp_file);
		ret = -1;
		goto end;
	}

	// д�뵱ǰbtmp�ļ���
	if(irow_save_vmstate2(birows, buf, 0, birows->vm_state_size) < 0) {
		fprintf(stderr, "Failed to write vmstate to %s\n", birows->opened_btmp_file);
		ret = -1;
		goto end;
	}

end:
#ifdef IROW_DEBUG
	printf("irow_copy_vmstate() return %d" IROW_DEBUG_END_STR, ret);
#endif
	if(target_birows != NULL) {
		irow_close_previous_state(target_birows);
		target_birows = NULL;
	}
	if(buf != NULL) {
		qemu_free(buf);
		buf = NULL;
	}
	return ret;

}*/

static int irow_snapshot_goto(BlockDriverState *bs, const char *snapshot_id) {

	BDRVIrowState *s = bs->opaque;
	IRowSnapshot *target_snap, *current_snap, *father_snap;
	int snap_index, ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_snapshot_goto()\n");
#endif

	if(strcmp(snapshot_id, "0") == 0 || strcmp(snapshot_id, "current state") == 0) {
		fprintf(stderr, "No need to goto current state.\n");
		goto end;
	}

	// �ҵ�Ŀ�����
	snap_index = irow_find_snapshot_by_id(s, snapshot_id);
	if(snap_index < 0) {
		snap_index = irow_find_snapshot_by_name(s, snapshot_id);
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

	// !!!��Ϊ�Ѿ���irow_load_vmstate()�и�Ϊ��fatherװ��vm״̬��Ϣ�����Բ�����Ҫ����vm״̬����ǰbtmp��
	// ����Ŀ�����vm״̬
	/*if(irow_copy_vmstate(s, snap_index) < 0) {
		fprintf(stderr, "Failed to copy vmstate from %s\n", target_snap->name);
		ret = -1;
		goto end;
	}*/

	// �ҵ���ǰ״̬��Ӧ�Ŀ���
	snap_index = irow_find_snapshot_by_btmp(s, s->current_btmp_file);
	if(snap_index < 0) {
		fprintf(stderr, "Failed to find current state.\n");
		ret = -1;
		goto end;
	}
	current_snap = s->snapshots + snap_index;

	// �ҵ���ǰ״̬��father����
	snap_index = irow_find_snapshot_by_btmp(s, s->father_btmp_file);
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
	irow_update_nb_children(s, father_snap, -1);
	irow_update_nb_children(s, target_snap, 1);

	current_snap->date_sec = target_snap->date_sec;
	current_snap->date_nsec = target_snap->date_nsec;
	current_snap->vm_clock_nsec = target_snap->vm_clock_nsec;
	current_snap->vm_state_size = 0;

	// ��յ�ǰ״̬��bitmap
	memset(s->bitmap, 0, s->bitmap_size);
	s->bitmap_is_dirty = 1;
	if(irow_update_btmp(s) < 0) {
		fprintf(stderr, "Failed to update btmp file\n");
		ret = -1;
		goto end;
	}
	/*// ���irvd�ļ�
	bdrv_truncate(s->irow_irvd, 0);
	bdrv_truncate(s->irow_irvd, s->disk_size);*/

	// ����meta�ļ�
	s->snapshots_is_dirty = 1;
	if(irow_update_meta(s, NULL, 0) < 0) {
		fprintf(stderr, "Failed to update meta file\n");
		ret = -1;
	}


end:
#ifdef IROW_DEBUG
	printf("irow_snapshot_goto() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_snapshot_delete(BlockDriverState *bs, const char *snapshot_id) {

	BDRVIrowState *s = bs->opaque;
	IRowSnapshot *target_snap, *father_snap;
	int snap_index, ret = 0;


#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_snapshot_delete()\n");
	printf("snapshot_id: %s\n", snapshot_id);
#ifdef IROW_DEBUG_DETAIL
	dump_BDRVIrowState(s);
#endif
#endif

	if(strcmp(snapshot_id, "0") == 0 || strcmp(snapshot_id, "current state") == 0) {
		fprintf(stderr, "Can not delete current state.\n");
		goto end;
	}

	// �ҵ�Ŀ�����
	snap_index = irow_find_snapshot_by_id(s, snapshot_id);
	if(snap_index < 0) {
		snap_index = irow_find_snapshot_by_name(s, snapshot_id);
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
			snap_index = irow_find_snapshot_by_btmp(s, target_snap->father_btmp_file);
			if(snap_index < 0) {
				fprintf(stderr, "Failed to find father snapshot\n");
				ret = -1;
				goto end;
			}
			father_snap = s->snapshots + snap_index;
			irow_update_nb_children(s, father_snap, -1);
		}
	}

#ifdef IROW_DEBUG
	printf("\ntarget snapshot index: %d, target_snap: %p\n", snap_index, target_snap);
#endif

	s->snapshots_is_dirty = 1;
	// ����meta�еĿ�����Ϣ
	irow_update_meta(s, NULL, 0);
#ifdef IROW_DEBUG_DETAIL
	printf("BDRVIrowState after delete snapshot %s\n", snapshot_id);
	dump_BDRVIrowState(s);
#endif

end:
#ifdef IROW_DEBUG
	printf("irow_snapshot_delete() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab) {

	BDRVIrowState *s = bs->opaque;
   QEMUSnapshotInfo *snap_tab, *snap_info;
   IRowSnapshot *snap;
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

static int irow_get_info(BlockDriverState *bs, BlockDriverInfo *bdi) {
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_get_info()\n");
#endif
	BDRVIrowState *s = bs->opaque;
	bdi->cluster_size = s->cluster_size;
	bdi->vm_state_offset = irow_vm_state_offset(s);
#ifdef IROW_DEBUG
	printf("return from irow_get_info()" IROW_DEBUG_END_STR);
#endif
	return 0;
}

static int irow_save_vmstate(BlockDriverState *bs, const uint8_t *buf, int64_t pos, int size) {

	BDRVIrowState *birows = bs->opaque;
	int ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_save_vmstate()\n");
	printf("vm_state_size %d, pos %" PRId64 ", size %d\n", birows->vm_state_size, pos, size);
#endif

	// savevm.c 1670��do_savevm()�У���1735���ȵ���qemu_savevm_state()����vm״̬������1750�е���bdrv_snapshot_create()
	// ����vm״̬ʱ����vm״̬��Ϣ���浽��ǰ��btmp�ļ��У���������ʱ�ϵĵ�ǰ״̬��Ϊ���ձ���
	// ���������irow_load_vmstate()��������

	ret = irow_save_vmstate2(birows, buf, pos, size);

#ifdef IROW_DEBUG
	printf("irow_save_vmstate() return %d" IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static int irow_load_vmstate(BlockDriverState *bs, uint8_t *buf, int64_t pos, int size) {

	BDRVIrowState *target_birows = NULL, *birows = bs->opaque;
	int target_index, ret = 0;

#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_load_vmstate()\n");
	printf("vm_state_size %d, pos %" PRId64 ", size %d\n", birows->vm_state_size, pos, size);
#endif
	// savevm.c 1777��load_vmstate()�У���1797���ȵ���bdrv_snapshot_goto()������״̬�ع�,Ȼ����1875�е���qemu_loadvm_state()����vm״̬
	// bdrv_snapshot_goto()���ջ����irow_snapshot_goto()��irow_snapshot_goto()�лὫĿ���������Ϊ��ǰ״̬��father
	// vm״̬�Ǳ�����Ŀ������е�,������Ҫ�ӵ�ǰ���յ�father����vm״̬

	// �ҵ���ǰ״̬��father
	target_index = irow_find_snapshot_by_btmp(birows, birows->father_btmp_file);
	if(target_index < 0) {
		ret = -1;
		goto end;
	}

	// �򿪵�ǰ״̬��father
	target_birows = irow_open_previous_state(birows, target_index);
	if(target_birows == NULL) {
		ret = -1;
		goto end;
	}

	// �ӵ�ǰ״̬��fatherװ��vm״̬
	ret = irow_load_vmstate2(target_birows, buf, pos, size);

end:
#ifdef IROW_DEBUG
	printf("irow_load_vmstate() return %d" IROW_DEBUG_END_STR, ret);
#endif
	if(target_birows != NULL) {
		irow_close_previous_state(target_birows);
		target_birows = NULL;
	}
	return ret;
}

static int irow_check(BlockDriverState *bs) {
	BDRVIrowState *birows = bs->opaque;
	char user_input[100];
	printf("current copy_on_demand state is ");
	if(birows->copy_on_demand) {
		printf("ON\n");
	} else {
		printf("OFF\n");
	}
	while(1) {
		printf("do you want to change copy_on_demand state? (y/n)");
		scanf("%s", user_input);
		user_input[0] = tolower(user_input[0]);
		if(user_input[0] == 'y') {
			birows->copy_on_demand = birows->copy_on_demand ? 0 : 1;
			irow_update_meta(birows, NULL, 1);
			break;
		}
		if(user_input[0] == 'n')
			break;
	}
	return 0;
}

static int64_t irow_get_length(BlockDriverState *bs) {
#ifdef IROW_DEBUG
	printf(IROW_DEBUG_BEGIN_STR "We are in irow_get_lenght()\n");
#endif
	BDRVIrowState *birows = bs->opaque;
	int64_t ret;
	ret = birows->disk_size;
#ifdef IROW_DEBUG
	printf("irow_get_lenght() return %" PRId64 IROW_DEBUG_END_STR, ret);
#endif
	return ret;
}

static QEMUOptionParameter irow_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_CLUSTER_SIZE,
        .type = OPT_SIZE,
        .help = "irow cluster size"
    },
    {
        .name = BLOCK_OPT_BACKING_FILE,
        .type = OPT_STRING,
        .help = "File name of a base image"
    },
    {
        .name = "copy_on_demand",
        .type = OPT_FLAG,
        .help = "copy clusters to current irvd when needed"
    },
    { NULL }
};

static BlockDriver bdrv_irow = {
    .format_name	= "irow",
    .instance_size	= sizeof(BDRVIrowState),
    .bdrv_probe		= irow_probe,
    .bdrv_open		= irow_open,
    .bdrv_read		= irow_read,
    .bdrv_write		= irow_write,
    .bdrv_close		= irow_close,
    .bdrv_create	= irow_create,
    .bdrv_flush		= irow_flush,

    .bdrv_aio_readv		= irow_aio_readv,
    .bdrv_aio_writev	= irow_aio_writev,
    .bdrv_aio_flush		= irow_aio_flush,

    .bdrv_snapshot_create   = irow_snapshot_create,
    .bdrv_snapshot_goto     = irow_snapshot_goto,
    .bdrv_snapshot_delete   = irow_snapshot_delete,
    .bdrv_snapshot_list     = irow_snapshot_list,

    .bdrv_get_info	= irow_get_info,
    .bdrv_getlength = irow_get_length,

    .bdrv_save_vmstate    = irow_save_vmstate,
    .bdrv_load_vmstate    = irow_load_vmstate,

    .create_options = irow_create_options,
    .bdrv_check = irow_check,
};

static void bdrv_irow_init(void)
{
    bdrv_register(&bdrv_irow);
}

block_init(bdrv_irow_init);
