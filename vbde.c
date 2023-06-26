#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>
#include <linux/blk-mq.h>

#define MIB_SECTORS	(1 << (20 - SECTOR_SHIFT))
#define DEVICE_NAME	"vbde"

struct vbde {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	u8                      *data;
	struct gendisk          *disk;
	struct blk_mq_tag_set   *tag_set;
};

static struct vbde      __vbde;
static int              __vbde_major = 0;
static unsigned long    __vbde_capacity_mib = 64;
static unsigned char	__lld_name[256];
static unsigned char	__store_in_ram = 0;

static struct block_device *__lld;

void request_finished(struct bio *bio)
{
	bio_uninit(bio);
	kfree(bio);
}

static sector_t vbde_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	void *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	pr_debug("transferring %4u bytes...\n", bvec->bv_len);

	if (pos + len > __vbde.capacity)
		len = __vbde.capacity - pos;

	offset = pos << SECTOR_SHIFT;
	nbytes = len << SECTOR_SHIFT;

	spin_lock(&__vbde.datalock);

	if (__store_in_ram) {
		pr_debug("Using RAM\n");
		if (dir)
			memcpy(__vbde.data + offset, buff, nbytes);
		else
			memcpy(buff, __vbde.data + offset, nbytes);
	} else {
		pr_debug("Using backing device\n");
		struct bio *bio = bio_kmalloc(1, GFP_KERNEL);
		struct bio_vec *vec = vzalloc(sizeof(struct bio_vec));
		memcpy(vec, bvec, sizeof(struct bio_vec));
		bio_init(bio, __lld, vec, 1, dir ? REQ_OP_WRITE : REQ_OP_READ);
		bio->bi_end_io = &request_finished;
		submit_bio(bio);
	}

	spin_unlock(&__vbde.datalock);

	pr_debug("pos #%6llu len #%4llu %s\n", pos, len, dir ? "w" : "r");
	pr_debug("offset #%6llu nbytes #%4llu\n", offset, nbytes);

	return len;
}

static void vbde_xfer_rq(struct request *rq)
{
	struct req_iterator iter;
	struct bio_vec bvec;
	int dir = rq_data_dir(rq);
	sector_t pos = blk_rq_pos(rq);

	pr_debug("xfer_rq\n");

	rq_for_each_segment(bvec, rq, iter)
		pos += vbde_xfer(&bvec, pos, dir);
}

static blk_status_t vbde_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_queue_data const *bd)
{
	pr_debug("queue_rq\n");

	if (atomic_read(&__vbde.deleting))
		return BLK_STS_IOERR;

	atomic_inc(&__vbde.refs_cnt);

	blk_mq_start_request(bd->rq);
	vbde_xfer_rq(bd->rq);
	blk_mq_end_request(bd->rq, BLK_STS_OK);

	if (atomic_dec_and_test(&__vbde.refs_cnt))
		wake_up(&__vbde.exitwait);

	return BLK_STS_OK;
}

static struct blk_mq_ops const __vbde_blk_mq_ops = {
	.queue_rq = vbde_queue_rq,
};

static struct block_device_operations const __vbde_bdev_ops = {
	.owner = THIS_MODULE,
};

static int vbde_create(void)
{
	int ret = 0;

	pr_info("registering blkdev...\n");

	__vbde_major = register_blkdev(0, DEVICE_NAME);
	if (__vbde_major < 0) {
		pr_err("register_blkdev() failed with %d\n", __vbde_major);
		return -EBUSY;
	}

	memset(&__vbde, 0, sizeof(struct vbde));
	__vbde.capacity = (sector_t)__vbde_capacity_mib * MIB_SECTORS;

	if (__store_in_ram) {
		pr_info("allocating space in RAM...\n");
		__vbde.data = vzalloc(__vbde.capacity << SECTOR_SHIFT);
		if (!__vbde.data) {
			pr_err("unable to alloc data\n");
			return -ENOMEM;
		}
	}

	spin_lock_init(&__vbde.datalock);
	init_waitqueue_head(&__vbde.exitwait);

	pr_info("allocating tag_set...\n");
	__vbde.tag_set = kzalloc(sizeof(struct blk_mq_tag_set), GFP_KERNEL);
	if (!__vbde.tag_set) {
		pr_err("unable to alloc tag_set\n");
		return -ENOMEM;
	}

	__vbde.tag_set->ops = &__vbde_blk_mq_ops;
	__vbde.tag_set->nr_hw_queues = 1;
	__vbde.tag_set->nr_maps = 1;
	__vbde.tag_set->queue_depth = 128;
	__vbde.tag_set->numa_node = NUMA_NO_NODE;
	__vbde.tag_set->flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING;
	__vbde.tag_set->cmd_size = 0;
	__vbde.tag_set->driver_data = &__vbde;

	ret = blk_mq_alloc_tag_set(__vbde.tag_set);
	if (ret) {
		pr_err("blk_mq_alloc_tag_set() failed with %d\n", ret);
		return ret;
	}

	pr_info("allocating disk...\n");
	__vbde.disk = blk_mq_alloc_disk(__vbde.tag_set, &__vbde);
	if (__vbde.disk == NULL) {
		pr_err("blk_alloc_disk() failed\n");
		return -EINVAL;
	}

	__vbde.disk->major = __vbde_major;
	__vbde.disk->first_minor = 0;
	__vbde.disk->minors = 1;
	__vbde.disk->fops = &__vbde_bdev_ops;
	__vbde.disk->private_data = &__vbde;

	scnprintf(__vbde.disk->disk_name, DISK_NAME_LEN, DEVICE_NAME);
	set_capacity(__vbde.disk, __vbde.capacity);
	blk_queue_logical_block_size(__vbde.disk->queue, SECTOR_SIZE);
	blk_queue_physical_block_size(__vbde.disk->queue, SECTOR_SIZE);

	pr_info("adding disk...\n");
	ret = add_disk(__vbde.disk);

	return ret;
}

static void vbde_delete(void)
{
	atomic_set(&__vbde.deleting, 1);

	wait_event(__vbde.exitwait, !atomic_read(&__vbde.refs_cnt));

	/* disk will be removed only after the last reference put */
	if (__vbde.disk) {
		pr_info("deleting disk...\n");
		del_gendisk(__vbde.disk);
		pr_info("cleaning up disk...\n");
		put_disk(__vbde.disk);
	}

	if (__vbde.tag_set && __vbde.tag_set->tags) {
		pr_info("freeing tag_set...\n");
		blk_mq_free_tag_set(__vbde.tag_set);
	}

	if (__vbde.tag_set)
		kfree(__vbde.tag_set);

	if (__vbde.data) {
		pr_info("freeing data...\n");
		vfree(__vbde.data);
	}

	memset(&__vbde, 0, sizeof(struct vbde));

	if (__vbde_major > 0) {
		pr_info("unregistering blkdev...\n");
		unregister_blkdev(__vbde_major, DEVICE_NAME);
		__vbde_major = 0;
	}
}

static int __init vbde_init(void)
{
	int ret = 0;

	pr_info("init...\n");

	if (strlen(__lld_name)) {
		pr_info("User want back up to %s\n", __lld_name);
		__lld = blkdev_get_by_path(__lld_name, FMODE_READ |
				FMODE_WRITE, THIS_MODULE);
		if (IS_ERR(__lld)) {
			pr_err("Target device is not available!\n");
			goto store_in_ram;
		} else {
			sector_t capacity = get_capacity(__lld->bd_disk);
			pr_info("capacity: %d sectors\n", capacity);
			pr_info("sector size: %d bytes\n", SECTOR_SIZE);
			__vbde_capacity_mib = (capacity << SECTOR_SHIFT)
				>> 20;
		}
	} else {
store_in_ram:
		__store_in_ram = 1;
		pr_info("Data will stored in RAM\n");
	}

	ret = vbde_create();

	if (ret) {
		pr_err("init err\n");
		vbde_delete();
	} else {
		pr_info("init ok\n");
	}

	return ret;
}

static void __exit vbde_exit(void)
{
	pr_info("exit...\n");
	vbde_delete();
	if (!__store_in_ram) {
		pr_info("releasing backing device...\n");
		blkdev_put(__lld, FMODE_READ | FMODE_WRITE);
	}
	pr_info("exit ok\n");
}

module_init(vbde_init);
module_exit(vbde_exit);

module_param_named(capacity, __vbde_capacity_mib, ulong, S_IRUGO);
module_param_string(lld, __lld_name, sizeof(__lld_name), S_IRUGO);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual Block Device Example");
