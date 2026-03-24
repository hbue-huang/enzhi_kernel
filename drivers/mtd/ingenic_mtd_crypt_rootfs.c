/*
 * mtd-crypt-linux310_hardware.c - Linux 3.10 MTD decryption boot support (AES-ECB/CBC Hardware Accelerated)
 * Fixed for Ingenic hardware acceleration with DMA buffer handling
 * No key needed - uses pre-configured hardware key from eFuse
 * Supports both ECB and CBC modes with IV in file header for CBC
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mtd/mtd.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/root_dev.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/bio.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <crypto/internal/skcipher.h>
#include <linux/types.h>

extern bool is_mtd_crypt_mode;
/* ========== Asynchronous decryption context ========== */
struct mtdcrypt_async_ctx {
	struct completion done;
	int err;
};

/* ========== Configuration structure ========== */
struct mtd_crypt_config {
	char mtd_name[32];
	int enabled;
	u64 mtd_size;
	int force_sw;
	int debug_level;
	int use_cbc;
	u8 iv[16];
};

struct mtd_crypt_config mtd_crypt_cfg = {
	.mtd_name = {0},
	.enabled = 0,
	.mtd_size = 0,
	.force_sw = 0,
	.debug_level = 1,
#ifdef CONFIG_INGENIC_MTD_CRYPTO_ROOTFS_MODE_CBC
	.use_cbc = 1,
#else
	.use_cbc = 0,
#endif
	.iv = {0}
};
EXPORT_SYMBOL(mtd_crypt_cfg);

/* ========== Ramdisk variables ========== */
static int mtdcrypt_major_num = 0;
static struct gendisk *mtdcrypt_ramdisk = NULL;
static struct request_queue *mtdcrypt_queue = NULL;
static unsigned char *mtdcrypt_ram_data = NULL;
static size_t mtdcrypt_ram_size = 0;

/* ========== Encryption variables ========== */
static struct crypto_ablkcipher *aes_tfm = NULL;
static struct mtd_info *mtd_device = NULL;

/* ========== Block device operations ========== */
static const struct block_device_operations mtdcrypt_fops = {
	.owner = THIS_MODULE,
};

/* ========== Completion callback ========== */
static void mtdcrypt_complete(struct crypto_async_request *req, int err)
{
	struct mtdcrypt_async_ctx *ctx = req->data;
	ctx->err = err;
	complete(&ctx->done);
}

/* ========== Ramdisk request handler ========== */
static void mtdcrypt_make_request(struct request_queue *q, struct bio *bio)
{
	int rw = bio_data_dir(bio);
	char *buffer = bio_data(bio);
	sector_t sector = bio->bi_sector;
	unsigned int nsectors = bio->bi_size >> 9;
	unsigned int offset = sector * 512;
	unsigned int size = nsectors * 512;

	if (offset + size > mtdcrypt_ram_size) {
		bio_endio(bio, -EIO);
		return;
	}

	if (rw == WRITE) {
		memcpy(mtdcrypt_ram_data + offset, buffer, size);
	} else {
		memcpy(buffer, mtdcrypt_ram_data + offset, size);
	}

	bio_endio(bio, 0);
}

/* ========== Create ramdisk device ========== */
static int create_mtdcrypt_ramdisk(void *data, size_t size)
{
	int ret;

	if (!data || size == 0) {
		printk(KERN_ERR "MTDCRYPT: Invalid ramdisk data\n");
		return -EINVAL;
	}

	mtdcrypt_ram_data = (unsigned char *)data;
	mtdcrypt_ram_size = size;

	mtdcrypt_major_num = register_blkdev(0, "mtdcrypt_ram");
	if (mtdcrypt_major_num < 0) {
		printk(KERN_ERR "MTDCRYPT: Failed to register block device: %d\n", mtdcrypt_major_num);
		return mtdcrypt_major_num;
	}

	mtdcrypt_queue = blk_alloc_queue(GFP_KERNEL);
	if (!mtdcrypt_queue) {
		printk(KERN_ERR "MTDCRYPT: Failed to create request queue\n");
		ret = -ENOMEM;
		goto unregister_blkdev;
	}

	blk_queue_make_request(mtdcrypt_queue, mtdcrypt_make_request);
	blk_queue_logical_block_size(mtdcrypt_queue, 512);
	blk_queue_max_hw_sectors(mtdcrypt_queue, 1024);

	mtdcrypt_ramdisk = alloc_disk(1);
	if (!mtdcrypt_ramdisk) {
		printk(KERN_ERR "MTDCRYPT: Failed to create device\n");
		ret = -ENOMEM;
		goto cleanup_queue;
	}

	mtdcrypt_ramdisk->major = mtdcrypt_major_num;
	mtdcrypt_ramdisk->first_minor = 0;
	mtdcrypt_ramdisk->minors = 1;
	mtdcrypt_ramdisk->fops = &mtdcrypt_fops;
	mtdcrypt_ramdisk->queue = mtdcrypt_queue;
	mtdcrypt_ramdisk->private_data = NULL;

	sprintf(mtdcrypt_ramdisk->disk_name, "mtdcrypt_ram");
	set_capacity(mtdcrypt_ramdisk, size / 512);
	add_disk(mtdcrypt_ramdisk);

	return 0;

cleanup_queue:
	if (mtdcrypt_queue) {
		blk_cleanup_queue(mtdcrypt_queue);
		mtdcrypt_queue = NULL;
	}

unregister_blkdev:
	if (mtdcrypt_major_num > 0) {
		unregister_blkdev(mtdcrypt_major_num, "mtdcrypt_ram");
		mtdcrypt_major_num = 0;
	}

	return ret;
}

/* ========== Asynchronous decryption function (ECB/CBC) ========== */
static int decrypt_aes_async(const u8 *cipher, u8 *plain, size_t len, u8 *iv)
{
	struct scatterlist sg_in, sg_out;
	struct ablkcipher_request *req;
	struct mtdcrypt_async_ctx ctx;
	int ret;

	if (!aes_tfm) {
		printk(KERN_ERR "MTDCRYPT: AES transform not initialized\n");
		return -EINVAL;
	}

	/* Verify length is multiple of AES block size (16 bytes) */
	if (len % 16 != 0) {
		printk(KERN_ERR "MTDCRYPT: Data length %zu not multiple of AES block size (16)\n", len);
		return -EINVAL;
	}

	/* Allocate async request */
	req = ablkcipher_request_alloc(aes_tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "MTDCRYPT: Failed to allocate ablkcipher request\n");
		return -ENOMEM;
	}

	init_completion(&ctx.done);
	ctx.err = -EINPROGRESS;

	/* Setup scatterlist - note DMA mapping usage */
	sg_init_one(&sg_in, cipher, len);
	sg_init_one(&sg_out, plain, len);

	/* Map DMA buffers */
	sg_dma_address(&sg_in) = dma_map_single(NULL, (void *)cipher, len, DMA_TO_DEVICE);
	sg_dma_address(&sg_out) = dma_map_single(NULL, plain, len, DMA_FROM_DEVICE);
	sg_dma_len(&sg_in) = len;
	sg_dma_len(&sg_out) = len;

	/* Setup async request */
	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP,
			mtdcrypt_complete, &ctx);

	/* Setup async request with IV for CBC mode */
	if (mtd_crypt_cfg.use_cbc && iv) {
		ablkcipher_request_set_crypt(req, &sg_in, &sg_out, len, iv);
	} else {
		ablkcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);
	}

	ret = crypto_ablkcipher_decrypt(req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx.done);
		ret = ctx.err;
	}

	/* Unmap DMA buffers */
	dma_unmap_single(NULL, sg_dma_address(&sg_in), len, DMA_TO_DEVICE);
	dma_unmap_single(NULL, sg_dma_address(&sg_out), len, DMA_FROM_DEVICE);

	ablkcipher_request_free(req);

	return ret;
}

/* ========== Crypto initialization ========== */
static int init_crypto(void)
{
	struct crypto_ablkcipher *tfm;
	const char *alg_name;

	/* Select algorithm based on mode */
	if (mtd_crypt_cfg.use_cbc) {
		alg_name = "cbc-aes-ingenic";
	} else {
		alg_name = "ecb-aes-ingenic";
	}

	/* Try hardware acceleration first */
	if (!mtd_crypt_cfg.force_sw) {
		tfm = crypto_alloc_ablkcipher(alg_name, 0, 0);

		if (!IS_ERR(tfm)) {
			/*
			 * Key is already configured in hardware via eFuse,
			 * so we don't need to set it here
			 */
			aes_tfm = tfm;
			printk(KERN_INFO "MTDCRYPT: Hardware AES acceleration enabled (%s, key from eFuse)\n",
				mtd_crypt_cfg.use_cbc ? "CBC" : "ECB");
			return 0;
		}
		printk(KERN_ERR "MTDCRYPT: Hardware AES not available: %ld\n", PTR_ERR(tfm));
	}

	/* Fallback to software implementation - not supported without key */
	printk(KERN_ERR "MTDCRYPT: Software AES not supported when using eFuse key\n");
	printk(KERN_ERR "MTDCRYPT: Hardware acceleration is required\n");
	return -ENOTSUPP;
}

/* ========== Kernel parameter parsing ========== */
static int __init mtdcrypt_setup(char *str)
{
	char *dev;
	char *sw_flag;
	char *debug_str;

	dev = str;

	/* Parse optional parameters */
	sw_flag = strchr(str, ',');
	if (sw_flag) {
		*sw_flag++ = '\0';

		debug_str = strchr(sw_flag, ',');
		if (debug_str) {
			*debug_str++ = '\0';
			if (kstrtoint(debug_str, 10, &mtd_crypt_cfg.debug_level)) {
				mtd_crypt_cfg.debug_level = 1;
			}
		}

		if (strcmp(sw_flag, "sw") == 0) {
			mtd_crypt_cfg.force_sw = 1;
			printk(KERN_WARNING "MTDCRYPT: Software mode forced (may not work with eFuse key)\n");
		}
	}

	strlcpy(mtd_crypt_cfg.mtd_name, dev, sizeof(mtd_crypt_cfg.mtd_name));
	mtd_crypt_cfg.enabled = 1;
	printk(KERN_INFO "MTDCRYPT: Enabled for device %s (mode: %s, using eFuse key)\n",
		dev, mtd_crypt_cfg.use_cbc ? "CBC" : "ECB");

	return 1;
}
__setup("mtdcrypt=", mtdcrypt_setup);

/* ========== MTD device acquisition ========== */
static int get_mtd_crypt_device(void)
{
	int i, retry;

	if (!mtd_crypt_cfg.enabled)
		return -ENODEV;

	for (retry = 0; retry < 5; retry++) {
		const char *test_names[] = {
			mtd_crypt_cfg.mtd_name,
			"mtd2",
			"mtdblock2",
			"root",
			NULL
		};

		for (i = 0; test_names[i]; i++) {
			mtd_device = get_mtd_device_nm(test_names[i]);
			if (!IS_ERR(mtd_device)) {
				mtd_crypt_cfg.mtd_size = mtd_device->size;
				printk(KERN_INFO "MTDCRYPT: Found MTD device: %s, size: %llu bytes\n",
						test_names[i], mtd_crypt_cfg.mtd_size);
				return 0;
			}
		}

		if (retry < 4) {
			msleep(200);
		}
	}

	printk(KERN_ERR "MTDCRYPT: Failed to find MTD device\n");
	return -ENODEV;
}

/* ========== Stream decryption function (ECB/CBC) ========== */
static void *decrypt_mtd_to_memory(void)
{
	u8 *plain_buf = NULL;
	u8 *cipher_chunk = NULL;
	dma_addr_t cipher_dma_handle;
	size_t total_size;
	size_t data_offset = 0;
	size_t read_offset = 0;
	size_t actual_data_size = 0;
	size_t data_start_offset = 0;
	off_t offset;
	int ret;
	int i;
	u8 header[20];  /* 4 bytes size + 16 bytes IV */

	if (!mtd_device)
		return NULL;

	total_size = mtd_device->size;

	is_mtd_crypt_mode = 1;

	/* Read header: [4B size] (CBC mode also has [16B IV]) */
	if (mtd_crypt_cfg.use_cbc) {
		/* CBC mode: [4B size][16B IV] = 20 bytes header */
		size_t retlen;
		ret = mtd_read(mtd_device, 0, 20, &retlen, header);
		if (ret || retlen != 20) {
			printk(KERN_ERR "MTDCRYPT: Failed to read header from MTD device, ret=%d, retlen=%zu\n",
				ret, retlen);
			goto error_exit;
		}

		/* Parse 4-byte big-endian size */
		actual_data_size = ((size_t)header[0] << 24) |
		                   ((size_t)header[1] << 16) |
		                   ((size_t)header[2] << 8) |
		                   ((size_t)header[3]);

		/* Copy IV from offset 4-19 */
		memcpy(mtd_crypt_cfg.iv, header + 4, 16);

		/* Validate size */
		if (actual_data_size == 0) {
			printk(KERN_ERR "MTDCRYPT: Invalid data size in header: 0\n");
			goto error_exit;
		}
		if (actual_data_size > total_size - 20) {
			printk(KERN_ERR "MTDCRYPT: Invalid data size in header: %zu > max possible: %zu\n",
				actual_data_size, total_size - 20);
			goto error_exit;
		}

		/* Adjust offsets: skip 20 bytes header (4B size + 16B IV) */
		read_offset = 20;
		total_size = actual_data_size;
		data_start_offset = 0;
	} else {
		/* ECB mode: [4B size] = 4 bytes header */
		size_t retlen;
		u8 ecb_header[4];
		ret = mtd_read(mtd_device, 0, 4, &retlen, ecb_header);
		if (ret || retlen != 4) {
			printk(KERN_ERR "MTDCRYPT: Failed to read header from MTD device, ret=%d, retlen=%zu\n",
				ret, retlen);
			goto error_exit;
		}

		/* Parse 4-byte big-endian size */
		actual_data_size = ((size_t)ecb_header[0] << 24) |
		                   ((size_t)ecb_header[1] << 16) |
		                   ((size_t)ecb_header[2] << 8) |
		                   ((size_t)ecb_header[3]);

		/* Validate size */
		if (actual_data_size == 0) {
			printk(KERN_ERR "MTDCRYPT: Invalid data size in header: 0\n");
			goto error_exit;
		}
		if (actual_data_size > total_size - 4) {
			printk(KERN_ERR "MTDCRYPT: Invalid data size in header: %zu > max possible: %zu\n",
				actual_data_size, total_size - 4);
			goto error_exit;
		}

		/* Adjust offsets: skip 4 bytes header */
		read_offset = 4;
		total_size = actual_data_size;
		data_start_offset = 0;
	}

	/* Ensure size is multiple of AES block size */
	if (total_size % 16 != 0) {
		size_t aligned_size = total_size - (total_size % 16);
		total_size = aligned_size;
	}

	plain_buf = vmalloc(total_size);
	if (!plain_buf) {
		printk(KERN_ERR "MTDCRYPT: Failed to allocate memory\n");
		goto error_exit;
	}

	/* Allocate DMA buffer - required for hardware encryption */
	cipher_chunk = dma_alloc_coherent(NULL, 4096, &cipher_dma_handle, GFP_KERNEL | GFP_DMA);
	if (!cipher_chunk) {
		printk(KERN_ERR "MTDCRYPT: Failed to allocate DMA buffer\n");
		goto error_exit;
	}

	for (offset = read_offset; offset < mtd_device->size && data_offset < total_size; offset += 4096) {
		size_t chunk = mtd_device->size - offset;
		size_t retlen;
		size_t remaining = total_size - data_offset;

		if (chunk > 4096)
			chunk = 4096;

		/* Don't read more than we need to decrypt */
		if (chunk > remaining)
			chunk = remaining;

		/* Ensure chunk is 16-byte aligned */
		chunk = chunk - (chunk % 16);
		if (chunk == 0)
			continue;

		ret = mtd_read(mtd_device, offset, chunk, &retlen, cipher_chunk);
		if (ret) {
			printk(KERN_ERR "MTDCRYPT: Read error at offset %llu, ret=%d\n",
					(unsigned long long)offset, ret);
			goto error;
		}

		if (retlen != chunk) {
			printk(KERN_WARNING "MTDCRYPT: Short read at offset %llu, requested=%zu, got=%zu\n",
					(unsigned long long)offset, chunk, retlen);
			chunk = retlen;
		}

		/* Ensure alignment again and don't exceed remaining */
		chunk = chunk - (chunk % 16);
		if (chunk > remaining)
			chunk = remaining;
		if (chunk == 0)
			continue;

		/* For CBC mode, pass IV (each 4K block uses the same IV) */
		if (mtd_crypt_cfg.use_cbc) {
			/*
			 * Each 4K chunk uses the same IV from file header.
			 * No CBC chaining between chunks - each chunk is independent.
			 */
			ret = decrypt_aes_async(cipher_chunk, plain_buf + data_offset, chunk, mtd_crypt_cfg.iv);
			if (ret) {
				printk(KERN_ERR "MTDCRYPT: Decryption error at offset %llu, ret=%d\n",
						(unsigned long long)offset, ret);
				goto error;
			}
			/* Note: IV is NOT updated - all chunks use the same IV */
		} else {
			ret = decrypt_aes_async(cipher_chunk, plain_buf + data_offset, chunk, NULL);
			if (ret) {
				printk(KERN_ERR "MTDCRYPT: Decryption error at offset %llu, ret=%d\n",
						(unsigned long long)offset, ret);
				goto error;
			}
		}

		data_offset += chunk;
	}

	/* Free DMA buffer */
	dma_free_coherent(NULL, 4096, cipher_chunk, cipher_dma_handle);
	is_mtd_crypt_mode = 0;

	/* Store the actual decrypted size for later use */
	mtd_crypt_cfg.mtd_size = data_offset;

	return plain_buf;

error:
	if (cipher_chunk)
		dma_free_coherent(NULL, 4096, cipher_chunk, cipher_dma_handle);
	if (plain_buf)
		vfree(plain_buf);

error_exit:
	is_mtd_crypt_mode = 0;
	printk(KERN_ERR "MTDCRYPT: Decryption failed\n");

	return NULL;
}

/* ========== Cleanup function ========== */
static void cleanup_resources(void)
{
	if (mtdcrypt_ramdisk) {
		del_gendisk(mtdcrypt_ramdisk);
		put_disk(mtdcrypt_ramdisk);
		mtdcrypt_ramdisk = NULL;
	}

	if (mtdcrypt_queue) {
		blk_cleanup_queue(mtdcrypt_queue);
		mtdcrypt_queue = NULL;
	}

	if (mtdcrypt_major_num > 0) {
		unregister_blkdev(mtdcrypt_major_num, "mtdcrypt_ram");
		mtdcrypt_major_num = 0;
	}

	if (mtd_device) {
		put_mtd_device(mtd_device);
		mtd_device = NULL;
	}

	if (aes_tfm) {
		crypto_free_ablkcipher(aes_tfm);
		aes_tfm = NULL;
	}
}

/* ========== Root filesystem setup ========== */
static int __init setup_decrypted_root(void)
{
	void *decrypted_data = NULL;
	int ret;

	if (!mtd_crypt_cfg.enabled) {
		printk(KERN_INFO "MTDCRYPT: Decryption not enabled\n");
		return 0;
	}

	printk(KERN_INFO "MTDCRYPT: Starting decryption using hardware AES with eFuse key...\n");

	/* Initialize cryptography */
	ret = init_crypto();
	if (ret != 0) {
		printk(KERN_ERR "MTDCRYPT: Crypto init failed\n");
		goto cleanup;
	}

	/* Get MTD device */
	ret = get_mtd_crypt_device();
	if (ret != 0) {
		printk(KERN_ERR "MTDCRYPT: No MTD device found\n");
		goto cleanup;
	}

	/* Decrypt data */
	decrypted_data = decrypt_mtd_to_memory();
	if (!decrypted_data) {
		printk(KERN_ERR "MTDCRYPT: Decryption failed\n");
		ret = -EIO;
		goto cleanup;
	}

	/* Create ramdisk from decrypted data */
	/* decrypt_mtd_to_memory() has already set mtd_crypt_cfg.mtd_size to actual decrypted size */
	printk(KERN_INFO "MTDCRYPT: Creating ramdisk with size=%llu bytes\n",
		(unsigned long long)mtd_crypt_cfg.mtd_size);

	ret = create_mtdcrypt_ramdisk(decrypted_data, mtd_crypt_cfg.mtd_size);
	if (ret) {
		printk(KERN_ERR "MTDCRYPT: Failed to create ramdisk\n");
		vfree(decrypted_data);
		goto cleanup;
	}

	if (mtdcrypt_ramdisk) {
		/* Set root device */
		ROOT_DEV = MKDEV(mtdcrypt_major_num, 0);

		printk(KERN_INFO "MTDCRYPT: Root device set to /dev/%s\n",
				mtdcrypt_ramdisk->disk_name);
		return 0;
	}

	ret = -EINVAL;

cleanup:
	printk(KERN_ERR "MTDCRYPT: Decryption failed\n");
	cleanup_resources();
	return ret;
}

/* ========== Execute before root filesystem mount ========== */
late_initcall(setup_decrypted_root);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux 3.10 MTD decryption boot support with AES-ECB/CBC (Hardware Accelerated with eFuse key)");
MODULE_AUTHOR("jz.zshi");
MODULE_VERSION("1.2");
