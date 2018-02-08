/*
 * Copyright (C) 2018 Tim Schlueter <schlueter.tim@linux.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 *
 * Based on code fragments from bcachefs-tools by Kent Overstreet:
 * http://evilpiepirate.org/git/bcachefs-tools.git
 */

#include <stddef.h>
#include <stdio.h>

#include "superblocks.h"

#define SB_LABEL_SIZE     32
#define SB_UUID_SIZE      16
#define SB_VERSION_MIN     7

static const char bcachefs_magic[] = {
	0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

/* magic string */
#define BCACHEFS_MAGIC     bcachefs_magic
/* magic string len */
#define BCACHEFS_MAGIC_LEN sizeof(bcachefs_magic)
/* super block offset */
#define BCACHEFS_SB_SECTOR_1   8
#define BCACHEFS_SB_SECTOR_2  88
/* super block offset in kB */
#define BCACHEFS_SB_KBOFF_1   (BCACHEFS_SB_SECTOR_1 >> 1)
#define BCACHEFS_SB_KBOFF_2   (BCACHEFS_SB_SECTOR_2 >> 1)
/* magic string offset within super block */
#define BCACHEFS_SB_MAGIC_OFF offsetof(struct bcachefs_super_block, magic)
/* the smallest bcachefs filesystem allowed (1024 blocks, 512 bytes each) */
#define BCACHEFS_MIN_SIZE (1024 * 512)

struct bch_sb_layout {
	uint8_t			magic[BCACHEFS_MAGIC_LEN];
	uint8_t			layout_type;
	uint8_t			sb_max_size_bits;
	uint8_t			nr_superblocks;
	uint8_t			pad[5];
	uint64_t		sb_offset[61];
} __attribute__((packed, aligned(8)));

struct bch_csum {
	uint64_t		lo;
	uint64_t		hi;
} __attribute__((packed, aligned(8)));

struct bcachefs_super_block {
	struct bch_csum		csum;
	uint64_t		version;
	uint8_t			magic[BCACHEFS_MAGIC_LEN];
	uint8_t			uuid[SB_UUID_SIZE];
	uint8_t			user_uuid[SB_UUID_SIZE];
	uint8_t			label[SB_LABEL_SIZE];
	uint64_t		offset;
	uint64_t		seq;

	uint16_t		block_size;
	uint8_t			dev_idx;
	uint8_t			nr_devices;
	uint32_t		u64s;

	uint64_t		time_base_lo;
	uint32_t		time_base_hi;
	uint32_t		time_precision;

	uint64_t		flags[8];
	uint64_t		features[2];
	uint64_t		compat[2];

	struct bch_sb_layout	layout;

	/* There's more, but it's not really necessary for libblkid */

} __attribute__((packed, aligned(8)));


static int is_zero(const void *_p, size_t n)
{
        const char *p = _p;
        size_t i;

        for (i = 0; i < n; i++) {
                if (p[i])
                        return 0;
	}

        return 1;
}

static int probe_bcachefs(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct bcachefs_super_block *bcfs;
	int rc = 0;

	bcfs = blkid_probe_get_sb(pr, mag, struct bcachefs_super_block);
	if (!bcfs)
		return errno ? -errno : BLKID_PROBE_NONE;

	if (le64_to_cpu(bcfs->offset) != BCACHEFS_SB_SECTOR_1
	    && le64_to_cpu(bcfs->offset) != BCACHEFS_SB_SECTOR_2)
		return BLKID_PROBE_NONE;

	if (le32_to_cpu(bcfs->version) < SB_VERSION_MIN)
		return BLKID_PROBE_NONE;

        if (is_zero(bcfs->user_uuid, sizeof(bcfs->user_uuid)))
		return BLKID_PROBE_NONE;

	// TODO: Verify superblock checksum? More sanity checks?

	if (*bcfs->label) {
		rc = blkid_probe_set_label(pr,
				(unsigned char *) bcfs->label,
				sizeof(bcfs->label));
		if (rc < 0)
			return BLKID_PROBE_NONE;
	}

	rc = blkid_probe_set_uuid(pr, bcfs->user_uuid);
	if (rc < 0)
		return BLKID_PROBE_NONE;

	rc = blkid_probe_sprintf_version(pr, "%u", le32_to_cpu(bcfs->version));
	if (rc < 0)
		return BLKID_PROBE_NONE;

	return BLKID_PROBE_OK;
}

const struct blkid_idinfo bcachefs_idinfo =
{
	.name		= "bcachefs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_bcachefs,
	.minsz		= BCACHEFS_MIN_SIZE,
	.magics		=
	{
		{ .magic = BCACHEFS_MAGIC
		, .len   = BCACHEFS_MAGIC_LEN
		, .kboff = BCACHEFS_SB_KBOFF_1
		, .sboff = BCACHEFS_SB_MAGIC_OFF
		} ,
		{ .magic = BCACHEFS_MAGIC
		, .len   = BCACHEFS_MAGIC_LEN
		, .kboff = BCACHEFS_SB_KBOFF_2
		, .sboff = BCACHEFS_SB_MAGIC_OFF
		} ,
		{ NULL }
	}
};

