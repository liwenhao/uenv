/*
 * Mapping uboot env to sysfs
 *
 * Copyright (C) 2011 Wenhao Li
 * Author: Wenhao Li
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#define pr_fmt(fmt) "[UENV] "fmt"\n"

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/mtd/mtd.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/crc32.h>

static char *name = "uboot";
static int offset = 0x60000;
static uint size = 0x40000;

module_param(name, charp, 0);
module_param(offset, int, 0);
module_param(size, uint, 0);

struct env_pair {
	struct attribute attr;
	char *value;
	struct list_head entry;
};

struct env_t {
	struct kobject kobj;
	struct list_head pairs;
	struct mtd_info *mtd;
	size_t size;
};

struct env_packet {
	uint32_t crc32;
	char body[1];
};
#define CRC_SIZE sizeof(uint32_t)

static size_t __init
read_skip_bad(struct env_t *env, char* buf, size_t *count)
{
	struct mtd_info *mtd = env->mtd;
	int error, step, offset = 0;
	char *p = buf;

	while (offset < env->size) {
		if (mtd_block_isbad(mtd, offset)) {
			offset += mtd->erasesize;
			continue;
		}

		step = mtd->erasesize;
		error = mtd_read(mtd, offset, step, &step, p);
		if (error) {
			pr_err("mtd read error: %d", error);
			return error;
		}
		offset += step;

		for (; step--; p++) {
			if (*p == '\0' && *(p+1) == '\0' && p > buf+CRC_SIZE)
				goto done;
		}
	}

	pr_err("no ending environment");
	return -EIO;

done:
	*count = (p - buf) + 2;
	return 0;
}

static int __init
add_pair(struct list_head *pairs, const char *name, const char *value)
{
	struct env_pair *pair;

	pair = kzalloc(sizeof(struct env_pair), GFP_KERNEL);
	if (!pair) {
		pr_err("no memory for pair");
		return -ENOMEM;
	}

	pair->attr.mode = S_IWUSR | S_IRGRP | S_IROTH;
	pair->attr.name = kstrdup(name, GFP_KERNEL);

	pair->value = kstrdup(value, GFP_KERNEL);
	if (!pair->value) {
		pr_err("no memory for pair value");
		return -ENOMEM;
	}

	list_add_tail(&pair->entry, pairs);

	return 0;
}

static int __init env_parse(struct env_t *env, char *data)
{
	char *name, *value, *dp = data;
	int error;

	while ((dp < data + env->size) && *dp) {
		/* skip leading blank */
		while ((*dp == ' ') || (*dp == '\t') || (*dp == '\n'))
			dp++;

		/* parse name */
		for (name = dp; *dp != '=' && *dp; dp++)
			;
		*dp++ = '\0';

		/* parse value*/
		for (value = dp; *dp; dp++)
			;
		*dp++ = '\0';

		/* add to attributes */
		error = add_pair(&env->pairs, name, value);
		if (error)
			return error;
	}

	return 0;
}

static int __init env_init(struct env_t *env)
{
	struct env_packet *packet;
	int error = 0, count = 0;
	struct env_pair *pair;
	uint32_t crc;

	/* get mtd info */
	env->mtd = get_mtd_device_nm(env->kobj.name);
	if (IS_ERR(env->mtd)) {
		error = PTR_ERR(env->mtd);
		pr_err("cannot open device: %s(%d)", env->kobj.name, error);
		return error;
	}

	/* set size */
	if (env->size <= 0 || env->size > env->mtd->size)
		env->size = env->mtd->size;

	/* read environment */
	packet = kmalloc(env->size, GFP_KERNEL);
	if (!packet) {
		pr_err("no memory for read buffer: %d", env->size);
		return -ENOMEM;
	}

	error = read_skip_bad(env, (char *)packet, &count);
	if (error) {
		pr_err("error in reading environment: %d", error);
		goto fail;
	}

	/* check crc32 */
	crc = crc32(~0, packet->body, count-CRC_SIZE) ^ ~0;
	if (crc != packet->crc32) {
		error = -EIO;
		pr_err("crc32 verify error: 0x%08X, 0x%08X",
		       crc, packet->crc32);
		goto fail;
	}

	/* parse */
	error = env_parse(env, packet->body);
	if (error) {
		pr_err("error in parsering environment: %d", error);
		goto fail;
	}

	/* add attributes to sysfs */
	count = 0;
	list_for_each_entry(pair, &env->pairs, entry) {
		error = sysfs_create_file(&env->kobj, &pair->attr);
		if (error) {
			pr_err("cannot create attribute: %s(%s:%s)",
			       env->kobj.name, pair->attr.name, pair->value);
			goto fail;
		}
		count++;
	}

	pr_notice("enviroment initialized: %s(%d)", env->kobj.name, count);

fail:
	kfree(packet);

	return error;
}

static int erase_skip_bad(struct env_t *env, int size)
{
	struct mtd_info *mtd = env->mtd;
	struct erase_info ei;
	int error;

	memset(&ei, 0, sizeof(struct erase_info));
	ei.mtd = mtd;
	ei.len = mtd->erasesize;

	while (size > 0 && ei.addr < env->size) {
		if (mtd_block_isbad(mtd, ei.addr)) {
			ei.addr += mtd->erasesize;
			continue;
		}

		error = mtd_erase(mtd, &ei);
		if (error || ei.state == MTD_ERASE_FAILED) {
			pr_err("error while erasing: %d", ei.state);
			return -EIO;
		}

		ei.addr += mtd->erasesize;
		size -= mtd->erasesize;
	}

	return 0;
}

static int
write_skip_bad(struct env_t *env, const char* buf, int len)
{
	struct mtd_info *mtd = env->mtd;
	size_t step, offset = 0;
	int error;
	const char *end;

	if (len > env->size) {
		pr_err("no enough space on device: %s,%d",
		       env->kobj.name, len);
		return -ENOSPC;
	}

	end = buf + len;
	while (offset < env->size && buf < end) {
		if (mtd_block_isbad(mtd, offset)) {
			offset += mtd->erasesize;
			continue;
		}

		step = mtd->erasesize; /* must page aligned */

		error = mtd_write(mtd, offset, step, &step, buf);
		if (error) {
			pr_err("mtd write error: %d", error);
			return error;
		}

		offset += step;
		buf += step;
	}

	if (buf < end) {
		pr_err("too many bad blocks: %s", env->kobj.name);
		return -EIO;
	}

	return 0;
}

static int join_pairs(struct list_head *pairs, char *buf, size_t *size)
{
	struct env_pair *pair;
	char *dest, *end;
	const char *src, *fmt[3] = {NULL, "=", NULL};
	int i;

	dest = buf;
	end = buf + *size;
	list_for_each_entry(pair, pairs, entry) {
		fmt[0] = pair->attr.name;
		fmt[2] = pair->value;

		for (i = 0; i < 3; i++) {
			src = fmt[i];
			while (*src && dest < end)
				*dest++ = *src++;
		}

		if (dest >= end) {
			pr_err("no enough space on device");
			return -ENOSPC;
		}

		*dest++ = '\0';

	}
	*dest = '\0';
	*size = (dest - buf) + 1;

	return 0;
}

static int env_save(struct env_t *env)
{
	struct env_packet *packet;
	int error = 0, count;

	/* prepare buffer */
	packet = kmalloc(env->size, GFP_KERNEL);
	if (!packet) {
		pr_err("no memory for write buffer: %d", env->size);
		return -ENOMEM;
	}

	/* join pairs */
	count = env->size - CRC_SIZE;
	error = join_pairs(&env->pairs, packet->body, &count);
	if (error)
		goto fail;

	/* crc32 */
	packet->crc32 = crc32(~0, packet->body, count) ^ ~0;
	count += CRC_SIZE;

	/* erase */
	error = erase_skip_bad(env, count);
	if (error) {
		pr_err("error in erasing: %d", error);
		goto fail;
	}

	/* write */
	error = write_skip_bad(env, (char *)packet, count);
	if (error) {
		pr_err("error in writing: %d ", error);
		goto fail;
	}

fail:
	kfree(packet);
	return error;
}

static ssize_t
env_show(struct kobject *obj, struct attribute *attr, char *buf)
{
	struct env_pair *pair = container_of(attr, struct env_pair, attr);
	return snprintf(buf, PAGE_SIZE, "%s\n", pair->value);
}

static ssize_t
env_store(struct kobject *obj, struct attribute *attr,
	  const char *buf, size_t count)
{
	int error;
	char *origin;
	struct env_pair *pair = container_of(attr, struct env_pair, attr);
	struct env_t *env = container_of(obj, struct env_t, kobj);

	origin = pair->value;
	pair->value = kstrndup(buf, count, GFP_KERNEL);
	if (!pair->value) {
		pr_err("no memory for environment value: %d", count);
		pair->value = origin;
		return -EIO;
	}

	/* sync */
	error = env_save(env);
	if (error) {
		kfree(pair->value);
		pair->value = origin;
		return -EIO;
	}

	return strnlen(buf, count);
}

static void env_release(struct kobject *kobj)
{
	struct env_pair *pair, *n;
	struct env_t *env = container_of(kobj, struct env_t, kobj);

	/* clean */
	list_for_each_entry_safe(pair, n, &env->pairs, entry) {
		kfree(pair->attr.name);
		kfree(pair->value);
		kfree(pair);
	}

	if (!IS_ERR(env->mtd))
		put_mtd_device(env->mtd);

	kfree(env);
}

static const struct sysfs_ops env_ops = {
	.show = env_show,
	.store = env_store
};

static struct kobj_type env_type = {
	.release = env_release,
	.sysfs_ops = &env_ops
};

static struct kset *uenv_kset;

/**
 * pce_register - register a new environment
 *
 * @name: the name of the mtd device
 * @size: max size of the environment
 */
static int __init uenv_register(const char* name, size_t size)
{
	struct env_t *env;
	int error;

	if (!name || !size)
		return 0;

	/* check/create top kset */
	if (!uenv_kset) {
		uenv_kset = kset_create_and_add("uenv", NULL, NULL);
		if (!uenv_kset) {
			pr_err("cannot create top kset");
			return -ENOMEM;
		}
	}

	/* create a new environment */
	env = kzalloc(sizeof(struct env_t), GFP_KERNEL);
	if (!env) {
		pr_err("no memory for environment kobject");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&env->pairs);
	env->kobj.kset = uenv_kset;
	env->size = size;

	/* add the new environment to sysfs */
	error = kobject_init_and_add(&env->kobj, &env_type, NULL, name);
	if (error) {
		pr_err("cannot add environment to sysfs: %s", name);
		kfree(env);
		return error;
	}

	pr_notice("environment registered: %s", name);

	return 0;
}

static int __init register_envs(void)
{
	int error;
	error = uenv_register(name, size);
	if (error)
		return error;

	return 0;
}

static int __init uenv_init(void)
{
	struct kobject *k, *n;
	struct env_t *env;
	int error;

	if (!uenv_kset && register_envs()) {
		pr_notice("error while initializing");
		return 0;
	}

	spin_lock(&uenv_kset->list_lock);
	list_for_each_entry_safe(k, n, &uenv_kset->list, entry) {
		env = container_of(k, struct env_t, kobj);
		error = env_init(env);
		if (error) {
			pr_warn("environment init failed: %s",
				env->kobj.name);
			kobject_put(&env->kobj);
		}
	}
	spin_unlock(&uenv_kset->list_lock);

	pr_notice("uboot environment mapped");

	return 0;
}

static void __exit uenv_exit(void)
{
	if (uenv_kset)
		kset_unregister(uenv_kset);

	pr_notice("uboot environment unmapped");
}

module_init(uenv_init);
module_exit(uenv_exit);

MODULE_AUTHOR("Wenhao Li");
MODULE_DESCRIPTION("Mapping uboot env to sysfs");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

