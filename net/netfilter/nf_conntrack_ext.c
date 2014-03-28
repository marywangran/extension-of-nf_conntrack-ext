/* conntrack扩展的扩展实现文件. */

/*
 * conntrack扩展的扩展实现文件.
 * 技术核心：
 *		1.位图
 *		2.索引的索引数组(外部维护的一个‘蓝图’)
 * (C) 2015 marywangran <marywangran@126.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_ext.h>

/* 这个spin lock应该和每一个ext绑定而不是全局的！ */
static DEFINE_SPINLOCK(nfct_ext_lock);

static struct nf_ct_ext_type ext_extend __read_mostly = {
	.len	= sizeof(struct nf_conntrack_ext),
	.align	= __alignof__(struct nf_conntrack_ext),
	.id	= NF_CT_EXT_EXT,
	.flags		= NF_CT_EXT_F_PREALLOC,
};

/* 
 * 增加一个数据到extend的extend
 * 注意：需要自己在外部维护一个关于索引的索引的数组
 **/
int nf_ct_exts_add(const struct nf_conn *ct, void *ext)
{
	int ret_idx = -1;
	struct nf_conntrack_ext *exts = NULL;

	if (!ext) {
		goto out;
	}

	exts = nf_conn_exts_find(ct);
	if (!exts) {
		goto out;
	}
	spin_lock(&nfct_ext_lock);
	ret_idx = find_first_zero_bit(exts->bits, MAX_EXT_SLOTS);
	if (ret_idx > MAX_EXT_SLOTS) {
		ret_idx = -1;
		spin_unlock(&nfct_ext_lock);
		goto out;
	}
	if (exts->slot[ret_idx]) {
		ret_idx = -1;
		spin_unlock(&nfct_ext_lock);
		goto out;
	}
	set_bit(ret_idx, exts->bits);
	exts->slot[ret_idx] = (char *)ext;
	spin_unlock(&nfct_ext_lock);
out:
	return ret_idx;
};
EXPORT_SYMBOL(nf_ct_exts_add);

/*
 * 根据ID的index获取保存在conntrack上的数据
 **/
void *nf_ct_exts_get(const struct nf_conn *ct, int idx)
{
	char *ret = NULL;
	struct nf_conntrack_ext *exts;

	if (idx > MAX_EXT_SLOTS || idx < 0) {
		goto out;
	}

	exts = nf_conn_exts_find(ct);
	if (!exts) {
		goto out;
	}
	spin_lock(&nfct_ext_lock);
	if (! test_bit(idx, exts->bits)) {
		spin_unlock(&nfct_ext_lock);
		goto out;
	}
	ret = exts->slot[idx];
	spin_unlock(&nfct_ext_lock);
out:
	return (void *)ret;
}
EXPORT_SYMBOL(nf_ct_exts_get);

/*
 * 根据ID的index删除保存在conntrack上的数据
 **/
void nf_ct_exts_remove(const struct nf_conn *ct, int idx)
{
	struct nf_conntrack_ext *exts;
	if (idx > MAX_EXT_SLOTS || idx < 0) {
		goto out;
	}

	exts = nf_conn_exts_find(ct);
	if (!exts) {
		goto out;
	}

	spin_lock(&nfct_ext_lock);
	if (! test_bit(idx, exts->bits)) {
		spin_unlock(&nfct_ext_lock);
		goto out;
	}
	clear_bit(idx, exts->bits);
	exts->slot[idx] = NULL;
	spin_unlock(&nfct_ext_lock);
out:
	return;
};
EXPORT_SYMBOL(nf_ct_exts_remove);

struct nf_conntrack_ext *nf_conn_exts_find(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_EXT);
}
EXPORT_SYMBOL(nf_conn_exts_find);

struct nf_conntrack_ext *nf_conn_exts_add(struct nf_conn *ct, gfp_t gfp)
{
	struct nf_conntrack_ext *exts;

	exts = nf_ct_ext_add(ct, NF_CT_EXT_EXT, gfp);
	if (!exts) {
		printk("failed to add extensions area");
		return NULL;
	}

	/* 初始化 */
	{
		int i;
		for (i = 0; i < MAX_EXT_SLOTS; i++) {
			exts->bits_idx[i] = -1;
			exts->slot[i] = NULL;
		}
	}
	return exts;
}
EXPORT_SYMBOL(nf_conn_exts_add);

int nf_conntrack_exts_init()
{
	int ret;

	ret = nf_ct_extend_register(&ext_extend);
	if (ret < 0) {
		printk("nf_conntrack_ext: Unable to register extension\n");
		goto out;
	}
	printk("nf_conntrack_ext: register extension OK\n");

	return 0;
out:
	return ret;
}

void nf_conntrack_exts_fini()
{
	nf_ct_extend_unregister(&ext_extend);
}
