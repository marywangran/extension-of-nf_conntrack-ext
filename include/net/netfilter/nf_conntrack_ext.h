/*
 * (C) 2015 marywangran <marywangran@126.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _NF_CONNTRACK_EXT_H
#define _NF_CONNTRACK_EXT_H
#include <net/net_namespace.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

#define MAX_EXT_SLOTS	8	
#define BITINT	1


struct nf_conntrack_ext {
	/* 必须有一个数组用于自省或者反射 */
	int	bits_idx[MAX_EXT_SLOTS];
	int	bits[BITINT];
	char *slot[MAX_EXT_SLOTS];
};


int nf_ct_exts_add(const struct nf_conn *ct, void *ext);

void *nf_ct_exts_get(const struct nf_conn *ct, int idx); 

void nf_ct_exts_remove(const struct nf_conn *ct, int idx);

struct nf_conntrack_ext *nf_conn_exts_find(const struct nf_conn *ct);

struct nf_conntrack_ext *nf_conn_exts_add(struct nf_conn *ct, gfp_t gfp);
extern int nf_conntrack_exts_init();
extern void nf_conntrack_exts_fini();

#endif /* _NF_CONNTRACK_EXT_H */
