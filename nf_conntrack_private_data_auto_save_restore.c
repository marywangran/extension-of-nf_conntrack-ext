#include <linux/module.h>  
#include <linux/skbuff.h>  
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack_ext.h>
  
MODULE_AUTHOR("marywangran");  
MODULE_LICENSE("GPL");  

/*
 * ���붨��һ��������ʡ����������
 * ����ͻ����롰����-Ԫ����-ԪԪ����-ԪԪԪ����...����������ָ��Ȧ��
 * ��Ҳ��AI�����ٵ����⣺������ʶ�Ǹ�����being֪��ĳ���£�����being֪����being֪��ĳ���¡���
 * ����being֪����being֪����being֪��ĳ���¡���...
 */
enum ext_idx_idx {
	CONN_ORIG_ROUTE,
	CONN_REPLY_ROUTE,
	CONN_SOCK, 
	CONN_AND_SO_ON, 
	NUM
};

static inline void
nf_ext_put_sock(struct sock *sk)
{
	if ((sk->sk_protocol == IPPROTO_TCP) && (sk->sk_state == TCP_TIME_WAIT)){
		inet_twsk_put(inet_twsk(sk));
	} else {
		sock_put(sk);
	}
}

static void
nf_ext_destructor(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	skb->sk = NULL;
	skb->destructor = NULL;
	if (sk) {
		nf_ext_put_sock(sk);
	}
}

/* ����socket��HOOK���� */
static unsigned int ipv4_conntrack_save_sock (unsigned int hooknum,  
                                      struct sk_buff *skb,  
                                      const struct net_device *in,  
                                      const struct net_device *out,  
                                      int (*okfn)(struct sk_buff *))  
{
	struct nf_conn *ct;  
	enum ip_conntrack_info ctinfo;  
	struct nf_conntrack_ext *exts;
	ct = nf_ct_get(skb, &ctinfo);  
	if (!ct || ct == &nf_conntrack_untracked) {
		goto out;
	}
	if ((ip_hdr(skb)->protocol != IPPROTO_UDP) && 
					(ip_hdr(skb)->protocol != IPPROTO_TCP)) {
		goto out;
	}
	exts = nf_conn_exts_find(ct);
	if (exts) {  
		/* ����socket��ע�⣬ֻ��INPUT�Ļָ�����socket���бȽϴ������ */
		if (exts->bits_idx[CONN_SOCK] == -1) {
			if (skb->sk == NULL){
				goto out;
			}
			if ((ip_hdr(skb)->protocol == IPPROTO_TCP) && skb->sk->sk_state != TCP_ESTABLISHED) {
				goto out;
			}
			exts->bits_idx[CONN_SOCK] = nf_ct_exts_add(ct, skb->sk);
		}
	} 
out:
	return NF_ACCEPT;
}

/* ����·�����HOOK���� */
static unsigned int ipv4_conntrack_save_dst (unsigned int hooknum,  
                                      struct sk_buff *skb,  
                                      const struct net_device *in,  
                                      const struct net_device *out,  
                                      int (*okfn)(struct sk_buff *))  
{  
	struct nf_conn *ct;  
	enum ip_conntrack_info ctinfo;  
	struct nf_conntrack_ext *exts;
	ct = nf_ct_get(skb, &ctinfo);  
	if (!ct || ct == &nf_conntrack_untracked) {
		goto out;     
	}
	exts = nf_conn_exts_find(ct);
	if (exts) {  
		/* ����·�ɡ�ע�⣬����������IP�޷�����������·�ɶ�Ҫ���� */
		int dir = CTINFO2DIR(ctinfo);  
		int idx = (dir == IP_CT_DIR_ORIGINAL)?CONN_ORIG_ROUTE:CONN_REPLY_ROUTE;
		if (exts->bits_idx[idx] == -1) {
			struct dst_entry *dst = skb_dst(skb);
			if (dst) {
				dst_hold(dst); 
				exts->bits_idx[idx] = nf_ct_exts_add(ct, dst);
			}
		} 
	} 
out:
	return NF_ACCEPT;  
}  

/* ��ȡ����socket��HOOK���� */
static unsigned int ipv4_conntrack_restore_sock (unsigned int hooknum,  
                                      struct sk_buff *skb,  
                                      const struct net_device *in,  
                                      const struct net_device *out,  
                                      int (*okfn)(struct sk_buff *))  
{  
	struct nf_conn *ct;  
	enum ip_conntrack_info ctinfo;  
	struct nf_conntrack_ext *exts;
	ct = nf_ct_get(skb, &ctinfo);  
	if (!ct || ct == &nf_conntrack_untracked){
		goto out;
	}
	if ((ip_hdr(skb)->protocol != IPPROTO_UDP) && 
			(ip_hdr(skb)->protocol != IPPROTO_TCP)) {
		goto out;
	}

	exts = nf_conn_exts_find(ct);
	if (exts) {  
		/* ��ȡ�����socket */
		if (exts->bits_idx[CONN_SOCK] != -1) {
			struct sock *sk = (struct sock *)nf_ct_exts_get(ct, exts->bits_idx[CONN_SOCK]);
			if (sk) {
				if ((ip_hdr(skb)->protocol == IPPROTO_TCP) && sk->sk_state != TCP_ESTABLISHED) {
					goto out;
				}
				if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt))) {
					goto out;
				}
				skb_orphan(skb);
				skb->sk = sk;
				/* ����������atomic inc�����ü������ȵ�ת��������owner��ʱ��һ��Ҫput */
				skb->destructor = nf_ext_destructor;
			}
		}
	}
out:
	return NF_ACCEPT;
}
  
/* ��ȡ����·�����HOOK���� */
static unsigned int ipv4_conntrack_restore_dst (unsigned int hooknum,  
                                      struct sk_buff *skb,  
                                      const struct net_device *in,  
                                      const struct net_device *out,  
                                      int (*okfn)(struct sk_buff *))  
{  
	struct nf_conn *ct;  
	enum ip_conntrack_info ctinfo;  
	struct nf_conntrack_ext *exts;
	ct = nf_ct_get(skb, &ctinfo);  
	if (!ct || ct == &nf_conntrack_untracked) {
		goto out;
	}

	exts = nf_conn_exts_find(ct);
	if (exts) {  
		/* ��ȡ�����·�� */
		int dir = CTINFO2DIR(ctinfo);  
		int idx = (dir == IP_CT_DIR_ORIGINAL)?CONN_ORIG_ROUTE:CONN_REPLY_ROUTE;
		if (exts->bits_idx[idx] != -1) {
			struct dst_entry *dst = (struct dst_entry *)nf_ct_exts_get(ct, exts->bits_idx[idx]);
			if (dst) {
				dst_hold(dst);
				skb_dst_set(skb, dst);
			}
		}  
	} 
out:
	return NF_ACCEPT;  
}  

/*
 * ����ͼ����
 * OUTPUT������socket
 * INPUT���ָ�socket
 *
 * POSTROUTING|INPUT������·��
 * PREROUTING���ָ�·��
 */
static struct nf_hook_ops ipv4_conn_cache_ops[] __read_mostly = {  
	{  
		.hook           = ipv4_conntrack_save_dst,  
		.owner          = THIS_MODULE,  
		.pf             = NFPROTO_IPV4,  
		.hooknum        = NF_INET_POST_ROUTING,  
		.priority       = NF_IP_PRI_CONNTRACK + 1,  
	},  
	{  
		.hook           = ipv4_conntrack_save_sock,  
		.owner          = THIS_MODULE,  
		.pf             = NFPROTO_IPV4,  
		.hooknum        = NF_INET_LOCAL_OUT,  
		.priority       = NF_IP_PRI_CONNTRACK + 1,  
	},  
	{  
		.hook           = ipv4_conntrack_save_dst,  
		.owner          = THIS_MODULE,  
		.pf             = NFPROTO_IPV4,  
		.hooknum        = NF_INET_LOCAL_IN,  
		.priority       = NF_IP_PRI_CONNTRACK + 1,  
	},
	{  
		.hook           = ipv4_conntrack_restore_sock,  
		.owner          = THIS_MODULE,  
		.pf             = NFPROTO_IPV4,  
		.hooknum        = NF_INET_LOCAL_IN,  
		.priority       = NF_IP_PRI_CONNTRACK + 2,  
	},
	{  
		.hook           = ipv4_conntrack_restore_dst,  
		.owner          = THIS_MODULE,  
		.pf             = NFPROTO_IPV4,  
		.hooknum        = NF_INET_PRE_ROUTING,  
		.priority       = NF_IP_PRI_CONNTRACK + 1,  
	},  
};  
  
static int __init cache_dst_and_sock_demo_init(void)  
{  
	int ret;  
	ret = nf_register_hooks(ipv4_conn_cache_ops, ARRAY_SIZE(ipv4_conn_cache_ops));  
	if (ret) {  
		goto out;;  
	}
	return 0;
out:	
	return ret;  
}  
  
static void __exit cache_dst_and_sock_demo_fini(void)  
{  
	nf_unregister_hooks(ipv4_conn_cache_ops, ARRAY_SIZE(ipv4_conn_cache_ops));  
}  
  
module_init(cache_dst_and_sock_demo_init);  
module_exit(cache_dst_and_sock_demo_fini);  
