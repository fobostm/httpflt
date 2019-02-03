#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


MODULE_LICENSE("GPL");


bool IsHttp(const char* data, int dataLen)
{
	int end = 0;
	int i = 0;
	
	char* httpTmp = "HTTP/";
	int httpTmpLen = strlen(httpTmp);
	
	if (dataLen <= httpTmpLen + 2)
	{
		return false;
	}
	
	if ('\n' == data[dataLen - 2] && '\r' == data[dataLen - 1])
	{
		return false;
	}
	
	for (i = 0; i < dataLen - 1; ++i)
	{
		if ('\n' == data[i] && '\r' == data[i + 1])
		{
			end = i;
			break;
		}
	}
	
	if (end <= httpTmpLen)
	{
		return false;
	}
	
	for (i = 0; i < end - httpTmpLen; ++i)
	{
		if (0 == strncmp(&data[i], httpTmp, httpTmpLen))
		{
			return true;
		}
	}
	
	return false;
};

unsigned int HttpFilter(void *priv,
						struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	struct iphdr* iph = NULL;
	struct tcphdr* tcph = NULL;
	
	char* data = NULL;
	unsigned int dataLen = 0;
	
	if (NULL == skb)
	{
		return NF_ACCEPT;
	}
	
	iph = ip_hdr(skb);
	if (NULL == iph)
	{
		return NF_ACCEPT;
	}
	
	if (IPPROTO_TCP != iph->protocol)
	{
		return NF_ACCEPT;
	}
	
	// iph->ihl - длина IP заголовка в 32-битных словах
	skb_set_transport_header(skb, iph->ihl * 4);
	tcph = tcp_hdr(skb);
	if (NULL == tcph)
	{
		return NF_ACCEPT;
	}
	
	dataLen = ntohs(iph->tot_len) - ((iph->ihl * 4) + (tcph->doff * 4));
	if (0 == dataLen)
	{
		return NF_ACCEPT;
	}
	
	data = (char*)((char*)tcph + (tcph->doff * 4));
	if (NULL == data)
	{
		return NF_ACCEPT;
	}
	
	// не использовал strstr т.к. мы не знаем что внутри данных
	if (!IsHttp(data, dataLen))
	{
		return NF_ACCEPT;
	}
	
	return NF_DROP;
}

static struct nf_hook_ops nfho = {
	.hook		= HttpFilter,
	.pf			= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FILTER,
};

static int __init HttpfltInit(void)
{
	printk("httpflt init\n");
	
	return nf_register_net_hook(&init_net, &nfho);
}

static void __exit HttpfltExit(void)
{
	printk("httpflt exit\n");
	
	nf_unregister_net_hook(&init_net, &nfho);
}


module_init(HttpfltInit);
module_exit(HttpfltExit);
