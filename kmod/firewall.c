#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Karoubi");
MODULE_DESCRIPTION("Module");
MODULE_VERSION("0.0");

static struct nf_hook_ops *nfhook = NULL;

static unsigned int UDP__hook(struct sk_buff *skb)
{
    struct udphdr *udph;
    unsigned int state;

    udph = udp_hdr(skb);
    /* dichotomy by port */
    switch (ntohs(udph->dest)) {
        default:
            state = NF_DROP;
    }
    if (state == NF_ACCEPT)
        printk(KERN_INFO "[firewall] Port %d UDP : ACCEPTED\n", ntohs(udph->dest));
    else
        printk(KERN_INFO "[firewall] Port %d UDP : REJECTED\n", ntohs(udph->dest));
    return (state);
}

static unsigned int TCP__hook(struct sk_buff *skb)
{
    struct tcphdr *tcph;
    unsigned int state;

    tcph = tcp_hdr(skb);
    /* dichotomy by port */
    switch (ntohs(tcph->dest)) {
        default:
            state = NF_DROP;
    }
    if (state == NF_ACCEPT)
        printk(KERN_INFO "[firewall] Port %d TCP : ACCEPTED\n", ntohs(tcph->dest));
    else
        printk(KERN_INFO "[firewall] Port %d TCP : REJECTED\n", ntohs(tcph->dest));
    return (state);
}

static unsigned int hookflow(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    unsigned int PacketState;

    if (!skb)
        return (NF_DROP); // there is nothing
    iph = ip_hdr(skb); // get informations on packet

    /* dichotomy by protocol */
    switch (iph->protocol) {
        case IPPROTO_UDP: // UDP packet
            PacketState = UDP__hook(skb);
            break;
        case IPPROTO_TCP: // TCP packet
            PacketState = TCP__hook(skb);
            break;
        default: // by default reject
            PacketState = NF_DROP;
            break;
    }
    return (PacketState);
}

extern void (*sysctl_exit_var)(void);
extern void (*sysctl_init_var)(void);

static int __init firewall_init(void)
{
    nfhook = (struct nf_hook_ops*)kcalloc(0x1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    // sysctl_init_var();
    /* Initialize netfilter hook */
    nfhook->hook     = (nf_hookfn *)hookflow; /* managing packets  */
    nfhook->hooknum  = NF_INET_PRE_ROUTING;   /* received packets  */
    nfhook->pf       = PF_INET;               /* IPv4              */
    nfhook->priority = NF_IP_PRI_FIRST;       /* max hook priority */
    nf_register_net_hook(&init_net, nfhook);
    return (0x0);
}

static void __exit firewall_exit(void)
{
    sysctl_exit_var();
    nf_unregister_net_hook(&init_net, nfhook);
    kfree(nfhook);
}

module_init(firewall_init);
module_exit(firewall_exit);
