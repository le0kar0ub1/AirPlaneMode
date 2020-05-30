#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SYSCTL_VAR_EXPOSED_PORT "kernel.firewallPortAllowed"
#define SYSCTL_VAR_MAX_LENGHT   sizeof(void *)

static struct ctl_table_header *ExposedPortHeader = NULL;
static struct ctl_table        *ExposedPort = NULL;

static unsigned int state_min = 0;
static unsigned int state_max = (1 << 16);
static unsigned int *data;

static int sysctl_proc_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int result, old, new;

    old = *(int *)table->data;
    result = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
    new = *(int *)table->data;

    return (0);
}

void sysctl_init_var(void)
{
    data = (unsigned int *)kcalloc(sizeof(unsigned int), 0x1, GFP_KERNEL);

    ExposedPort = (struct ctl_table *)kcalloc(0x1, sizeof(struct ctl_table), GFP_KERNEL);
    ExposedPort->procname = SYSCTL_VAR_EXPOSED_PORT;
    ExposedPort->data     = data;
    ExposedPort->maxlen   = SYSCTL_VAR_MAX_LENGHT;
    ExposedPort->mode     = 0644;
    ExposedPort->proc_handler = &sysctl_proc_handler;
    ExposedPort->extra1 = &state_min;
    ExposedPort->extra2 = &state_max;

    if (!(ExposedPortHeader = register_sysctl_table(ExposedPort)))
        printk(KERN_INFO "[firewall] can't register sysctl table\n");
    else
        printk(KERN_INFO "[firewall] sysctl table well registered\n");
}

void sysctl_exit_var(void)
{
    unregister_sysctl_table(ExposedPortHeader);
}