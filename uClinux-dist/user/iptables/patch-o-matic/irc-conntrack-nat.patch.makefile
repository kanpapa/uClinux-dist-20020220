obj-$(CONFIG_IP_NF_CONNTRACK) += ip_conntrack.o

# IRC support
obj-$(CONFIG_IP_NF_IRC) += ip_conntrack_irc.o
obj-$(CONFIG_IP_NF_NAT_IRC) += ip_nat_irc.o
