#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// COMPILE:
//    gcc onlyme.c -lmnl -lnetfilter_queue

typedef struct ip_hdr {
    unsigned char  ip_verlen;        // 4-bit IPv4 version 4-bit header length (in 32-bit words)
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Source address
} IPV4_HDR, *PIPV4_HDR;

static struct mnl_socket *nl;
time_t ip_last_modified = 0;
char ip_data[64];
char* ip_path = NULL;

char* get_authorized_ip() {
    struct stat file_stat;
    int err = stat(ip_path, &file_stat);
    if (err != 0) {
        perror(" [get_authorized_ip] stat");
        exit(errno);
    }
    
    if (file_stat.st_mtime > ip_last_modified) {
		FILE* f;
		
		memset(ip_data, 0, 64);
		f = fopen(ip_path, "r");
		if (f) {
			fread(ip_data, 64, 1, f);
			fclose(f);
			ip_last_modified = file_stat.st_mtime;
		}
		printf("IP updated to: %s\n", ip_data);
    }
    
    return ip_data;
}

static struct nlmsghdr *
nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	return nlh;
}

static int
nfq_send_verdict(int queue_num, uint32_t id, int verdict)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, verdict);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = NULL;
	struct nfqnl_msg_packet_hw *hw = NULL;
	struct nlattr *attr[NFQA_MAX+1];
	uint32_t id = 0;
	struct nfgenmsg *nfg;

	if (nfq_nlmsg_parse(nlh, attr) < 0) {
		perror("problems parsing");
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	ph = (struct nfqnl_msg_packet_hdr *)
		mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
	if (ph == NULL) {
		perror("problems retrieving metaheader");
		return MNL_CB_ERROR;
	}

	id = ntohl(ph->packet_id);

	uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
	void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
	int verdict = NF_DROP;
	
	PIPV4_HDR ip4 = (PIPV4_HDR)payload;
	if (ip4->ip_verlen == 0x45 && plen >= 16) {
		verdict = ip4->ip_srcaddr == inet_addr(get_authorized_ip()) ? NF_ACCEPT : NF_DROP;
	}
	
	printf("packet received (id=%u hw=0x%04x hook=%u) pktsize=%u, verdict=%s\n",
		id, ntohs(ph->hw_protocol), ph->hook, plen,
		verdict == NF_ACCEPT ? "Allow" : "Denied");

	nfq_send_verdict(ntohs(nfg->res_id), id, verdict);

	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;
	unsigned int portid, queue_num;

	if (argc != 3) {
		printf("Usage: %s [queue_num] [authorized_ip_file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	queue_num = atoi(argv[1]);
	ip_path = argv[2];
	get_authorized_ip();

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_UNBIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
		if (ret < 0){
			perror("mnl_cb_run");
			exit(EXIT_FAILURE);
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			exit(EXIT_FAILURE);
		}
	}

	mnl_socket_close(nl);

	return 0;
}