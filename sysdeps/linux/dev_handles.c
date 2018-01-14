#include <glibtop/netlist.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include "dev_handles.h"
#include "packet.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include "interface_local_addr.h"
#include "connection.h"
#include "net_process.h"
#include "netsockets.h"
#include <glib.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <glibtop/procstate.h>
/*GLOBAL HASH TABLE */
//local_addr *interface_local_addr;
	int size_ip;
	int size_tcp;
int promisc = 0;
char errbuf[PCAP_ERRBUF_SIZE];
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

//GHashTable *inode_table = g_hash_table_new(g_direct_hash, g_direct_equal);
//GHashTable *hash_table = g_hash_table_new(g_str_hash, g_str_equal);
void
process_init()
{
	Net_process_list *processes = get_proc_list_instance(NULL);//global process list
	Net_process *unknownTCP = get_unknown_proc_instance(NULL);

	Net_process_init(unknownTCP, 0, "", "unknownTCP");
	Net_process_list_init(processes, unknownTCP, NULL);
}

timeval 
get_curtime(timeval val)
{	static timeval curtime ;
	if(val.tv_sec)
		curtime = val;
	return curtime;
}
Net_process *get_process_from_inode(unsigned long inode, const char *device_name)
{
	int pid = match_pid(inode);
	printf("pid%d",pid);
	Net_process_list *current = get_proc_list_instance(NULL) ;/*global list of all procs*/
	while (current != NULL)
	{
		Net_process *curr_process = Net_process_list_get_proc(current);
		g_assert(curr_process);
		if (pid == curr_process->pid)
			return curr_process;
		current = current->next;
	}
	if (pid!= -1)
	{	//if(is_packet)
		Net_process *proc = g_slice_new(Net_process);

		Net_process_list *temp = g_slice_new(Net_process_list);
		glibtop_proc_state *proc_buf = g_slice_new(glibtop_proc_state);
		glibtop_get_proc_state(proc_buf, pid);
		printf("proc name%s\n",proc_buf->cmd);
		Net_process_init(proc, pid,"", proc_buf->cmd);

		return proc;
	}
	return NULL;
}

Net_process * 
get_process(Connection *conn, const char *device_name)
{
	unsigned long inode = match_hash_to_inode(Packet_gethash(conn->ref_packet));
	if (inode == -1)
	{	printf("Unknown PROC\n");
		Packet *reverse_pkt = get_inverted_packet(conn->ref_packet);
		inode = match_hash_to_inode(Packet_gethash(reverse_pkt));
		if (inode == -1)
		{	g_slice_free(Packet, reverse_pkt);
			Conn_list *temp = g_slice_new(Conn_list);
			Conn_list_init(temp, conn, get_unknown_proc_instance(NULL)->proc_connections);
			get_unknown_proc_instance(NULL)->proc_connections = temp; //assigning this connection to unknown TCP 
			return get_unknown_proc_instance(NULL);
		}
		//g_slice_free(Packet, conn->ref_packet);
		conn->ref_packet = reverse_pkt;
	}
	/*this proc is present in the hash table*/
	printf("%s inode:%d\n",Packet_gethash(conn->ref_packet),inode );
	Net_process *proc = get_process_from_inode(inode, device_name);
	if (proc == NULL)
	{
		proc = g_slice_new(Net_process);
		printf("%s not in /proc/net/tcp \n", Packet_gethash(conn->ref_packet));
		Net_process_init(proc, inode,"", Packet_gethash(conn->ref_packet));
		Net_process_list *temp = g_slice_new(Net_process_list);
		Net_process_list_init(temp, proc, get_proc_list_instance(NULL));
		get_proc_list_instance(temp);	//processes = temp
	}
	else
	{
		Net_process_list *temp = g_slice_new(Net_process_list);
		Net_process_list_init(temp, proc, get_proc_list_instance(NULL));
		get_proc_list_instance(temp);	//processes = temp
	}
	Conn_list *temp_list = g_slice_new(Conn_list);
	Conn_list_init(temp_list, conn, proc->proc_connections);
	proc->proc_connections = temp_list;

	return proc;
}

int 
process_ip(u_char *userdata, const struct pcap_pkthdr *header /* header */,const u_char *m_packet) /*hash tables pass*/
{
	packet_args *args = (packet_args *)userdata;
	struct ip *ip4 = (struct ip *)m_packet;
	args->sa_family = AF_INET;
	args->ip_src = ip4->ip_src;
	args->ip_dst = ip4->ip_dst;
	printf("sa family:%d \n",args->sa_family );

	/* we're not done yet - also parse tcp */
	return 0;
}
int 
process_ip6(u_char *userdata, const struct pcap_pkthdr *header /* header */,const u_char *m_packet) /*hash tables pass*/ 
{
	packet_args *args = (packet_args *)userdata;
	const struct ip6_hdr *ip6 = (struct ip6_hdr *)m_packet;
	args->sa_family = AF_INET6;
	args->ip6_src = ip6->ip6_src;
	args->ip6_dst = ip6->ip6_dst;
	return 0;
}
int 
process_tcp(u_char *userdata, const struct pcap_pkthdr *header /* header */,const u_char *m_packet) /*hash tables pass*/
{	/*WIP*/
	packet_args *args = (packet_args *)userdata;
	struct sniff_tcp *tcp = (struct sniff_tcp *)(m_packet);
	timeval cur = header->ts;
	get_curtime(header->ts);
	Packet *packet = g_slice_new(Packet);

	char *local_string = (char *)malloc(128);
	char *remote_string = (char *)malloc(128);
	switch(args->sa_family)
	{
	case AF_INET:
		//printf("LOOKING at packet sip%s :%d-dip%s:%d\n",inet_ntoa(args->ip_src),ntohs(tcp->th_sport),inet_ntoa(args->ip_dst),ntohs(tcp->th_sport));
		Packet_init_in_addr(packet, args->ip_src, ntohs(tcp->th_sport), args->ip_dst, ntohs(tcp->th_dport), header->len, header->ts);
		//printf("src:%s dest:%s\n",args->ip_src,args->ip_dst);
		if(is_pkt_outgoing(packet))
			printf("outgoind\n");
		else
			printf("incoming\n");
			break;

	case AF_INET6:
		//printf("LOOKING at packet sip%s :%d-dip%s:%d\n",inet_ntoa(args->ip6_src),ntohs(tcp->th_sport),inet_ntoa(args->ip6_dst),ntohs(tcp->th_sport));
		Packet_init_in6_addr(packet, args->ip6_src, ntohs(tcp->th_sport), args->ip6_dst, ntohs(tcp->th_dport), header->len, header->ts);
		inet_ntop(AF_INET6,  &args->ip6_src, local_string, 46);
		inet_ntop(AF_INET6, &args->ip6_dst, remote_string, 46);
		printf("src:%s dest:%s\n",args->ip6_src,args->ip6_dst);
		printf("src:%s dest:%s\n",local_string,remote_string );
		if(is_pkt_outgoing(packet))
			printf("outgoind\n");
		else
			printf("incoming\n");
		free(local_string);
		free(remote_string);
		break;
	default:
		printf("invalid family\n");
		packet = NULL;
	}
	if(packet != NULL)
	{
		Connection *connection = find_connection(packet);
		/*if(is_pkt_outgoing(packet))
			unsigned long inode = match_hash_to_inode(Packet_gethash(packet));
		else
			unsigned long inode = match_hash_to_inode(Packet_gethash(get_inverted_packet(packet)));*/
		if (connection != NULL)
			add_packet_to_connection(connection, packet);
		else
		{	printf("NEW PROC \n");
			/*if(is_pkt_outgoing(packet))
				{	unsigned long inode = match_hash_to_inode(Packet_gethash(packet));
					if(inode != -1)
					{
						int pid = match_pid(inode);
						Net_process *proc = match_proc_with_pid(pid);
					}
				}
			else*/
			//	unsigned long inode = match_hash_to_inode(Packet_gethash(get_inverted_packet(packet)));
			Connection *connection = g_slice_new(Connection);
			Connection_init(connection, packet);
			//Add this connection to a connectionlist depending on the process it belongs to
			//write this 
			 get_process(connection, args->device);
			// add_packet_to_connection(temp_proc->proc_connections, packet);

		}
	}
	//g_slice_free(Packet, packet); remove pkt from conn
	return 1;//just to tell that work's over
}

void 
add_callback(packet_handle *handle ,enum packet_type type ,packet_callback callback)
{
	handle->callback[type] = callback ;
}

packet_handle*
get_interface_handle(char *device, GError **err)
{	
	bpf_u_int32 maskp; // subnet mask
	bpf_u_int32 netp; // interface IP
char filter_exp[] = "ip";
struct bpf_program fp;	
	pcap_t *temp = pcap_open_live(device, BUFSIZ, promisc, 100, errbuf);
	pcap_lookupnet(device, &netp, &maskp, errbuf);
	if(temp == NULL)
	{
		g_set_error(err,
					IF_HANDLE,
					IF_HANDLE_FUNC,
					"failed to open handle for device : %s",
					device);
		return NULL;
	}
	if (pcap_compile(temp, &fp, filter_exp, 0, netp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(temp));
		exit(EXIT_FAILURE);
	}
		if (pcap_setfilter(temp, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(temp));
		exit(EXIT_FAILURE);
	}


	packet_handle *temp_packet_handle = (packet_handle *)malloc(sizeof(packet_handle));
	if(temp_packet_handle != NULL)
	{	
		temp_packet_handle->pcap_handle = temp;
		temp_packet_handle->device_name = device;
		temp_packet_handle->next = NULL;
		temp_packet_handle->linktype = pcap_datalink(temp);
		for(int i = 0; i < no_of_packet_types; i++)
		{
			temp_packet_handle->callback[i] = NULL;
		}
		return temp_packet_handle;
	}
	return NULL;
}

packet_handle * 
open_pcap_handles()
{	glibtop_netlist buf;
	char **devices;
	devices = glibtop_get_netlist (&buf);
	GError **if_error;
	int count=0;
	packet_handle *previous_handle=NULL , *initial_handle = NULL;
	gboolean init_ele = true ; 
	while(count < buf.number){
		packet_handle *new_handle = get_interface_handle(devices[count], if_error);
		local_addr *temp;
		if ((temp = get_device_local_addr(devices[count])) == NULL)
			printf("Failed to get addr for %s\n",devices[count]);
		if(new_handle != NULL)
		{	if(init_ele)
			{
				initial_handle = new_handle;
				init_ele = false;
			}
			add_callback(new_handle, packet_ip, process_ip);
			add_callback(new_handle, packet_ip6, process_ip6);
			add_callback(new_handle, packet_tcp, process_tcp);
			if(pcap_setnonblock(new_handle->pcap_handle, 1, errbuf) == -1)
				printf("failed to set to non blocking mode %s\n",devices[count]);
			if(previous_handle != NULL)
				previous_handle->next = new_handle;
			previous_handle = new_handle;
		}	
		count++;
	}
	return initial_handle;

}
void 
print_pcap_handles(packet_handle *handle)
{
	glibtop_netlist buf;
	char **devices;
	devices = glibtop_get_netlist (&buf);
	int count=0;
	packet_handle *temp_handle = handle;
	while(temp_handle != NULL)
	{
		printf("device name : %s linktype: %d \n ",temp_handle->device_name, temp_handle->linktype);
		temp_handle = temp_handle->next;
	}	
}

void
print_interface_local_address()
{
	local_addr *temp = get_local_addr_instance(NULL);
	while(temp != NULL && temp->device_name != NULL)
	{
		printf("%s : %s \n",temp->device_name,temp->ip_text);
		temp = temp->next;
	}
}

void
packet_parse_tcp(packet_handle *handle, const struct pcap_pkthdr *hdr, const u_char * pkt)
{
	if (handle->callback[packet_tcp] != NULL)
	{
		if(handle->callback[packet_tcp](handle->userdata, hdr, pkt))
			return;
	}
}

void
packet_parse_ip(packet_handle *handle, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const struct sniff_ip *ip_packet = (struct sniff_ip*)pkt;
	printf("Looking at packet with length %d \n", hdr->len);
	//check
	size_ip = IP_HL(ip_packet)*4;
		if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		/* print source and destination IP addresses */
	
	

	u_char *payload = (u_char *)(pkt + sizeof(ip));
	if (handle->callback[packet_ip] != NULL)
	{	
		if(handle->callback[packet_ip](handle->userdata, hdr, pkt))
			return ;
	}
const struct sniff_tcp *tcp;
	switch(ip_packet->ip_p)
	{
		case IPPROTO_TCP:
			printf("exec tcp\n");
			printf("       From: %s\n", inet_ntoa(ip_packet->ip_src));
	printf("         To: %s\n", inet_ntoa(ip_packet->ip_dst));
			tcp  = (struct sniff_tcp*)(pkt  + sizeof(ip));
			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));
			packet_parse_tcp(handle, hdr, payload);
			break;
		//non tcp IP packet support not present currently
			
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			break;
		default:
			
		
			break;
	}
}

void packet_parse_ip6(packet_handle *handle, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
	u_char *payload = (u_char *)(pkt + sizeof(ip6));

	if (handle->callback[packet_ip6] != NULL) 
	{
		if (handle->callback[packet_ip6])(handle->userdata, hdr, pkt);
			return;
	}
	switch ((ip6->ip6_ctlun).ip6_un1.ip6_un1_nxt) 
	{
	case IPPROTO_TCP:
		packet_parse_tcp(handle, hdr, payload);
		break;
	default:
	// TODO: maybe support for non-tcp ipv6 packets
	break;
	}
}

void
packet_parse_ethernet(packet_handle * handle, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const struct sniff_ethernet *ethernet = (struct sniff_ethernet *)pkt;
	u_char *payload = (u_char *)(pkt +14);	
	printf("parse ethernet\n");
	switch (ntohs(ethernet->ether_type)) 
	{
	case ETHERTYPE_IP:
 		printf("ethertype ip exec");
		packet_parse_ip(handle, hdr, payload);
		break;

	case ETHERTYPE_IPV6:
		printf("ethertype ipv6 exec");
		packet_parse_ip6(handle, hdr, payload);
		break;
	
	}
}

void
packet_pcap_callback(u_char *u_handle, const struct pcap_pkthdr *hdr, const u_char *pkt)
{	
	packet_handle *handle = (packet_handle *)u_handle;
	switch(handle->linktype)
	{
	case (DLT_EN10MB):
		packet_parse_ethernet(handle, hdr, pkt);
		break;
	/*
	case (DLT_EN10MB):
		packet_parse_ethernet(handle, hdr, pkt);
		break;
	*/
	default :
		printf("Unknown linktype\n");
	}
}


int
packet_dispatch(packet_handle *handle, int count, u_char *user, int size)
{
	handle->userdata = user;
	handle->userdata_size = size;
	return pcap_dispatch(handle->pcap_handle, -1, packet_pcap_callback, (u_char *)handle);
}

