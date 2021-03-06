#ifndef __GLIBTOP_NET_PROCESS_H_
#define __GLIBTOP_NET_PROCESS_H_

#include <glib.h>
#include <sys/types.h>
#include <glibtop/connection.h>
G_BEGIN_DECLS

#define CONNTIMEOUT 50
#define PERIOD 5

typedef struct _Net_process Net_process;
struct _Net_process
{
	unsigned long inode;
	pid_t pid;
	guint64 bytes_sent;
	guint64 bytes_recv;
	GSList *proc_connections; 
	//char *device_name;
	//uid_t uid;
};

void Net_process_init(Net_process *proc, unsigned long pid);
time_t Net_process_get_last_packet_time(Net_process *proc);
void Net_process_get_total(Net_process *proc, guint64 *recvd, guint64 *sent);
void Net_process_get_bytes(Net_process *proc, guint *recvd, guint *sent, struct timeval currtime);
uid_t Net_process_get_uid(Net_process *proc);
GSList *Net_process_list_init(GSList *plist, Net_process *proc);
Net_process *Net_process_list_get_proc(GSList *plist);
GSList *get_proc_list_instance(GSList *val);
Net_process *get_unknown_proc_instance(Net_process *val);
G_END_DECLS
#endif
