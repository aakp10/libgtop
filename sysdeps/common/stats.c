#include <stdio.h>
#include <glibtop/stats.h>
#include <stdlib.h>
#include <glibtop/dev_handles.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <glibtop/net_process.h>
#include <glibtop/netsockets.h>
#include <gmodule.h>

static time_t last_refresh_time = 0;

void
network_stats_init(network_stats_entry *st, guint recv_value, guint sent_value, pid_t pid)
{
	st->pid = pid;
	st->sent_value = sent_value;
	st->recv_value = recv_value;
	g_assert(pid >= 0);
}

static void
free_dbus_stats (gpointer data)
{
  stats *temp = data;
  g_slice_free (stats, temp);
}

GArray *
network_stats_get_global_instance(GArray *val)
{
	static GArray *global_stats = NULL;
	if (val != NULL)
		{
			global_stats = val;
		}
	else	if (global_stats == NULL)
	{
		global_stats = g_array_new (TRUE,FALSE,sizeof(network_stats_entry));
	}
	return global_stats;
}

static stats *
new_stats(guint pid, guint bytes_sent, guint bytes_recv)
{
	stats *temp_stats = g_slice_new(stats);
	temp_stats->pid = pid;
	temp_stats->bytes_recv = bytes_recv;
	temp_stats->bytes_sent = bytes_sent;
	return temp_stats;
}

GPtrArray **
glibtop_get_stats_instance(GPtrArray *val)
{
	static GPtrArray *dbus_stats = NULL;
	if (val != NULL)
	{
		dbus_stats = val;
	}
	else if (dbus_stats == NULL)
	{
		dbus_stats = g_ptr_array_new_with_free_func (free_dbus_stats);
	}
	return &dbus_stats;
}

/**
*NOTE (DBus): this function is used to change the capture status when a relevant
*	   		  signal is processed by the callback in the dbus interface.
*      		  source of signal emission is any application which tries to consume
*      		  the libgtop API through the DBus
*
*NOTE (Daemon): if later a daemon is proposed to be used over DBus this won't be
*	   			an issue since by default status is kept to be active
*/
gboolean
glibtop_get_capture_status(gboolean val)
{
	static gboolean active = FALSE;
	//if val is true invert the capture status
	//if false capture status is unchanged
	if(val)
		{
			active = !active;
		}
	return active;
}
static void
network_stats_print_entry(network_stats_entry *st)
{
	printf("pid :%d \t sent_value:%d \trecv value:%d \t \n", st->pid, st->sent_value, st->recv_value);
}

static void
network_stats_print_stat(GArray *stats,int nproc)
{
	for(guint index = 0; index < (guint)nproc; index++)
	{
		network_stats_entry temp = g_array_index (stats, network_stats_entry, index);
		network_stats_print_entry(&temp);
		if(stats->len>index	)
		stats = g_array_remove_index(stats, index);
	}
	network_stats_get_global_instance(stats);
}

static void
do_refresh()
{
	global_hashes test_hash = get_global_hashes_instance();
	test_hash.inode_table = NULL;
	test_hash.hash_table = NULL;
	test_hash = get_global_hashes_instance();
	glibtop_get_netsockets ("/proc/self/net/tcp", test_hash.inode_table, test_hash.hash_table);
	GSList *curproc = get_proc_list_instance(NULL);
	int nproc = g_slist_length(curproc);
	GArray *network_stats_instance = network_stats_get_global_instance(NULL);
	GPtrArray **set_dbus_stats_to_null = glibtop_get_stats_instance(NULL);
	//free the previous entries in dbus stats
	g_ptr_array_free(*set_dbus_stats_to_null, FALSE);
	*set_dbus_stats_to_null = NULL;
	GPtrArray *dbus_stats_instance = *(glibtop_get_stats_instance(NULL));
	while (curproc != NULL)
	{
		g_assert(curproc->data != NULL);
		guint value_sent = 0;
		guint value_recv = 0;
		struct timeval t;
		t.tv_sec = 0;
		t = get_curtime(t);
		Net_process_get_bytes(Net_process_list_get_proc(curproc), &value_recv, &value_sent, t);
		/**
		* use cases:
		* (RAW STATS) Use this to print the stats on the terminal (uncomment this to use raw data)
		* (INTERFACE with APPLICATIONS) As now it's proposed that DBus will be used to consume
		*  the stats in applications so instatiate the dbus_stats which is GArray of ptr to stats 
		*  struct
		*/
		network_stats_entry temp_stats;
		network_stats_init(&temp_stats,
		                   value_recv,
		                   value_sent,
		                   Net_process_list_get_proc(curproc)->pid);
		network_stats_instance = g_array_prepend_val(network_stats_instance, temp_stats);
		network_stats_get_global_instance(network_stats_instance);
		//new instance of stats (dbus) with curproc , prepend , get_instanceNet_process_list_get_proc(curproc)->pid
		if (value_sent > 0  || value_recv > 0)
		{
			stats *temp_dbus_stats = new_stats((guint)Net_process_list_get_proc(curproc)->pid,
									  value_sent,
									  value_recv);
			g_ptr_array_add (dbus_stats_instance, temp_dbus_stats);
		}
			network_stats_print_stat(network_stats_get_global_instance(NULL), nproc);
	printf("\n\n\n");
		curproc = curproc->next;

	}
}

gboolean
glibtop_init_packet_capture (void)
{
	global_hashes test_hash = get_global_hashes_instance();
	glibtop_socket *socket_list = glibtop_get_netsockets ("/proc/self/net/tcp", test_hash.inode_table, test_hash.hash_table);
	packet_handle *handles = get_global_packet_handles(NULL);
	packet_args *userdata = g_slice_new(packet_args);
	for(packet_handle *current_handle = handles; current_handle != NULL; current_handle = current_handle->next)
		{
			userdata->device = current_handle->device_name;
			userdata->sa_family = AF_UNSPEC;

			if (current_handle->pcap_handle == NULL)
				continue;
			int retval = packet_dispatch(current_handle, 0, (u_char *)userdata, sizeof(packet_args))	;
			if (retval < 0)
				g_error("Error dispatching for device %s \n ", current_handle->device_name);
		}
		time_t const now = time(NULL);
		if (last_refresh_time + refresh_delay <= now)
		{
			last_refresh_time = now;
			g_slice_free(glibtop_socket, socket_list);
			do_refresh();
		}
	return (glibtop_get_capture_status(FALSE));
}

void
glibtop_init_netstats(void)
{
	process_init();
	packet_handle *handles = open_pcap_handles();
	get_global_packet_handles(handles);
}
