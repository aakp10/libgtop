#include <glibtop/connection.h>
#include <glibtop/packet.h>
#include <stdio.h>

GSList *
Packet_list_init(GSList *pktlist, Packet *pkt_val)
{
	return g_slist_append(pktlist, pkt_val);
}

//adding a packet to the linked list
void addPacket(GSList **pktlist, Packet *pkt)
{
	if (*pktlist == NULL)
	{	
		Packet *copy_pkt = g_slice_new(Packet);
		Packet_init(copy_pkt, pkt);
		*pktlist = Packet_list_init(*pktlist, copy_pkt);
		return;
	}
	if ((Packet *)((*pktlist)->data) != NULL)
	{
		if (((Packet *)((*pktlist)->data))->time.tv_sec == pkt->time.tv_sec)
		{
			((Packet *)((*pktlist)->data))->len += pkt->len;
			return;
		}
	}
	
	Packet *copy_pkt = g_slice_new(Packet);
	Packet_init(copy_pkt, pkt);
	*pktlist = Packet_list_init(*pktlist, copy_pkt);
}

//this packet to get the time of the last pcket capture for th given connection
void 
add_packet_to_connection(Connection *conn, Packet *pkt)
{	printf("ADDING to %d:%d pkt %d:%d\n", conn->ref_packet->sport, conn->ref_packet->dport, pkt->sport, pkt->dport);
	conn->last_packet_time = pkt->time.tv_sec;
	//if outgoing or incoming accordingly add the packet to respective packet list sent or recv i.e malloc a new 
	if (is_pkt_outgoing(pkt)) //check packet.c
	{
		conn->bytes_sent += pkt->len;
		addPacket(&(conn->sent_packets), pkt);
	}
	else
	{
		conn->bytes_recv += pkt->len;
		addPacket(&(conn->received_packets), pkt);
	}
}

GSList *
Conn_list_init(GSList *clist, Connection *conn_val)
{
	return g_slist_append(clist, conn_val);
}

Connection *
Conn_list_get_connection(GSList *clist)
{
	return clist->data;
}

GSList *
Connection_list_get_next(GSList *clist)
{
	return clist->next;
}

GSList *
get_global_connections_instance(GSList *val)
{
	static GSList *global_connections_list = NULL;
	if (val != NULL)
		global_connections_list = val;
	return global_connections_list;
}

void
Connection_init(Connection *conn, Packet *pkt)
{
	GSList *connections = get_global_connections_instance(NULL);
	GSList *temp = Conn_list_init(connections, conn);
	get_global_connections_instance(temp); //to set connections = temp in the static var global_connections_list
	conn->sent_packets = NULL;

	conn->received_packets = NULL;
	conn->bytes_sent = 0;
	conn->bytes_recv = 0;
	printf("new conn w/ pkt len = %d\n", pkt->len );
	if (is_pkt_outgoing(pkt))
	{
		conn->bytes_sent += pkt->len;
		addPacket(&(conn->sent_packets), pkt);
		conn->ref_packet = g_slice_new(Packet);
		Packet_init(conn->ref_packet, pkt);
		printf("New reference packet created at %d: \n",conn->ref_packet->sport );
	}
	else
	{
		conn->bytes_recv += pkt->len;
		addPacket(&(conn->received_packets), pkt);
		conn->ref_packet = get_inverted_packet(pkt);
		printf("New reference packet created at %d:\n", conn->ref_packet->sport );
	}
	conn->last_packet_time = pkt->time.tv_sec;
	
}

Connection *
find_connection_with_matching_source(Packet *pkt)
{	
	GSList *current = get_global_connections_instance(NULL);
	while (current != NULL)
	{
		if (packet_match_source(pkt, Conn_list_get_connection(current)->ref_packet))
			return current->data;
		current = current->next;
	}
	return NULL;
}

//can be used later to debug 
void 
print_packet_list(Connection *conn)
{	
	int i = 1;
	GSList *sent_packets;
	GSList *received_packets;
	if (conn->sent_packets)
		sent_packets = conn->sent_packets;
	if (conn->received_packets)
		received_packets = conn->received_packets;
	printf("SENT PACKETS\n");
	GSList *previous = NULL;
	while (sent_packets != NULL && previous != sent_packets)
	{	
		if (sent_packets->data)
		{
			printf("%d. %dbytes\n", i++, ((Packet *)(sent_packets->data))->len);
			previous = sent_packets;
			sent_packets = sent_packets->next;
		}
		else
			break;
	}
	
	previous = NULL;
	printf("received_packets\n");
	i = 1;
	while (received_packets != NULL && previous != received_packets)
	{	if (received_packets->data)
		{
			printf("%d. %dbytes\n", i++, ((Packet *)received_packets->data)->len);
			previous = received_packets;
			received_packets = received_packets->next;
		}
		else
			return;
	}
}

//can be used to debug
void 
print_global_connection_list()
{	
	printf("CONNECTION LIST\n");
	GSList *current = get_global_connections_instance(NULL);
	while (current != NULL)
	{
		printf("bytes_recv:%d from%d bytes sent %d sent %d\n",((Connection *)(current->data))->bytes_recv, 
															((Connection *)(current->data))->ref_packet->sport, 
															((Connection *)(current->data))->bytes_sent, 
															((Connection *)(current->data))->ref_packet->dport);
		print_packet_list(current->data);
		current = current->next;
	}
}

Connection *
find_connection_with_matching_ref_packet_or_source(Packet *pkt)
{
	GSList *current = get_global_connections_instance(NULL);
	while (current != NULL)
	{	
		if (packet_match(pkt, Conn_list_get_connection(current)->ref_packet))
			return current->data;
		current = current->next;
	}
	return find_connection_with_matching_source(pkt);
}

Connection *
find_connection(Packet *pkt)
{
	if (is_pkt_outgoing(pkt))
		return find_connection_with_matching_ref_packet_or_source(pkt);
	else
	{
		Packet *inverted_packet = get_inverted_packet(pkt);
		Connection *result = find_connection_with_matching_ref_packet_or_source(inverted_packet);
		g_slice_free(Packet, inverted_packet);
		return result;
	}
}

int 
Connection_get_last_packet_time(Connection *conn)
{
	return conn->last_packet_time;
}

guint64 Packet_list_sum_and_del(GSList *pktlist, struct timeval t)
{
	guint64 sum = 0;
	int i=0;
	GSList *current = pktlist;
	GSList *previous = NULL;
	while (current != NULL && previous != current && current->data)
	{	
		if (!(((Packet *)(current->data))->time.tv_sec <= t.tv_sec - PERIOD))
		{ 
			sum += ((Packet *)current->data)->len;
		}
		previous = current;
		current = current->next;
	}
	return sum;
}

void
Connection_sum_and_del(Connection *conn, struct timeval t, guint64 *recv, guint64 *sent)
{
 	*sent = 0;
	*recv = 0;
	if(conn->sent_packets->data == NULL)
		printf("null packet list\n");
	*sent = Packet_list_sum_and_del(conn->sent_packets, t);
	*recv = Packet_list_sum_and_del(conn->received_packets, t);
}