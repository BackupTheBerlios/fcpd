/***************************************************************************
                          api.c
                             -------------------
    begin                : Tue Dec 19 2000
    copyright            : (C) 2000 by Ulrich Abend, Nils Ohlmeier
    email                : ullstar@ullstar.de, develop@ohlmeier.org
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/version.h>

#ifdef LINUX_VERSION_CODE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ipt_tos.h>
#include <linux/netfilter_ipv4/ipt_TOS.h>
#include <linux/netfilter_ipv4/ipt_LOG.h>
#include <linux/netfilter_ipv4/ipt_limit.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <libipfwc/ipfwc_kernel_headers.h>
#include <libipfwc/libipfwc.h>
#endif

#include "api.h"
#include "debug.h"

/* This if devides the ipchains and the iptables code */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)

#include "main.h"

#define FCP_API_LOGGING_LEVEL LOG_NOTICE
#define FCP_API_LOGGING_PREFIX "fcpd"

/* This struct holds the socket number, the port number of the socket and a
   pointer to the next structure/socket. */
struct api_socket
{
  int socket;
  int port;
  struct api_socket *next;
};

/* This is the first element of the list of allocated sockets and should
   always be empty. */
struct api_socket socket_list;

/* Arrays which holds the number of rules of this priority class in this
   chain. */
int priority_classes_input[FCP_MAX_PRIORITY_CLASSES];
int priority_classes_output[FCP_MAX_PRIORITY_CLASSES];
int priority_classes_forward[FCP_MAX_PRIORITY_CLASSES];

/* This int stores the determined chain for the filter table. This make it a
   lot easyer to know which of the above arrays we have to modifiy. */
int filter_chain;

/* Very dirty hack: offset and size of the hole in the deleting mask, where
   we don't set the memory to 0xFF */
size_t mask_hole_offset, mask_hole_size;

/* This helper logs an ipt_entry */
void log_ipt_entry (struct ipt_entry *e)
{
  sprintf (debug_msg_helper, "src: %u dst: %u", e->ip.src.s_addr,
		   e->ip.dst.s_addr);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "smsk: %u dmsk: %u", e->ip.smsk.s_addr,
		   e->ip.dmsk.s_addr);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "iniface: %s outiface: %s", e->ip.iniface,
		   e->ip.outiface);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "iniface_mask: %s outiface_mask: %s",
		   e->ip.iniface_mask, e->ip.outiface_mask);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "proto: %u flags: %u invflags: %u", e->ip.proto,
		   e->ip.flags, e->ip.invflags);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "nfcache: %u", e->nfcache);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "target_offset: %u next_offset: %u",
		   e->target_offset, e->next_offset);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "comefrom: %u pcnt: %u bcnt: %u", e->comefrom,
		   (unsigned int)e->counters.pcnt, (unsigned int)e->counters.bcnt);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "elems: %u", e->elems[0]);
  fcp_log (LOG_DEBUG, debug_msg_helper);
}

/* This helper logs an ipt_entry_target */
void log_ipt_entry_target (struct ipt_entry_target *t)
{
  sprintf (debug_msg_helper, "user.target_size: %u user.name: %s",
		   t->u.user.target_size, t->u.user.name);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "u.target_size: %u", t->u.target_size);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "data: %u", t->data[0]);
  fcp_log (LOG_DEBUG, debug_msg_helper);
}

/* Trying to convert a state into an ipt_entry for iptables. Returns TRUE for
   OK and 0 if failed. If returned 0 the string error will be filled with
   reason for returning to client. If option is 1 a ipt_entry sturcture for
   the NAT table have to be created. If option is 2 a ipt_entry structure for
   the mangle tabel have to be cereated. If option is 3 a ipt_entry strucutre
   for LOG target have to be created. */
static struct ipt_entry *state_to_iptentry (struct fcp_state *state,
											char *error, int option)
{
  /* only helper variable */
  struct fcp_state fcp = *state;
  /* fw is temporary header structure, and ret is what the function returns */
  struct ipt_entry *fw, *ret;
  /* the temporary match structure */
  struct ipt_entry_match *match;
  /* the temporary target structure */
  struct ipt_entry_target *target;
  /* the temporary nat strucutre */
  struct ip_nat_multi_range *nat;
  /* a helper to go through the fcp_internals_ips */
  // struct fcp_address_list *list;
  /* the sizes of the header, the target, the match, and the return */
  size_t fw_size, target_size, match_size, ret_size;
  /* target_b and macht_b are boolean which indicate if we have a match at
     the end. if return_val is zero an error occured and we return nothing.
     intf_name_size stores how long the interface mask have to be. ip_found
     indicates if the srcip in member of the internal ips. */
  int target_b, match_b, return_val, intf_name_size;

	/* ugly, but don't wan't to copy this code three times */
	void create_match ()
	{
		/* allocate memory or report error if it fails */
		match = malloc (match_size);
		if (!match)
		{
			fcp_log (LOG_CRIT,
					 "API: state_to_iptentry: couldn't allocate memory for match");
			sprintf (error,
					 "500 Server Internal Error: couldn't allocate memory");
			return_val = 0;
		}
		/* null the allocated memory, set the sizes, and indicate that we have a
			 match sturcture now */
		memset (match, 0, match_size);
		match->u.user.match_size = match_size;
		match->u.match_size = match_size;
		match_b = 1;
  }

  /* initalies the local variables correct */
  return_val = 1;
  target_b = 0;
  match_b = 0;
  ret_size = 0;
  match_size = 0;
  target_size = 0;
  // ip_found = 0;

  /* first of all allocate a header, null the memory and set the according
     offsets */
  fw_size = IPT_ALIGN (sizeof (struct ipt_entry));
  fw = malloc (fw_size);
  if (!fw)
	{
	  fcp_log (LOG_CRIT,
			   "API: state_to_iptentry: couldn't allocate memory for fw");
	  sprintf (error, "500 Server Internal Error: couldn't allocate memory");
	  return NULL;
	}
  memset (fw, 0, fw_size);
  fw->next_offset = fw_size;
  fw->target_offset = fw_size;

  /* if masq is set we have to create a structure for the NAT table */
  if (option == 1)
	{
	  /* allocate memory for both structures, null it, set the offsets
	     correct and indicate that we have a target now */
	  target_size = IPT_ALIGN (sizeof (struct ipt_entry_target) +
							   sizeof (struct ip_nat_multi_range));
	  target = malloc (target_size);
	  if (!target)
		{
		  fcp_log (LOG_CRIT,
				   "API: state_to_iptentry: couldn't allocate"
                   " memory for nat_target");
		  sprintf (error,
				   "500 Server Internal Error: couldn't allocate memory");
		  free (fw);
		  return NULL;
		}
	  memset (target, 0, target_size);
	  target->u.user.target_size = target_size;
	  target->u.target_size = target_size;
	  target_b = 1;

	  /* search the srcip in the list of internal ips */
	  /* list = fcp_internal_ips.next; while (list && !ip_found) { ip_found =
	     ip_is_in_tuple (list->address, list->netmask, fcp.pme->src_ip); list
	     = list->next; } */
	  /* If the direction is OUT_IN we make destination NAT otherwise we make
	     source NAT. */
	  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
		strcpy (target->u.user.name, "DNAT");
	  else
		strcpy (target->u.user.name, "SNAT");

	  /* set the nat pointer so that we can fill the nat structure and set
	     that we have only one ip_nat_range strucute (cause we support only
	     one IP for NAT) */
	  nat = (struct ip_nat_multi_range *) target->data;
	  nat->rangesize = 1;
	  /* set the flag and copy the masquerading IP */
	  nat->range->flags |= IP_NAT_RANGE_MAP_IPS;
	  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
		nat->range->min_ip = nat->range->max_ip = fcp.pme->dst_ip;
	  else
		nat->range->min_ip = nat->range->max_ip = fcp.masq_ip;
	  /* we should have a masq port but we also need a protocol for NAT */
	  if (fcp.masq_port && fcp.pme->proto_def)
		{
		  /* set the flag that we have a port */
		  nat->range->flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
		  /* if TCP is defined copy the masq port to TCP structure */
		  if (fcp.pme->proto == 6)
			{
			  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
				nat->range->min.tcp.port = nat->range->max.tcp.port =
				  htons (fcp.pme->dst_pt);
			  else
				nat->range->min.tcp.port = nat->range->max.tcp.port =
				  htons (fcp.masq_port);
			}
		  /* if UDP is defined copy the masq port to UDP strucutre */
		  else if (fcp.pme->proto == 17)
			{
			  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
				nat->range->min.udp.port = nat->range->max.udp.port =
				  htons (fcp.pme->dst_pt);
			  else
				nat->range->min.udp.port = nat->range->max.udp.port =
				  htons (fcp.masq_port);
			}
		  /* if a port range was requested we have to copy the upper port
		     also */
		  if (fcp.masq_uppt)
			{
			  if (fcp.pme->proto == 6)
				{
				  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
					nat->range->max.tcp.port = htons (fcp.pme->dst_uppt);
				  else
					nat->range->max.tcp.port = htons (fcp.masq_uppt);
				}
			  else if (fcp.pme->proto == 17)
				{
				  if (fcp.direction == OUT_IN || fcp.direction == DMZ_IN)
					nat->range->max.udp.port = htons (fcp.pme->dst_uppt);
				  else
					nat->range->max.udp.port = htons (fcp.masq_uppt);
				}
			}
		}
	}
  /* if option is 2 we have to build a TOS target for the mangle table */
  else if (option == 2)
	{
	  struct ipt_tos_target_info *tos;

	  /* first check if we know the tos value */
	  if (fcp.sop->packet_modf.tos_fld == 16
		  || fcp.sop->packet_modf.tos_fld == 8
		  || fcp.sop->packet_modf.tos_fld == 4
		  || fcp.sop->packet_modf.tos_fld == 2
		  || fcp.sop->packet_modf.tos_fld == 0)
		{
		  /* allocate the memory for the target and fill it with values */
		  target_size = IPT_ALIGN (sizeof (struct ipt_entry_target) +
								   sizeof (struct ipt_tos_target_info));
		  target = malloc (target_size);
		  if (!target)
			{
			  fcp_log (LOG_CRIT,
					   "API: state_to_iptentry: couldn't allocate memory for"
                       " mangle_target");
			  sprintf (error,
					   "500 Server Internal Error: couldn't allocate memory");
			  free (fw);
			  return NULL;
			}
		  memset (target, 0, target_size);
		  target->u.user.target_size = target_size;
		  target->u.target_size = target_size;
		  target_b = 1;

		  strcpy (target->u.user.name, "TOS");
		  tos = (struct ipt_tos_target_info *) target->data;
		  tos->tos = fcp.sop->packet_modf.tos_fld;
		}
	  else
		{
		  sprintf (error,
				   "402 Invalid Control State Field Value: unknown/unsurported"
                   " type of service (TOS) %u in packet modifier",
				   fcp.sop->packet_modf.tos_fld);
		  return NULL;
		}
	}
  /* if option is 3 we have to build rule with log target */
  else if (option == 3)
	{
	  /* allocate memory and fill it with the correct values */
	  struct ipt_log_info *log;

	  target_size = IPT_ALIGN (sizeof (struct ipt_entry_target) +
							   sizeof (struct ipt_log_info));
	  target = malloc (target_size);
	  memset (target, 0, target_size);
	  target->u.user.target_size = target_size;
	  target->u.target_size = target_size;
	  strcpy (target->u.user.name, "LOG");
	  target_b = 1;

	  log = (struct ipt_log_info *) target->data;
	  log->level = FCP_API_LOGGING_LEVEL;
	  strcpy (log->prefix, FCP_API_LOGGING_PREFIX);

	  fw->nfcache |= NFC_UNKNOWN;
	}
  /* masquerading, mangleing and logging isn't asked so make a normal target */
  else
	{
	  /* a target is always needed. we use a normal target with nothing in
	     it, or with pass or drop in it. */
	  if ((!fcp.sop) || (!fcp.sop->action_def)
		  || (fcp.sop->action == fcp_action_pass)
		  || (fcp.sop->action == fcp_action_drop))
		{
		  /* allocate memory for the traget, null it, set the offsets and the
		     target boolean */
		  target_size =
			IPT_ALIGN (sizeof (struct ipt_entry_target) + sizeof (int));
		  target = malloc (target_size);
		  if (!target)
			{
			  fcp_log (LOG_CRIT,
					   "API: state_to_iptentry: couldn't allocate memory for"
                       " target");
			  sprintf (error,
					   "500 Server Internal Error: couldn't allocate memory");
			  free (fw);
			  return NULL;
			}
		  memset (target, 0, target_size);
		  target->u.user.target_size = target_size;
		  target->u.target_size = target_size;
		  target_b = 1;

		  /* set the action if it's requested else we let it empty */
		  if (fcp.sop->action == fcp_action_pass)
			strcpy (target->u.user.name, "ACCEPT");
		  else if (fcp.sop->action == fcp_action_drop)
			strcpy (target->u.user.name, "DROP");
		}
	  /* create a special icmp target for action reject */
	  else if (fcp.sop->action == fcp_action_reject)
		{
		  struct ipt_reject_info *rej;

		  /* allocate memory for the traget, null it, set the offsets and the
		     target boolean */
		  target_size =
			IPT_ALIGN (sizeof (struct ipt_entry_target) +
					   sizeof (struct ipt_reject_info));
		  target = malloc (target_size);
		  if (!target)
			{
			  fcp_log (LOG_CRIT,
					   "API: state_to_iptentry: couldn't allocate memory for"
                       " target and reject_info");
			  sprintf (error,
					   "500 Server Internal Error: couldn't allocate memory");
			  free (fw);
			  return NULL;
			}
		  memset (target, 0, target_size);
		  target->u.user.target_size = target_size;
		  target->u.target_size = target_size;
		  target_b = 1;

			/* the target is REJECT and set pointer so that we can fill it */
			strcpy (target->u.user.name, "REJECT");
			rej = (struct ipt_reject_info *) target->data;
			if (fcp.sop->icmp_msg_def)
			{
				/* only destination unreachable is supported */
				if (fcp.sop->icmp_msg == 3)
				{
					if (fcp.sop->icmp_msg_code_def)
					{
						/* switch the requested icmp message code if one is requested */
						switch (fcp.sop->icmp_msg_code)
						{
							case 0:
								rej->with = IPT_ICMP_NET_UNREACHABLE;
								break;
							case 1:
								rej->with = IPT_ICMP_HOST_UNREACHABLE;
								break;
							case 2:
								rej->with = IPT_ICMP_PROT_UNREACHABLE;
								break;
							case 3:
								rej->with = IPT_ICMP_PORT_UNREACHABLE;
								break;
							case 9:
								rej->with = IPT_ICMP_NET_PROHIBITED;
								break;
							case 10:
								rej->with = IPT_ICMP_HOST_PROHIBITED;
								break;
							default:
								sprintf (debug_msg_helper,
										"API: Unsupported icmp message code (%i) requested",
										fcp.sop->icmp_msg_code);
								fcp_log (LOG_WARNING, debug_msg_helper);
								sprintf (error,
									"402 Invalid Control State Field Value: unknown/unsurported"
									" ICMP message code");
								return_val = 0;
								break;
						}
					}
					/* no type requested so we take our default */
					else
						rej->with = IPT_ICMP_HOST_UNREACHABLE;
				}
				else
				{
					sprintf (debug_msg_helper,
								"API: Unsupported icmp message (%i) requested",
								fcp.sop->icmp_msg);
					fcp_log (LOG_WARNING, debug_msg_helper);
					sprintf (error,
								"402 Invalid Control State Field Value: unknown/unsurported"
								" ICMP message type");
					return_val = 0;
				}
			}
			/* default if protocol is icmp but no message was requested is host
				 unreachebale, what else... ;-) */
			else
				rej->with = IPT_ICMP_HOST_UNREACHABLE;
		}
	}

  /* Copy source and destination IPs if defined */
  if (fcp.pme->src_ip_def)
	{
	  fw->ip.src.s_addr = fcp.pme->src_ip;
	  fw->nfcache |= NFC_IP_SRC;
	}
  if (fcp.pme->dst_ip_def)
	{
	  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
		  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
		fw->ip.dst.s_addr = fcp.masq_ip;
	  else
		fw->ip.dst.s_addr = fcp.pme->dst_ip;
	  fw->nfcache |= NFC_IP_DST;
	}

  /* Copy netmasks if defined; if only an IP was defined set to
     255.255.255.255 */
  if (fcp.pme->src_netmask_def)
	fw->ip.smsk.s_addr = fcp.pme->src_netmask;
  else if (fcp.pme->src_ip_def)
	fw->ip.smsk.s_addr = 0xFFFFFFFF;
  if (fcp.pme->dst_netmask_def)
	fw->ip.dmsk.s_addr = fcp.pme->dst_netmask;
  else if (fcp.pme->dst_ip_def)
	fw->ip.dmsk.s_addr = 0xFFFFFFFF;

  /* If a protocol is defines copy it */
  if (fcp.pme->proto_def)
	{
	  fw->ip.proto = fcp.pme->proto;
	  fw->nfcache |= NFC_IP_PROTO;
	}

  /* If an interface is specified copy it to the right place */
  if (fcp.pme->in_if_def || fcp.pme->out_if_def)
	{
	  /* First check if all name which are requiered for this request not to
	     long and exists (e.g. DMZ) */
	  if ((fcp.pme->in_if == FCP_INTERFACE_IN
		   || fcp.pme->out_if == FCP_INTERFACE_IN)
		  && strlen (fcp_in_interface.name) > IFNAMSIZ)
		{
		  sprintf (error,
				   "500 Server Internal Error: name of interface IN is to"
                   " long");
		  return_val = 0;
		}
	  if ((fcp.pme->in_if == FCP_INTERFACE_OUT
		   || fcp.pme->out_if == FCP_INTERFACE_OUT)
		  && strlen (fcp_out_interface.name) > IFNAMSIZ)
		{
		  sprintf (error,
				   "500 Server Internal Error: name of interface OUT is to"
                   " long");
		  return_val = 0;
		}
	  if ((fcp.pme->in_if == FCP_INTERFACE_DMZ
		   || fcp.pme->out_if == FCP_INTERFACE_DMZ)
		  && !fcp_dmz_interface.name)
		{
		  sprintf (error,
				   "500 Server Internal Error: name of interface DMZ is not"
                   " specified");
		  return_val = 0;
		}
	  if ((fcp.pme->in_if == FCP_INTERFACE_DMZ
		   || fcp.pme->out_if == FCP_INTERFACE_DMZ) && fcp_dmz_interface.name
		  && strlen (fcp_dmz_interface.name) > IFNAMSIZ)
		{
		  sprintf (error,
				   "500 Server Internal Error: name of interface DMZ is to"
                   " long");
		  return_val = 0;
		}
	  /* *FIXME*nils* if only one interface is given we have to install two
	     rules. one in the FORWARD and one in the INPUT or OUTPUT chain. this
	     is to complecated so we report an error. */
	  if ((fcp.pme->in_if_def && !fcp.pme->out_if_def) ||
		  (fcp.pme->out_if_def && !fcp.pme->in_if_def))
		{
		  sprintf (error,
				   "501 Not Implemented: no support for mutiple interface"
                   " (only one interface was specified)");
		  return_val = 0;
		}
		/* If all checks above are ok copy the strings */
		if (return_val)
		{
			/* If the packet comes from loopback or we make SNAT we can only
				 specifie an out interface */
			if (fcp.pme->in_if == FCP_INTERFACE_LOOPBACK ||
					(option == 1 && fcp.pme->out_if_def &&
					(fcp.direction == IN_OUT || fcp.direction == IN_DMZ)))
				switch (fcp.pme->out_if)
				{
					case FCP_INTERFACE_IN:
						strcpy (fw->ip.outiface, fcp_in_interface.name);
						break;
					case FCP_INTERFACE_OUT:
						strcpy (fw->ip.outiface, fcp_out_interface.name);
						break;
					case FCP_INTERFACE_DMZ:
						strcpy (fw->ip.outiface, fcp_dmz_interface.name);
						break;
				}
			/* If the packet goes to loopback or we make DNAT we can only
				 specifie an in interface */
			else if (fcp.pme->out_if == FCP_INTERFACE_LOOPBACK ||
					(option == 1 && fcp.pme->in_if_def &&
					(fcp.direction = OUT_IN || fcp.direction == DMZ_IN)))
				switch (fcp.pme->in_if)
				{
					case FCP_INTERFACE_IN:
						strcpy (fw->ip.iniface, fcp_in_interface.name);
						break;
					case FCP_INTERFACE_OUT:
						strcpy (fw->ip.iniface, fcp_out_interface.name);
						break;
					case FCP_INTERFACE_DMZ:
						strcpy (fw->ip.iniface, fcp_dmz_interface.name);
						break;
				}
			/* we route the packet only so it goes through two interfaces and
				 we switch both. if both interfaces are equal are checked at
				 validity */
			else
			{
				switch (fcp.pme->in_if)
				{
					case FCP_INTERFACE_IN:
						strcpy (fw->ip.iniface, fcp_in_interface.name);
						break;
					case FCP_INTERFACE_OUT:
						strcpy (fw->ip.iniface, fcp_out_interface.name);
						break;
					case FCP_INTERFACE_DMZ:
						strcpy (fw->ip.iniface, fcp_dmz_interface.name);
						break;
				}
				switch (fcp.pme->out_if)
				{
					case FCP_INTERFACE_IN:
						strcpy (fw->ip.outiface, fcp_in_interface.name);
						break;
					case FCP_INTERFACE_OUT:
						strcpy (fw->ip.outiface, fcp_out_interface.name);
						break;
					case FCP_INTERFACE_DMZ:
						strcpy (fw->ip.outiface, fcp_dmz_interface.name);
						break;
				}
			}
		  /* If we have filled in an in interface we have to set the mask */
		  intf_name_size = strlen (fw->ip.iniface);
		  if (intf_name_size > 0)
			{
			  if (intf_name_size < IFNAMSIZ)
				memset (fw->ip.iniface_mask, 255, intf_name_size + 1);
			  else
				memset (fw->ip.iniface_mask, 255, IFNAMSIZ);
			}
		}
	  /* If have filled in an out interface we have to set the mask */
	  intf_name_size = strlen (fw->ip.outiface);
	  if (intf_name_size > 0)
		{
		  if (intf_name_size < IFNAMSIZ)
			memset (fw->ip.outiface_mask, 255, intf_name_size + 1);
		  else
			memset (fw->ip.outiface_mask, 255, IFNAMSIZ);
		}
	}

  /* if protocol should be TCP and a port or syn falg is requested we have to
     set up a TCP match structure */
  if (fcp.pme->proto == 6
	  && (fcp.pme->src_pt_def || fcp.pme->dst_pt_def || fcp.pme->syn_flg_def))
	{
	  struct ipt_tcp *tcp;

	  /* set the match size and call the ugly function above */
	  match_size =
		IPT_ALIGN (sizeof (struct ipt_entry_match) + sizeof (struct ipt_tcp));
		create_match ();
		if (!return_val)
			return NULL;

	  /* we want to match TCP and set the pointer to fill the structure */
	  strcpy (match->u.user.name, "tcp");
	  tcp = (struct ipt_tcp *) match->data;

	  /* copy a definied port. copy a definied upper port, otherwise copy the
	     port */
	  if (fcp.pme->src_pt_def)
		tcp->spts[0] = fcp.pme->src_pt;
	  else
		tcp->spts[1] = 65535;
	  if (fcp.pme->src_uppt_def)
		tcp->spts[1] = fcp.pme->src_uppt;
	  else if (fcp.pme->src_pt_def)
		tcp->spts[1] = fcp.pme->src_pt;

	  if (fcp.pme->dst_pt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			tcp->dpts[0] = fcp.masq_port;
		  else
			tcp->dpts[0] = fcp.pme->dst_pt;
		}
	  else
		tcp->dpts[1] = 65535;
	  if (fcp.pme->dst_uppt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			tcp->dpts[1] = fcp.masq_uppt;
		  else
			tcp->dpts[1] = fcp.pme->dst_uppt;
		}
	  else if (fcp.pme->dst_pt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			tcp->dpts[1] = fcp.masq_port;
		  else
			tcp->dpts[1] = fcp.pme->dst_pt;
		}

	  /* if syn is requested we set the flag, mask and inverse falg */
	  if (fcp.pme->syn_flg_def && !fcp.pme->syn_flg)
		{
		  tcp->flg_mask = 22;
		  tcp->flg_cmp = 2;
		  tcp->invflags = IPT_TCP_INV_FLAGS;
		}
	}

  /* if protocol is UDP and a port is requested we have to create a UDP match
     strucutre */
  if (fcp.pme->proto == 17 && (fcp.pme->src_pt_def || fcp.pme->dst_pt_def))
	{
	  struct ipt_udp *udp;

	  /* set the size and call the ugly function above */
	  match_size =
		IPT_ALIGN (sizeof (struct ipt_entry_match) + sizeof (struct ipt_udp));
		create_match ();
		if (!return_val)
			return NULL;

	  /* we have a UDP match and set the pointer to it */
	  strcpy (match->u.user.name, "udp");
	  udp = (struct ipt_udp *) match->data;

	  /* copy a definied port. copy a definied upper port, otherwise set it
	     to port */
	  if (fcp.pme->src_pt_def)
		udp->spts[0] = fcp.pme->src_pt;
	  else
		udp->spts[1] = 65535;
	  if (fcp.pme->src_uppt_def)
		udp->spts[1] = fcp.pme->src_uppt;
	  else if (fcp.pme->src_pt_def)
		udp->spts[1] = fcp.pme->src_pt;

	  if (fcp.pme->dst_pt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			udp->dpts[0] = fcp.masq_port;
		  else
			udp->dpts[0] = fcp.pme->dst_pt;
		}
	  else
		udp->dpts[1] = 65535;
	  if (fcp.pme->dst_uppt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			udp->dpts[1] = fcp.masq_uppt;
		  else
			udp->dpts[1] = fcp.pme->dst_uppt;
		}
	  else if (fcp.pme->dst_pt_def)
		{
		  if ((option == 1 || (option == 2 && fcp.masq_ip)) &&
			  (fcp.direction == OUT_IN || fcp.direction == DMZ_IN))
			udp->dpts[1] = fcp.masq_port;
		  else
			udp->dpts[1] = fcp.pme->dst_pt;
		}
	}

  /* if the protocol is icmp and a type is requested we have to set up a icmp
     match structure */
  if (fcp.pme->proto == 1 && fcp.pme->icmp_type_def)
	{
		struct ipt_icmp *icmp;
		int supported = 1;

		/* check if the icmp type and code are supported by netfilter. */
		switch (fcp.pme->icmp_type)
		{
			case 0:		// echo-reply
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 3:		// destination-unreachable
				if (fcp.pme->icmp_code_def && (fcp.pme->icmp_code > 15
						|| fcp.pme->icmp_code < 0 || fcp.pme->icmp_code == 8))
					supported = 0;
				break;
			case 4:		// source-quench
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 5:		// redirect
				if (fcp.pme->icmp_code_def && (fcp.pme->icmp_code < 0
						|| fcp.pme->icmp_code > 3))
					supported = 0;
				break;
			case 8:		// echo-request
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 9:		// router-advertisment
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 10:	// router-solicitation
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 11:	// time-exceeded
				if (fcp.pme->icmp_code_def && (fcp.pme->icmp_code != 0
						|| fcp.pme->icmp_code != 1))
					supported = 0;
				break;
			case 12:	// parameter-problem
				if (fcp.pme->icmp_code_def && (fcp.pme->icmp_code != 0
						|| fcp.pme->icmp_code != 1))
					supported = 0;
				break;
			case 13:	// timestamp-request
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 14:	// timestamp-reply
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 17:	// address-mask-request
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			case 18:	// address-mask-reply
				if (fcp.pme->icmp_code_def)
					supported = 0;
				break;
			default:
				supported = 0;
				break;
		}

		if (supported)
		{
			/* set the match size and call the ugly function above to allocate the
				 memory */
			match_size =
			IPT_ALIGN (sizeof (struct ipt_entry_match) +
									sizeof (struct ipt_icmp));
			create_match ();
			if (!return_val)
				return NULL;

			/* we want ICMP and set the pointer to the ICMP structure */
			strcpy (match->u.user.name, "icmp");
			icmp = (struct ipt_icmp *) match->data;

			/* a type was requested */
			icmp->type = fcp.pme->icmp_type;
			/* copy the icmp code if it was defined, otherwise set it to any */
			if (fcp.pme->icmp_code_def)
				icmp->code[0] = icmp->code[1] = fcp.pme->icmp_code;
			else
				icmp->code[1] = 0xFF;
		}
		else
		{
			sprintf (debug_msg_helper,
						"API: Unsupported icmp type (%i:%i) requested",
						fcp.pme->icmp_type, fcp.pme->icmp_code);
			fcp_log (LOG_WARNING, debug_msg_helper);
			sprintf (error,
							"402 Invalid Control State Field Value: unknown/unsurported"
							" ICMP type or code in PME");
			free (fw);
			free (target);
			if (match_b) free (match);
			return NULL;
		}
	}

  /* if tos is set in the PME, we have to build aother match */
  if (fcp.pme->tos_fld_def)
	{
	  struct ipt_tos_info *tos;
	  struct ipt_entry_match *old_match, *new_match;
	  size_t old_size, new_size;

	  /* first off all check if we know the requested tos value */
	  if (fcp.pme->tos_fld == 16 || fcp.pme->tos_fld == 8
		  || fcp.pme->tos_fld == 4 || fcp.pme->tos_fld == 2
		  || fcp.pme->tos_fld == 0)
		{
		  /* allocate memory for the tos match and fill it with values */
		  new_size =
			IPT_ALIGN (sizeof (struct ipt_entry_match) +
					   sizeof (struct ipt_tos_info));
		  new_match = malloc (new_size);
		  memset (new_match, 0, new_size);
		  new_match->u.user.match_size = new_size;
		  new_match->u.match_size = new_size;
		  strcpy (new_match->u.user.name, "tos");
		  tos = (struct ipt_tos_info *) new_match->data;
		  tos->tos = fcp.pme->tos_fld;

		  /* if another match exists we have to copy both into one memory
		     block */
		  if (match_b)
			{
			  old_size = match_size;
			  old_match = match;
			  match_size = IPT_ALIGN (match_size + new_size);
			  match = malloc (match_size);
			  memset (match, 0, match_size);
			  memcpy (match, old_match, old_size);
			  memcpy ((void *) match + old_size, new_match, new_size);
			  free (old_match);
			  free (new_match);
			}
		  /* if their is no other match install this as first */
		  else
			{
			  match_size = new_size;
			  match = new_match;
			  match_b = 1;
			}
		}
		else
		{
			sprintf (error,
							"402 Invalid Control State Field Value: unknown/unsurported"
							" type of service (TOS) %u in PME",
							fcp.pme->tos_fld);
			free (fw);
			free (target);
			if (match_b) free (match);
			return NULL;
		}
	}

  /* every logging rule will be limited to prevent to much logging, so we
     have to create a limit match */
  if (option == 3)
	{
	  struct ipt_rateinfo *limit;
	  struct ipt_entry_match *old_match, *new_match;
	  size_t old_size, new_size;

	  /* allocate memory for the limit match and fill it with values */
	  new_size =
		IPT_ALIGN (sizeof (struct ipt_entry_match) +
				   sizeof (struct ipt_rateinfo));
	  new_match = malloc (new_size);
	  memset (new_match, 0, new_size);
	  new_match->u.user.match_size = new_size;
	  new_match->u.match_size = new_size;
	  strcpy (new_match->u.user.name, "limit");

	  limit = (struct ipt_rateinfo *) new_match->data;
	  limit->burst = 5;
	  switch (fcp.sop->log)
		{
		case 1:
		  limit->avg = IPT_LIMIT_SCALE / fcp_log_per_sec;
		  break;
		case 2:
		  limit->avg = IPT_LIMIT_SCALE * 60 / fcp_log_per_min;
		  break;
		case 3:
		  limit->avg = IPT_LIMIT_SCALE * 60 * 60 / fcp_log_per_hou;
		  break;
		case 4:
		  if (fcp_log_per_day == 1)
			/* Very dirty but else we got an kernel internal overflow. */
			limit->burst = 3;
		  limit->avg = IPT_LIMIT_SCALE * 24 * 60 * 60 / fcp_log_per_day;
		  break;
		}

	  fw->nfcache |= NFC_UNKNOWN;

	  /* The limit match is the only one which contains variables which are
	     only used in the kernel and not in userland. If we try to delete
	     such a rule we have to mark that this kernel variables don't have to
	     be compared to the existing rules, because we don't know the values
	     of this variables. Because of this we store where the starting point
	     and size of this 'hole' in the deletion_mask here. */
	  mask_hole_offset = sizeof (limit->avg) + sizeof (limit->burst);
	  mask_hole_size = sizeof (struct ipt_rateinfo) - mask_hole_offset;
	  mask_hole_offset += fw_size + sizeof (struct ipt_entry_match);
	  /* If another match exists we have to copy both into one memory */
	  if (match_b)
		{
		  mask_hole_offset += match_size;
		  old_size = match_size;
		  old_match = match;
		  match_size = IPT_ALIGN (match_size + new_size);
		  match = malloc (match_size);
		  memset (match, 0, match_size);
		  memcpy (match, old_match, old_size);
		  memcpy ((void *) match + old_size, new_match, new_size);
		  free (old_match);
		  free (new_match);
		}
	  /* if their is no other match we this at first match */
	  else
		{
		  match_size = new_size;
		  match = new_match;
		  match_b = 1;
		}
	}

	/* everything should be set up correct, now calculate how big the returned
		 structure have to be */
	ret_size = fw_size;
	if (match_b)
		ret_size += match_size;
	if (target_b)
		ret_size += target_size;

	/* allocate the memory for the return and null it */
	ret = malloc (ret_size);
	if (!ret)
	{
		fcp_log (LOG_CRIT,
					"API: state_to_iptentry: couldn't allocate memory for ret");
		sprintf (error, "500 Server Internal Error: couldn't allocate memory");
		free (fw);
		if (target_b)
			free (target);
		if (match_b)
			free (match);
		return NULL;
	}
	memset (ret, 0, ret_size);

	/* copy the header (ipt_entry) and free it */
	memcpy (ret, fw, fw_size);
	free (fw);

	/* set the offsets in the header of the return */
	ret->target_offset = fw_size + match_size;
	ret->next_offset = ret_size;

	/* if we have a match copy it to the return and free the old */
	if (match_b)
	{
		memcpy ((void *) ret + fw_size, match, match_size);
		free (match);
	}
	/* if we have a target (i known that we always have one) copy and free it */
	if (target_b)
	{
		memcpy ((void *) ret + ret->target_offset, target, target_size);
		free (target);
	}

	/* if an error occured return nothing, otherwise return the hole strucutre */
	if (return_val)
		return ret;
	else
	{
		free (ret);
		return NULL;
	}
};

/* allocate memory for a delete mask, set bits in high, and return the
   pointer to this area (or NULL if failed). */
static unsigned char *make_delete_mask (unsigned int size)
{
  unsigned char *mask;

  mask = malloc (size);
  if (!mask)
	return NULL;
  memset (mask, 0xFF, size);
  /* We have to set the bits of the kernel variables of the limit match to
     zero because their are not compared at the search for a matching rule.
     See comments at state_to_iptentry. */
  if (mask_hole_offset)
	memset ((void *) mask + mask_hole_offset, 0, mask_hole_size);
  return mask;
};

/* This function determines the label of the destination chain for the state
   and copys the label to chain_label. If option is set to 1 it will assume
   that the masq_ip is set (no checks) and determine the according NAT-Table.
   If option is set to 2 it will assume that the mangle table is target. */
void set_chain_label (struct fcp_state *state, ipt_chainlabel * chain_label,
					  int option)
{
  /* *FIXME* Generall problem: what should we do, if the direction is
     NOT_SET? We then always go in the else tree an hope the best... ;-) */

  /* destination for masquerading */
  if (option == 1)
	{
	  /* Only if the direction is OUT_IN we have to substitude the
	     destination */
	  if (state->direction == OUT_IN || state->direction == DMZ_IN)
		strcpy ((char *) chain_label, "PREROUTING");
	  else
		strcpy ((char *) chain_label, "POSTROUTING");
	}
  /* destination mangle */
  else if (option == 2)
	{
	  if (state->direction == LOOP_IN ||
		  state->direction == LOOP_OUT || state->direction == LOOP_DMZ)
		strcpy ((char *) chain_label, "OUTPUT");
	  else
		strcpy ((char *) chain_label, "PREROUTING");
	}
  /* normal (filter) destination */
  else
	{
	  if (state->direction == IN_LOOP ||
		  state->direction == OUT_LOOP || state->direction == DMZ_LOOP)
		{
		  strcpy ((char *) chain_label, "INPUT");
		  filter_chain = 1;
		}
	  else if (state->direction == LOOP_IN ||
			   state->direction == LOOP_OUT || state->direction == LOOP_DMZ)
		{
		  strcpy ((char *) chain_label, "OUTPUT");
		  filter_chain = 2;
		}
	  else
		{
		  strcpy ((char *) chain_label, "FORWARD");
		  filter_chain = 3;
		}
	}
}

/* inserts a rule according to state. returns: 1: ok ; 0: failed the reason
   for failing should be in errstr. */
int fcp_rule_insert (struct fcp_state *state, char *errstr)
{
  /* a temporary return code */
  int ret, rule_position, i;
  /* destination tables can be nat, filter or mangle */
  char *nat_table = "nat";
  char *filter_table = "filter";
  char *mangle_table = "mangle";
  /* the handle of the destination table */
  iptc_handle_t handle = NULL;
  /* the structure we wan't to insert */
  struct ipt_entry *entry;
  /* the name of the destination chain */
  ipt_chainlabel default_chain;

  filter_chain = 0;
  rule_position = 0;

  /* If we have to modify the TOS field install this rule first */
  if (state->sop->packet_modf.tos_fld_def)
	{
	  /* try to get the handle for the mangle table */
	  handle = iptc_init (mangle_table);
	  if (!handle)
		{
		  fcp_log (LOG_ERR, "API: couldn't get handle for the table mangle");
		  fcp_log (LOG_ERR, "API: maybe missing iptable_mangle module ?!");
		  sprintf (errstr,
				   "502 Service Unavailable: TOS modifying support"
                   " missing ?!");
		  return 0;
		}
	  /* set the name of the chain */
	  set_chain_label (state, &default_chain, 2);
	  fcp_log (LOG_DEBUG,
			   "API: trying to convert state into ipt_entry for mangle");
	  /* convert a state into a ipt_entry structure (with mangleing) */
	  if ((entry = state_to_iptentry (state, errstr, 2)) != NULL)
		{
		  fcp_log (LOG_DEBUG,
				   "API: trying to insert mangle rule with iptc_insert_entry");
		  /* insert the structure. the place in the chain for mangle
		     shouldn't be relevant so use always 0 */
		  ret = iptc_insert_entry (default_chain, entry, 0, &handle);
		  if (ret)
			{
			  fcp_log (LOG_DEBUG, "API: mangle rule succesfull inserted");
			  /* and commit the changes we made */
			  if (iptc_commit (&handle))
				fcp_log (LOG_DEBUG, "API: mangle commit succesfull");
			  else
				{
				  sprintf (debug_msg_helper,
						   "API: mangle commit failed with %i", errno);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (debug_msg_helper, "API: %s",
						   iptc_strerror (errno));
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (errstr,
						   "500 Server Internal Error: rule commit"
                           " returned %i",
						   errno);
				  free (entry);
				  return 0;
				}
			}
		  else
			{
			  sprintf (debug_msg_helper,
					   "API: iptc_insert_entry for mangle retuned %i", errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: rule insert returned %i",
					   errno);
			  free (entry);
			  return 0;
			}
		}
	  else						/* state_to_iptentry failed */
		return 0;
	  free (entry);
	  handle = NULL;
	}

  /* If we have to masquerade this rule install the masq rule first */
  if (state->masq_ip)
	{
	  /* try to get the handle for the nat table */
	  handle = iptc_init (nat_table);
	  if (!handle)
		{
		  fcp_log (LOG_ERR, "API: couldn't get handle for the table nat");
		  fcp_log (LOG_ERR,
				   "API: maybe missing iptable_nat or ip_conntrack module ?!");
		  sprintf (errstr, "502 Service Unavailable: NAT support missing ?!");
		  return 0;
		}
	  /* set the name of the chain */
	  set_chain_label (state, &default_chain, 1);
	  fcp_log (LOG_DEBUG,
			   "API: trying to convert state into ipt_entry for masq");
	  /* convert a state into a ipt_entry structure (with masquerading) */
	  if ((entry = state_to_iptentry (state, errstr, 1)) != NULL)
		{
		  fcp_log (LOG_DEBUG,
				   "API: trying to insert masq rule with iptc_insert_entry");
		  /* insert the structure. the place in the chain for NAT shouldn't
		     be relevant so use always 0 */
		  ret = iptc_insert_entry (default_chain, entry, 0, &handle);
		  if (ret)
			{
			  fcp_log (LOG_DEBUG, "API: masq rule succesfull inserted");
			  /* and commit the changes we made */
			  if (iptc_commit (&handle))
				fcp_log (LOG_DEBUG, "API: masq commit succesfull");
			  else
				{
				  sprintf (debug_msg_helper,
						   "API: masq commit failed with %i", errno);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (debug_msg_helper, "API: %s",
						   iptc_strerror (errno));
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (errstr,
						   "500 Server Internal Error: rule commit"
                           " returned %i",
						   errno);
				  free (entry);
				  return 0;
				}
			}
		  else
			{
			  sprintf (debug_msg_helper,
					   "API: iptc_insert_entry for masq retuned %i", errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: rule insert returned %i",
					   errno);
			  free (entry);
			  return 0;
			}
		}
	  else						/* state_to_iptentry failed */
		return 0;
	  free (entry);
	  handle = NULL;
	}

  /* trying to get the handle for the default table filter */
  handle = iptc_init (filter_table);
  if (!handle)
	{
	  fcp_log (LOG_ERR, "API: couldn't get handle for the table filter");
	  fcp_log (LOG_ERR, "API: maybe missing iptables module ?!");
	  sprintf (errstr,
			   "502 Service Unavailable: iptables support missing ?!");
	  return 0;
	}
  /* set the name of the destination chain */
  set_chain_label (state, &default_chain, 0);

  fcp_log (LOG_DEBUG, "API: trying to convert state into ipt_entry");
  /* convert the state into an ipt_entry structure */
  if ((entry = state_to_iptentry (state, errstr, 0)) != NULL)
	{
	  /* If a priority class is requested calculate the position of the new
	     rule in their destination chain. */
	  if (state->sop->pri_class_def)
		{
		  if (filter_chain == 1)
			{
			  for (i = 0; i < state->sop->pri_class; i++)
				{
				  rule_position += priority_classes_input[i];
				}
			}
		  else if (filter_chain == 2)
			{
			  for (i = 0; i < state->sop->pri_class; i++)
				{
				  rule_position += priority_classes_output[i];
				}
			}
		  else if (filter_chain == 3)
			{
			  for (i = 0; i < state->sop->pri_class; i++)
				{
				  rule_position += priority_classes_forward[i];
				}
			}
		}
	  fcp_log (LOG_DEBUG,
			   "API: trying to insert rule with iptc_insert_entry");
	  /* ##################################### *FIXME* Simple pinholes hav
	     highest priority, so we insert them every time at place 0. In real
	     we have to determine with the priority classes where the rule have
	     to be inserted. ##################################### */
	  ret = iptc_insert_entry (default_chain, entry, rule_position, &handle);

	  if (ret)
		{
		  fcp_log (LOG_DEBUG, "API: rule succesfull inserted");
		  /* If logging is requested insert an aditional rule for logging */
		  if (state->sop->log_def)
			{
			  fcp_log (LOG_DEBUG,
					   "API: trying to convert state into ipt_entry for"
                       " logging");
			  /* convert a state into a ipt_entry structure (with logging) */
			  if ((entry = state_to_iptentry (state, errstr, 3)) != NULL)
				{
				  mask_hole_offset = 0;
				  mask_hole_size = 0;
				  fcp_log (LOG_DEBUG,
						   "API: trying to insert logging rule with"
                           " iptc_insert_entry");
				  if (iptc_insert_entry (default_chain, entry, 0, &handle))
					fcp_log (LOG_DEBUG,
							 "API: logging rule succesfull inserted");
				  else
					{
					  sprintf (debug_msg_helper,
							   "API: iptc_insert_entry for logging retuned %i",
							   errno);
					  fcp_log (LOG_ERR, debug_msg_helper);
					  sprintf (debug_msg_helper, "API: %s",
							   iptc_strerror (errno));
					  fcp_log (LOG_ERR, debug_msg_helper);
					  sprintf (errstr,
							   "500 Server Internal Error: rule insert"
                               " returned %i",
							   errno);
					  free (entry);
					  return 0;
					}
				}
			}
		  /* finaly commit the changes */
		  if (iptc_commit (&handle))
			{
			  /* After everything is okay increase the number of rules in the
			     priority class of their destination chain. Additionaly
			     increase the number of rule in priority class zero if logging
			     is requested. */
			  if (filter_chain == 1)
				{
				  priority_classes_input[state->sop->pri_class] =
					priority_classes_input[state->sop->pri_class] + 1;
				  if (state->sop->log_def)
					priority_classes_input[0] = priority_classes_input[0] + 1;
				}
			  else if (filter_chain == 2)
				{
				  priority_classes_output[state->sop->pri_class] =
					priority_classes_output[state->sop->pri_class] + 1;
				  if (state->sop->log_def)
					priority_classes_output[0] =
					  priority_classes_output[0] + 1;
				}
			  else if (filter_chain == 3)
				{
				  priority_classes_forward[state->sop->pri_class] =
					priority_classes_forward[state->sop->pri_class] + 1;
				  if (state->sop->log_def)
					priority_classes_forward[0] =
					  priority_classes_forward[0] + 1;
				}
			  fcp_log (LOG_DEBUG, "API: commit succesfull");
			}
		  else
			{
			  sprintf (debug_msg_helper, "API: commit failed with %i", errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: rule commit returned %i",
					   errno);
			  free (entry);
			  return 0;
			}
		}
	  else
		{
		  sprintf (debug_msg_helper, "API: iptc_insert_entry retuned %i",
				   errno);
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (errstr,
				   "500 Server Internal Error: rule insert returned %i",
				   errno);
		}
	  free (entry);
	  return ret;
	}
  else							/* state_to_iptentry failed and filled errstr
								   (hopefully) */
	return 0;
};

/* deletes a rule according to state. returns: 1: ok ; 0: delete failed on
   error the reason should be contained in errstr. for detailed comments see
   fcp_rule_insert. the only differenc is that we don't have a number in the
   chain instead we have to create a deltion mask which is big as the
   structure we want to delelte and filled with 0xFF. */
int fcp_rule_delete (struct fcp_state *state, char *errstr)
{
  int ret;
  char *nat_table = "nat";
  char *filter_table = "filter";
  char *mangle_table = "mangle";
  iptc_handle_t handle = NULL;
  struct ipt_entry *entry;
  ipt_chainlabel default_chain;
  unsigned char *mask;

  filter_chain = 0;

  /* If we have to modify the TOS field delete this rule first */
  if (state->sop->packet_modf.tos_fld_def)
	{
	  /* try to get the handle for the mangle table */
	  handle = iptc_init (mangle_table);
	  if (!handle)
		{
		  fcp_log (LOG_ERR, "API: couldn't get handle for the table mangle");
		  fcp_log (LOG_ERR, "API: maybe missing iptable_mangle module ?!");
		  sprintf (errstr,
				   "502 Service Unavailable: TOS modifying support"
                   " missing ?!");
		  return 0;
		}
	  /* set the name of the chain */
	  set_chain_label (state, &default_chain, 2);
	  fcp_log (LOG_DEBUG,
			   "API: trying to convert state into ipt_entry for mangle");
	  /* convert a state into a ipt_entry structure (with mangleing) */
	  if ((entry = state_to_iptentry (state, errstr, 2)) != NULL)
		{
		  mask = make_delete_mask (entry->next_offset);
		  if (!mask)
			{
			  fcp_log (LOG_CRIT,
					   "API: couldn't allocate memory for the deletion mask");
			  sprintf (errstr,
					   "500 Server Internal Error: couldn't allocate memory");
			  return 0;
			}
		  fcp_log (LOG_DEBUG,
				   "API: trying to delete mangle rule with iptc_delete_entry");
		  ret = iptc_delete_entry (default_chain, entry, mask, &handle);
		  if (ret)
			{
			  fcp_log (LOG_DEBUG, "API: mangle rule succesfull deleted");
			  if (iptc_commit (&handle))
				fcp_log (LOG_DEBUG, "API: mangle commit succesfull");
			  else
				{
				  sprintf (debug_msg_helper,
						   "API: mangle commit failed with %i", errno);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (debug_msg_helper, "API: %s",
						   iptc_strerror (errno));
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (errstr,
						   "500 Server Internal Error: rule commit"
                           " returned %i",
						   errno);
				  free (entry);
				  return 0;
				}
			}
		  else
			{
			  sprintf (debug_msg_helper,
					   "API: iptc_delete_entry for mangle retuned %i", errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: rule delete returned %i",
					   errno);
			  free (entry);
			  return 0;
			}
		}
	  else						/* state_to_iptentry failed */
			return 0;
	  free (entry);
	  handle = NULL;
	}

	/* If we have to masquerade this rule delete the masq rule first */
	if (state->masq_ip)
	{
		handle = iptc_init (nat_table);
		if (!handle)
		{
			fcp_log (LOG_ERR, "API: couldn't get handle for the table nat");
			fcp_log (LOG_ERR, "API: maybe missing iptable_nat or ip_conntrack module ?!");
			sprintf (errstr, "502 Service Unavailable: NAT support missing ?!");
			return 0;
		}
		set_chain_label (state, &default_chain, 1);
		fcp_log (LOG_DEBUG, "API: trying to convert state into ipt_entry for masq");
		if ((entry = state_to_iptentry (state, errstr, 1)) != NULL)
		{
			mask = make_delete_mask (entry->next_offset);
			if (!mask)
			{
				fcp_log (LOG_CRIT, "API: couldn't allocate memory for the deletion mask");
				sprintf (errstr, "500 Server Internal Error: couldn't allocate memory");
				return 0;
			}
			fcp_log (LOG_DEBUG, "API: trying to delete masq rule with iptc_delete_entry");
			ret = iptc_delete_entry (default_chain, entry, mask, &handle);
			if (ret)
			{
				fcp_log (LOG_DEBUG, "API: masq rule succesfull deleted");
				if (iptc_commit (&handle))
					fcp_log (LOG_DEBUG, "API: masq commit succesfull");
				else
				{
					sprintf (debug_msg_helper, "API: masq commit failed with %i", errno);
					fcp_log (LOG_ERR, debug_msg_helper);
					sprintf (debug_msg_helper, "API: %s", iptc_strerror(errno));
					fcp_log (LOG_ERR, debug_msg_helper);
					sprintf (errstr, "500 Server Internal Error: rule commit returned %i",
										errno);
					free (entry);
					return 0;
				}
			}
			else
			{
				sprintf (debug_msg_helper, "API: iptc_delete_entry for masq retuned %i",
									errno);
				fcp_log (LOG_ERR, debug_msg_helper);
				sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
				fcp_log (LOG_ERR, debug_msg_helper);
				sprintf (errstr, "500 Server Internal Error: rule delete returned %i",
									errno);
				free (entry);
				return 0;
			}
		}
		else /* state_to_iptentry failed */
			return 0;
		free (entry);
		handle = NULL;
	}

  /* trying to get the handle for the default table */
  handle = iptc_init (filter_table);
  if (!handle)
	{
	  fcp_log (LOG_ERR, "API: couldn't get handle for the table filter");
	  fcp_log (LOG_ERR, "API: maybe missing iptables module ?!");
	  sprintf (errstr,
			   "502 Service Unavailable: iptables support missing ?!");
	  return 0;
	}

  set_chain_label (state, &default_chain, 0);

  fcp_log (LOG_DEBUG, "API: trying to convert state into ipt_entry");

  if ((entry = state_to_iptentry (state, errstr, 0)) != NULL)
	{
	  mask = make_delete_mask (entry->next_offset);
	  if (!mask)
		{
		  fcp_log (LOG_CRIT,
				   "API: couldn't allocate memory for the deletion mask");
		  sprintf (errstr,
				   "500 Server Internal Error: couldn't allocate memory");
		  return 0;
		}

	  fcp_log (LOG_DEBUG,
			   "API: trying to delete rule with iptc_delete_entry");
	  /* ####################################### If this func is called a
	     state was found, so we assume that a rule representing the state is
	     in the firewall. If not the iptc_delete_entry call will fail. Also
	     this call will delete the first rule which matches, so if their are
	     more then one rule in the firewall only the first will be deleted
	     !!! ####################################### */
	  ret = iptc_delete_entry (default_chain, entry, mask, &handle);

	  if (ret)
		{
		  fcp_log (LOG_DEBUG, "API: rule succesfull removed");
		  /* If logging is requested remove the aditional rule for logging */
		  if (state->sop->log_def)
			{
			  fcp_log (LOG_DEBUG,
					   "API: trying to convert state into ipt_entry for"
                       " logging");
			  if ((entry = state_to_iptentry (state, errstr, 3)) != NULL)
				{
				  fcp_log (LOG_DEBUG,
						   "API: trying to remove logging rule with"
                           " iptc_delete_entry");
				  free (mask);
				  mask = make_delete_mask (entry->next_offset);
				  mask_hole_offset = mask_hole_size = 0;
				  if (iptc_delete_entry (default_chain, entry, mask, &handle))
					fcp_log (LOG_DEBUG,
							 "API: logging rule succesfull removed");
				  else
					{
					  sprintf (debug_msg_helper,
							   "API: iptc_delete_entry for logging retuned %i",
							   errno);
					  fcp_log (LOG_ERR, debug_msg_helper);
					  sprintf (debug_msg_helper, "API: %s",
							   iptc_strerror (errno));
					  fcp_log (LOG_ERR, debug_msg_helper);
					  sprintf (errstr,
							   "500 Server Internal Error: rule deletion"
                               " returned %i",
							   errno);
					  free (entry);
					  return 0;
					}
				}
			}
		  if (iptc_commit (&handle))
			{
			  /* Decrease the number of rules in the priority class of the
			     rule in their chain. Additionaly decrease priority class
			     zero for the logging rule. */
			  if (filter_chain == 1)
				{
				  priority_classes_input[state->sop->pri_class] =
					priority_classes_input[state->sop->pri_class] - 1;
				  if (state->sop->log_def)
					priority_classes_input[0] = priority_classes_input[0] - 1;
				}
			  else if (filter_chain == 2)
				{
				  priority_classes_output[state->sop->pri_class] =
					priority_classes_output[state->sop->pri_class] - 1;
				  if (state->sop->log_def)
					priority_classes_output[0] =
					  priority_classes_output[0] - 1;
				}
			  else if (filter_chain == 3)
				{
				  priority_classes_forward[state->sop->pri_class] =
					priority_classes_forward[state->sop->pri_class] - 1;
				  if (state->sop->log_def)
					priority_classes_forward[0] =
					  priority_classes_forward[0] - 1;
				}
			  fcp_log (LOG_DEBUG, "API: commit succesfull");
			}
		  else
			{
			  sprintf (debug_msg_helper,
					   "API: deletion commit failed with %i", errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: deletion commit"
                       " returned %i",
					   errno);
			  return 0;
			}
		}
	  else
		{
		  sprintf (debug_msg_helper, "API: iptc_delete_entry failed with %i",
				   errno);
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (debug_msg_helper, "API: %s", iptc_strerror (errno));
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (errstr,
				   "500 Server Internal Error: rule delete returns %i",
				   errno);
		}
	  return ret;
	}
  else
	return 0;
};

/* a call to this function changes the masq_port attrribute to the port
   number, which this function reserves. The masq_ip must be set to the ip,
   on which the masq port should be reserved (important for multiple ip's on
   the firewall) returns: 1: ok ; 0: failed. */
int fcp_port_request (struct fcp_reserved *res, char *errstr)
{
  /* Dirty but simple implementation: we allocate a socket to get a port
     number and block this port on our host. */
  struct api_socket *api_s, *tmp_s, *first_s;
  struct sockaddr_in sock;
  int ret, req_range, api_range, okay;
  socklen_t len;

  tmp_s = first_s = NULL;
  okay = 1;

  /* check if a port range was request */
  if (res->origin_uppt != 0 && res->origin_uppt != res->origin_port)
	req_range = res->origin_uppt - res->origin_port;
  else
	req_range = 0;
  api_range = -1;

  while ((req_range != api_range) && okay)
	{
	  /* Allocate memory for our structure and try to get a socket for the
	     requested protocol. */
	  api_s = malloc (sizeof (struct api_socket));
	  memset (api_s, 0, sizeof (struct api_socket));
	  api_s->socket = socket (AF_INET, SOCK_STREAM, res->proto);
	  if (api_s->socket == -1)
		{
		  fcp_log (LOG_ERR,
				   "API: fcp_port_request: error while trying to get a socket");
		  sprintf (debug_msg_helper,
				   "API: fcp_port_request: socket() call returned %i", errno);
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (errstr,
				   "500 Server Internal Error: error while trying to allocate"
                   " a port for NAT");
		  free (api_s);
		  api_s = NULL;
		  okay = 0;
		}
	  else
		{
		  /* Initalise the sockaddr_in structure with the external IP of our
		     host and port 0 so that the bind() call will allocate the port
		     for us. */
		  memset (&sock, 0, sizeof (struct sockaddr_in));
		  sock.sin_family = AF_INET;
		  if (api_range == -1)
			sock.sin_port = htons (0);
		  else
			sock.sin_port = htons (first_s->port + api_range + 1);
		  sock.sin_addr.s_addr = fcp_outer_IP;
		  ret =
			bind (api_s->socket, (struct sockaddr *) &sock,
				  sizeof (struct sockaddr_in));
		  if (ret == -1)
			{
			  fcp_log (LOG_ERR,
					   "API: fcp_port_request: error while trying to bind a"
                       " socket");
			  sprintf (debug_msg_helper,
					   "API: fcp_port_request: bind() call returned %i",
					   errno);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (errstr,
					   "500 Server Internal Error: error while trying to"
                       " allocate a port for NAT");
			  close (api_s->socket);
			  free (api_s);
			  api_s = NULL;
			  okay = 0;
			}
		  if (api_range == -1 && okay)
			{
			  /* Clear the sockaddr_in structure to be sure, and let it be
			     filled with the values of the socket, so we know what port
			     we got. */
			  memset (&sock, 0, sizeof (struct sockaddr_in));
			  len = sizeof (sock);
			  ret =
				getsockname (api_s->socket, (struct sockaddr *) &sock, &len);
			  if (ret == -1)
				{
				  fcp_log (LOG_ERR,
						   "API: fcp_port_request: error while trying to"
                           " determine the port of the socket");
				  sprintf (debug_msg_helper,
						   "API: fcp_port_request: getsockname() call"
                           " returned %i",
						   errno);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (errstr,
						   "500 Server Internal Error: error while trying to"
                           " allocate a port for NAT");
				  close (api_s->socket);
				  free (api_s);
				  okay = 0;
				}
			  /* We have the first information to fill the return structure. */
			  res->masq_ip = fcp_outer_IP;
			  res->masq_port = api_s->port = ntohs (sock.sin_port);
			  res->masq_uppt = 0;
			  first_s = api_s;
			}
		  else
			api_s->port = ntohs (sock.sin_port);
		  if (tmp_s != NULL)
			tmp_s->next = api_s;
		  tmp_s = api_s;
		  api_range++;
		}
	}

  if (okay)
	{
	  res->masq_uppt = first_s->port + api_range;
	  /* At last insert our structure(s) at the beginning of the list. */
	  tmp_s = socket_list.next;
	  socket_list.next = first_s;
	  api_s->next = tmp_s;
	  if (res->masq_uppt)
		sprintf (debug_msg_helper,
				 "API: fcp_port_request: succesfull from port %u to %u"
                 " reserved",
				 res->masq_port, res->masq_uppt);
	  else
		sprintf (debug_msg_helper,
				 "API: fcp_port_request: succesfull port %u reserved",
				 res->masq_port);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	  return 1;
	}
  else
	{
	  tmp_s = first_s;
	  while (tmp_s)
		{
		  api_s = tmp_s->next;
		  close (tmp_s->socket);
		  free (tmp_s);
		  tmp_s = api_s;
		}
	  return 0;
	}
};

/* Releases the port masq_port on the ip masq_ip. returns: 1: ok ; 0: failed.
 */
int fcp_port_release (struct fcp_reserved *res, char *errstr)
{
  struct api_socket *api_s, *tmp_s;
  int i, ret;

  /* Try to find the according socket to the reservation. Because it's not a
     double linked list we have to save the last element. */
  tmp_s = &socket_list;
  api_s = tmp_s->next;
  while (api_s && api_s->port != res->masq_port)
	{
	  tmp_s = api_s;
	  api_s = api_s->next;
	}
  /* If the pointer isn't NULL we should have found the socket. */
  if (api_s)
	{
	  /* Close the socket, remove the struct from the list and free the
	     memory. */
	  close (api_s->socket);
	  tmp_s->next = api_s->next;
	  free (api_s);
	  if (res->masq_uppt)
		{
		  ret = 1;
		  api_s = tmp_s->next;
		  for (i = res->masq_port + 1; i <= res->masq_uppt; i++)
			{
			  if (api_s->port == i)
				{
				  close (api_s->socket);
				  tmp_s->next = api_s->next;
				  free (api_s);
				  api_s = tmp_s->next;
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "API: fcp_port_release: socket with port %u not"
                           " found to release",
						   i);
				  fcp_log (LOG_WARNING, debug_msg_helper);
				  api_s = api_s->next;
				  ret = 0;
				}
			}
		  if (ret)
			{
			  sprintf (debug_msg_helper,
					   "API: fcp_port_release: succesfull ports from %u to %u"
                       " released",
					   res->masq_port, res->masq_uppt);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  res->masq_port = res->masq_uppt = res->masq_ip = 0;
			  return 1;
			}
		  else
			{
			  sprintf (errstr,
					   "500 Server Internal Error: couldn't release all ports"
                       " of the range (%u - %u)",
					   res->origin_port, res->origin_uppt);
			  return 0;
			}
		}
	  sprintf (debug_msg_helper,
			   "API: fcp_port_release: succesfull port %u released",
			   res->masq_port);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	  res->masq_port = res->masq_ip = 0;
	  return 1;
	}
  else
	{
	  /* We haven't found the socket so report this error. */
	  sprintf (debug_msg_helper,
			   "API: fcp_port_release: socket with port %u with masq port %u"
               " to release not found",
			   res->masq_port, res->origin_port);
	  fcp_log (LOG_NOTICE, debug_msg_helper);
	  sprintf (errstr,
			   "500 Server Internal Error: NAT port for port %u not found",
			   res->origin_port);
	  return 0;
	}
};


/* This function is called from main at startup of the server. So here can
   all nessecary things be initalised or checked. */
void fcp_api_init ()
{
  memset (&socket_list, 0, sizeof (struct api_socket));
  socket_list.next = NULL;
  memset (&priority_classes_input[0], 0,
		  sizeof (priority_classes_input[FCP_MAX_PRIORITY_CLASSES]));
  memset (&priority_classes_output[0], 0,
		  sizeof (priority_classes_output[FCP_MAX_PRIORITY_CLASSES]));
  memset (&priority_classes_forward[0], 0,
		  sizeof (priority_classes_forward[FCP_MAX_PRIORITY_CLASSES]));
  /* *FIXME* Here we can/should check if iptables is initalised, the policy
     of the chains are correct, determine the IPs of the interfaces... */
};

#else /* LINUX_VERSION_CODE */

/* This helper function tryes to convert a state of fcp into a ip_fwuser from
   the library libipfwc of ipchains. Returns 1: ok, 0: failed If returned 0
   the according fcp reply will written to error. */
int state_to_ipfwuser (struct fcp_state *state, struct ip_fwuser *ipfw,
					   char *error)
{
  struct fcp_state fcp = *state;

  /* evaluate the action if it's set, else set no action */
  if ((fcp.sop != NULL) && (fcp.sop->action_def))	/* will this segfault, if
													   fcp.sop is NULL ??? */
	{
	  if (fcp.sop->action == fcp_action_pass)
		strcpy ((*ipfw).label, "ACCEPT");
	  else if (fcp.sop->action == fcp_action_drop)
		strcpy ((*ipfw).label, "DENY");
	  else if (fcp.sop->action == fcp_action_reject)
		strcpy ((*ipfw).label, "REJECT");
	  else						/* this should not happen but for safety */
		strcpy ((*ipfw).label, "\0");
	}
  else
	strcpy ((*ipfw).label, "\0");


  /* Copy source and destination IPs, or set to 0 if not definied */
  if (fcp.pme->src_ip_def)
	(*ipfw).ipfw.fw_src.s_addr = fcp.pme->src_ip;
  else
	(*ipfw).ipfw.fw_src.s_addr = 0;

  if (fcp.pme->dst_ip_def)
	(*ipfw).ipfw.fw_dst.s_addr = fcp.pme->dst_ip;
  else
	(*ipfw).ipfw.fw_dst.s_addr = 0;

  /* Copy netmasks if defined; if only an IP was defined set to
     255.255.255.255; if no IP and netmask defined set to 0 */
  if (fcp.pme->src_netmask_def)
	(*ipfw).ipfw.fw_smsk.s_addr = fcp.pme->src_netmask;
  else if (fcp.pme->src_ip_def)
	(*ipfw).ipfw.fw_smsk.s_addr = 0xFFFFFFFF;
  else
	(*ipfw).ipfw.fw_smsk.s_addr = 0;

  if (fcp.pme->dst_netmask_def)
	(*ipfw).ipfw.fw_dmsk.s_addr = fcp.pme->dst_netmask;
  else if (fcp.pme->dst_ip_def)
	(*ipfw).ipfw.fw_dmsk.s_addr = 0xFFFFFFFF;
  else
	(*ipfw).ipfw.fw_dmsk.s_addr = 0;

  /* ############################## We don't support marking of packets, so
     set it to 0 ############################## */
  (*ipfw).ipfw.fw_mark = 0;

  /* If a protocol is defines copy it, else set it to 0 */
  if (fcp.pme->proto_def)
	(*ipfw).ipfw.fw_proto = fcp.pme->proto;
  else
	(*ipfw).ipfw.fw_proto = 0;

  /* ############################# We only look for the syn flag... I got
     these values only from viewing existing rules. How should we handle the
     combinations of syn_allowed and actions ?????
     ############################# */
  if (fcp.pme->syn_flg_def)
	{
	  /* If TCPSYNALLOWED is set to yes we don't set any flag. */
	  if (fcp.pme->syn_flg)
		{
		  (*ipfw).ipfw.fw_flg = IP_FW_F_WILDIF;
		  (*ipfw).ipfw.fw_invflg = 0;
		}
	  else
		{
		  (*ipfw).ipfw.fw_flg = (IP_FW_F_WILDIF + IP_FW_F_TCPSYN);
		  (*ipfw).ipfw.fw_invflg = IP_FW_INV_SYN;
		  // fcp_log (LOG_DEBUG, "API: set <! -y>");
		}
	}
  else
	{
	  (*ipfw).ipfw.fw_flg = IP_FW_F_WILDIF;
	  (*ipfw).ipfw.fw_invflg = 0;
	  // fcp_log (LOG_DEBUG, "API: no syn_flg_def found");
	}

  /* If a lower port is definied copy it, else set the complete port range
     (lower=0, upper=65535). If a upper port is defined copy it, else set it
     to the value of the lower, so that only the lower port is allowed. */
  if (fcp.pme->src_pt_def)
	(*ipfw).ipfw.fw_spts[0] = fcp.pme->src_pt;
  else
	{
	  (*ipfw).ipfw.fw_spts[0] = 0;
	  (*ipfw).ipfw.fw_spts[1] = 65535;
	}
  if (fcp.pme->src_uppt_def)
	(*ipfw).ipfw.fw_spts[1] = fcp.pme->src_uppt;
  else if (fcp.pme->src_pt_def)
	(*ipfw).ipfw.fw_spts[1] = fcp.pme->src_pt;

  if (fcp.pme->dst_pt_def)
	(*ipfw).ipfw.fw_dpts[0] = fcp.pme->dst_pt;
  else
	{
	  (*ipfw).ipfw.fw_dpts[0] = 0;
	  (*ipfw).ipfw.fw_dpts[1] = 65535;
	}
  if (fcp.pme->dst_uppt_def)
	(*ipfw).ipfw.fw_dpts[1] = fcp.pme->dst_uppt;
  else if (fcp.pme->dst_pt_def)
	(*ipfw).ipfw.fw_dpts[1] = fcp.pme->dst_pt;

  /* ################################## We don't support redirecting of
     ports, so set it to 0 ################################# */
  (*ipfw).ipfw.fw_redirpt = 0;

  /* ################################ What is outputsize ? We don't support
     it, so set it to 0 ################################ */
  (*ipfw).ipfw.fw_outputsize = 0;

  if (fcp.pme->in_if_def || fcp.pme->out_if_def)
	{
	  sprintf (error,
			   "501 Not Implemented: Interfaces are not supported by this"
               " version");
	  return 0;
	}
  else
	{
	  /* ################################ We don't support any interfaces at
	     this time, so we write nothing. ################################ */
	  strcpy ((*ipfw).ipfw.fw_vianame, "\0");
	}

  if (fcp.pme->tos_fld_def)
	{
	  sprintf (error,
			   "501 Not Implemeted: TOS Field not supported by ipchains");
	  return 0;
	}
  else
	{
	  /* ############################### We don't support the tos field, so
	     set it to 255 ############################### */
	  (*ipfw).ipfw.fw_tosand = 255;
	}

  /* if defined copy the icmp type to the ports */
  if (fcp.pme->icmp_type_def)
	{
	  /* copy the icmp type */
	  (*ipfw).ipfw.fw_spts[0] = fcp.pme->icmp_type;
	  (*ipfw).ipfw.fw_spts[1] = fcp.pme->icmp_type;
	  /* we don't support the icmp code so set it to the hole range */
	  (*ipfw).ipfw.fw_dpts[0] = 0;
	  (*ipfw).ipfw.fw_dpts[1] = 65535;
	}
  return 1;
};

/* This helper function tryes to convert a ip_fw struct from
   ipfwc_kernel_headers into a fcp_pme struct. Returns 1: ok, 0: failed If
   returned 0 the according fcp reply will written to error. */
int ipfw_to_pme (struct ip_fw *rule_ip_fw, struct fcp_pme *pme, char *error)
{
  struct ip_fw ipfw = *rule_ip_fw;

  /* copy protocol value ################################# if protocol is 0
     set it as undefined. Is this right ?????
     ################################# */
  if (ipfw.fw_proto != 0)
	{
	  (*pme).proto = ipfw.fw_proto;
	  (*pme).proto_def = 1;
	}
  else
	{
	  (*pme).proto = 0;
	  (*pme).proto_def = 0;
	}

  /* copy source IP and set defined according to */
  (*pme).src_ip = ipfw.fw_src.s_addr;
  if (ipfw.fw_src.s_addr != 0)
	(*pme).src_ip_def = 1;
  else
	(*pme).src_ip_def = 0;

  /* copy destination IP and set defined according to */
  (*pme).dst_ip = ipfw.fw_dst.s_addr;
  if (ipfw.fw_dst.s_addr != 0)
	(*pme).dst_ip_def = 1;
  else
	(*pme).dst_ip_def = 0;

  /* copy source netmaks and if it's 0 or FFFFFF set undefined !?!? */
  (*pme).src_netmask = ipfw.fw_smsk.s_addr;
  if ((ipfw.fw_smsk.s_addr == 0) || (ipfw.fw_smsk.s_addr == 0xFFFFFF))
	(*pme).src_netmask_def = 0;
  else
	(*pme).src_netmask_def = 1;

  /* copy destination netmaks and if it's 0 or FFFFFF set undefined !?!? */
  (*pme).dst_netmask = ipfw.fw_dmsk.s_addr;
  if ((ipfw.fw_dmsk.s_addr == 0) || (ipfw.fw_dmsk.s_addr == 0xFFFFFF))
	(*pme).dst_netmask_def = 0;
  else
	(*pme).dst_netmask_def = 1;

  /* copy source ports and set according defines */
  (*pme).src_pt = ipfw.fw_spts[0];
  (*pme).src_uppt = ipfw.fw_spts[1];
  if (ipfw.fw_spts[0] == ipfw.fw_spts[1])
	{
	  (*pme).src_pt_def = 1;
	  (*pme).src_uppt_def = 0;
	}
  else if ((ipfw.fw_spts[0] == 0) && (ipfw.fw_spts[1] == 65535))
	{
	  (*pme).src_pt_def = 0;
	  (*pme).src_uppt_def = 0;
	}
  else
	{
	  (*pme).src_pt_def = 1;
	  (*pme).src_uppt_def = 1;
	}

  /* copy destination ports and set according defines */
  (*pme).dst_pt = ipfw.fw_dpts[0];
  (*pme).dst_uppt = ipfw.fw_dpts[1];
  if (ipfw.fw_dpts[0] == ipfw.fw_dpts[1])
	{
	  (*pme).dst_pt_def = 1;
	  (*pme).dst_uppt_def = 0;
	}
  else if ((ipfw.fw_dpts[0] == 0) && (ipfw.fw_dpts[1] == 65535))
	{
	  (*pme).dst_pt_def = 0;
	  (*pme).dst_uppt_def = 0;
	}
  else
	{
	  (*pme).dst_pt_def = 1;
	  (*pme).dst_uppt_def = 1;
	}

  /* copy tos field and set defined */
  (*pme).tos_fld = ipfw.fw_tosand;
  if (ipfw.fw_tosand == 255)
	(*pme).tos_fld_def = 0;
  else
	(*pme).tos_fld_def = 1;

  /* icmp not supported by ipchains so set it to zero */
  (*pme).icmp_type = 0;
  (*pme).icmp_type_def = 0;

  /* ############################ At this time we don't support interfaces so
     set it all to zero. Here we should convert ipfw.fw_vianame...
     ############################ */
  (*pme).in_if = 0;
  (*pme).in_if_def = 0;
  (*pme).out_if = 0;
  (*pme).out_if_def = 0;

  return 1;
};

/* inserts a rule according to state. returns: 1: ok ; 0: failed */
int fcp_rule_insert (struct fcp_state *state, char *errstr)
{
  int ret;
  struct ip_fwuser ipc_rule;
  ip_chainlabel default_chain;

  // fcp_log_fcp_state (state);

  /* ###################################### Simple pinholes make only sence
     in the forward chain. In real we have to set this according to the
     interfaces. ###################################### */
  strcpy (default_chain, "forward");

  fcp_log (LOG_DEBUG, "API: trying to convert state into ip_fwuser");

  if (state_to_ipfwuser (state, &ipc_rule, errstr))
	{
	  fcp_log (LOG_DEBUG,
			   "API: trying to insert rule with ipfwc_insert_entry");
	  /* ##################################### Simple pinholes hav highest
	     priority, so we insert them every time at place 1. In real we have
	     to determine with the priority classes where the rule have to be
	     inserted. Also we should interpret errno if insert fails, because it
	     should deliver more info about the failure.
	     ##################################### */
	  ret = ipfwc_insert_entry (default_chain, &ipc_rule, 1);

	  if (ret)
		fcp_log (LOG_DEBUG, "API: rule succesfull inserted");
	  else
		{
		  sprintf (debug_msg_helper, "API: ipfwc_insert_entry errno is %i",
				   errno);
		  fcp_log (LOG_DEBUG, debug_msg_helper);
		  sprintf (errstr,
				   "500 Server Internal Error: rule insert returns %i",
				   errno);
		}

	  return ret;
	}
  else
	return 0;
};

/* deletes a rule according to state. returns: 1: ok ; 0: delete failed */
int fcp_rule_delete (struct fcp_state *state, char *errstr)
{
  int ret;
  struct ip_fwuser ipc_rule;
  ip_chainlabel default_chain;

  /* ###################################### Simple pinholes make only sence
     in the forward chain. In real we have to set this according to the
     interfaces. ###################################### */
  strcpy (default_chain, "forward");

  fcp_log (LOG_DEBUG, "API: trying to convert state into ip_fwuser");

  if (state_to_ipfwuser (state, &ipc_rule, errstr))
	{
	  fcp_log (LOG_DEBUG,
			   "API: trying to delete rule with ipfwc_delete_entry");
	  /* ####################################### If this func is called a
	     state was found, so we assume that a rule representing the state is
	     in the firewall. If not the ipfwc_delete_entry call will fail. Also
	     this call will delete the first rule which matches, so if their are
	     more then one rule in the firewall only the first will be deleted
	     !!! ####################################### */
	  ret = ipfwc_delete_entry (default_chain, &ipc_rule);

	  if (ret)
		fcp_log (LOG_DEBUG, "API: rule succesfull deleted");
	  else
		{
		  sprintf (debug_msg_helper, "API: ipfwc_delete_entry errno is %i",
				   errno);
		  fcp_log (LOG_DEBUG, debug_msg_helper);
		  sprintf (errstr,
				   "500 Server Internal Error: rule delete returns %i",
				   errno);
		}

	  return ret;
	}
  else
	return 0;
};

/* a call to this function changes the masq_port attrribute to the port
   number, which this function reserves. The masq_ip must be set to the ip,
   on which the masq port should be reserved (important for multiple ip's on
   the firewall) returns: 1: ok ; 0: failed; -1: no ports avaiable; -2...:
   reserved for *future* use */
int fcp_port_request (struct fcp_reserved *res, char *errstr)
{
  fcp_log (LOG_DEBUG, "call to dummy func fcp_port_request");
  fcp_log (LOG_INFO, "501 Not Implemented: NAT not supported by ipchains");
  sprintf (errstr, "501 Not Implemented: NAT not supported by ipchains");
  return 0;
};

/* Releases the port masq_port on the ip masq_ip. returns: 1: ok ; 0: failed;
   -1: port not reserved; -2...: reserved for *future* use */
int fcp_port_release (struct fcp_reserved *res, char *errstr)
{
  fcp_log (LOG_DEBUG, "call to dummy func fcp_port_release");
  fcp_log (LOG_INFO, "501 Not Implemented: NAT not supported by ipchains");
  sprintf (errstr, "501 Not Implemented: NAT not supported by ipchains");
  return 0;
};

/* This function is called from main at startup of the server. So here can
   all nessecary things be initalised or checked. */
void fcp_api_init ()
{
};

#endif /* if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0) */

#else /* ifdef LINUX_VERSION_CODE */

/* ################################################### The following
   implementation is only a dummy to compile on not Linux systems.
   ################################################### */

int fcp_rule_insert (struct fcp_state *state, char *errstr)
{
  sprintf (errstr,
		   "501 Not Implemted: rule inserting not implemented (dummy API)");
  return 0;
};

int fcp_rule_delete (struct fcp_state *state, char *errstr)
{
  sprintf (errstr,
		   "501 Not Implemted: rule deleting not implemented (dummy API)");
  return 0;
};

int fcp_port_request (struct fcp_reserved *res, char *errstr)
{
  sprintf (errstr,
		   "501 Not Implemted: port request not implemented (dummy API)");
  return 0;
};

int fcp_port_release (struct fcp_reserved *res, char *errstr)
{
  sprintf (errstr,
		   "501 Not Implemted: port release not implemented (dummy API)");
  return 0;
};

/* This function is called from main at startup of the server. So here can
   all nessecary things be initalised or checked. */
void fcp_api_init ()
{
};

#endif /* ifdef LINUX_VERSION_CODE */
