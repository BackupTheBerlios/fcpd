/***************************************************************************
                          configure.c
                             -------------------
    begin                : Sun Dec 24 2000
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
#include <signal.h>

#include "main.h"
#include "debug.h"
#include "interpret.h"
#include "configure.h"

#define fcp_token_unknown		0

#define argument_PORT					1
#define argument_DEBUGLEVEL		2
#define argument_ACL					3
#define argument_INTFIN				4
#define argument_INTFOUT			5
#define argument_INTFDMZ			6
#define argument_TIMEOUT			7
#define argument_MAXPRIORITY	8
#define argument_MAXLOG				9
#define argument_INTERNALIPS	10
#define argument_MASQUIPS			11
#define argument_IPIN					12
#define argument_IPOUT				13
#define argument_IPDMZ				14
#define argument_DMZIPS				15
#define argument_LOG_S				16
#define argument_LOG_M				17
#define argument_LOG_H				18
#define argument_LOG_D				19

#define fcp_token_at_all			19

/* the handle of the config file if we kill ourself we should close it */
FILE *config_file;

static char *token_names[] = { "",
  "PORT", "DEBUGLEVEL", "ACL", "INTFIN", "INTFOUT", "INTFDMZ",
  "TIMEOUT", "MAXPRIORITY", "MAXLOG", "INTERNALIPS", "MASQUIPS",
  "IPIN", "IPOUT", "IPDMZ", "DMZIPS", "LOG_S", "LOG_M", "LOG_H",
  "LOG_D"
};

int compare_to_def (char *token)
{
  int i;
  for (i = 1; i <= fcp_token_at_all; i++)
	{
	  if (!strcmp (token, token_names[i]))
		return i;
	}
  return fcp_token_unknown;
};

/* this functione tryes to interpret what we have read from the config file
   and makes the changes to the global variables if possible */
void change_config (struct name_value *config_values)
{
  int result, ret;
  unsigned int conv;
  struct name_value *config_list, *csv_list, *this_name_value;
  struct fcp_address_list *this_address_list, *tmp;

  config_list = config_values;

  fcp_log (LOG_DEBUG, "CONFIGURE: begin of changing configuration");

  while (config_list->name != NULL)
	{
	  /* what parameter was read */
	  result = compare_to_def (config_list->name);
	  if (result)
		{
		  /* if it was a correct spelled parameter switch to point where we
		     scan the value and make the changes */
		  switch (result)
			{
			case argument_PORT:
			  conv = atol (config_list->value);
			  if ((conv > 65535) || (conv < 0))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: error port %i out of range", conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  conv = FCP_DEFAULT_PORT;
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using standard port %i instead", conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  else
				{
				  sprintf (debug_msg_helper, "CONFIGURE: using port %i",
						   conv);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}
			  if (conv != fcp_port)
				{
				  /* *FIXME* here we have to terminate all our existing
				     connections, and try to listen to the new defined port. */
				  fcp_log (LOG_DEBUG,
						   "CONFIGURE: new port defined. here we SHOULD"
                           " restart our network. NOT IMPLEMENTED");
				}
			  break;
			case argument_DEBUGLEVEL:
			  conv = atoi (config_list->value);
			  if ((conv > 7) || (conv < 0))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: error debuglevel %i out of range",
						   conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  else
				{
				  if (fcp_loglevel_override)
					conv = fcp_loglevel;	/* was specified on command line */
				  sprintf (debug_msg_helper, "CONFIGURE: using debuglevel %i",
						   conv);
				  fcp_log (LOG_INFO, debug_msg_helper);
				  if (conv != fcp_loglevel)
					/* change our loglevel to the new value */
					fcp_loglevel = conv;
				}
			  break;
			case argument_ACL:
			  sprintf (debug_msg_helper,
					   "CONFIGURE: access restricted to %s.",
					   config_list->value);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* Seperate the string by the commas */
			  csv_list = (struct name_value *) scan_csv (config_list->value);
			  if (csv_list)
				{
				  /* First of all free the existing acl_list. */
				  this_address_list = fcp_acl_list.next;
				  while (this_address_list)
					{
					  tmp = this_address_list->next;
					  free (this_address_list);
					  this_address_list = tmp;
					}
				  /* Convert the strings into IPs and netmasks and put them
				     into the acl_list. */
				  this_name_value = csv_list;
				  fcp_acl_list.next =
					malloc (sizeof (struct fcp_address_list));
				  this_address_list = fcp_acl_list.next;
				  this_address_list->next = NULL;
				  ret =
					parse_ip_netmask (this_name_value->name,
									  &this_address_list->netmask);
				  if (ret == 1)
					{
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in ACL isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else if (ret == 0)
					{
					  this_address_list->netmask = 0xFFFFFFFF;
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in ACL isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else
					{
					  fcp_log (LOG_ERR,
							   "CONFIGURE: netmask in ACL isn't valid");
					  this_address_list->netmask = 0xFFFFFFFF;
					  this_address_list->address = 0;
					}
				  this_name_value = this_name_value->next;
				  /* The first element is now in the list, now do the same
				     for the rest. */
				  while (this_name_value)
					{
					  this_address_list->next =
						malloc (sizeof (struct fcp_address_list));
					  this_address_list = this_address_list->next;
					  this_address_list->next = NULL;
					  ret =
						parse_ip_netmask (this_name_value->name,
										  &this_address_list->netmask);
					  if (ret == 1)
						{
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in ACL isn't valid");
							  this_address_list->address = 0;
							}
						}
					  else if (ret == 0)
						{
						  this_address_list->netmask = 0xFFFFFFFF;
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in ACL isn't valid");
							  this_address_list->address = 0;
							}
						}
					  else
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: netmask in ACL isn't valid");
						  this_address_list->netmask = 0xFFFFFFFF;
						  this_address_list->address = 0;
						}
					  this_name_value = this_name_value->next;
					}
				  /* Everything is in the acl_list now freeing the
				     name_value_list where the strings were in. */
				  while (csv_list)
					{
					  this_name_value = csv_list->next;
					  free (csv_list->name);
					  free (csv_list);
					  csv_list = this_name_value;
					}
				}
			  else
				{
				  fcp_log (LOG_ERR, "CONFIGURE: ACL couldn't be converted");
				  /* Free the existing acl_list if exists. */
				  if (fcp_acl_list.next)
					{
					  this_address_list = fcp_acl_list.next;
					  while (this_address_list)
						{
						  tmp = this_address_list->next;
						  free (this_address_list);
						  this_address_list = tmp;
						}
					  fcp_acl_list.next = NULL;
					}
				}
			  break;
			case argument_INTFIN:
			  if (strlen (config_list->value) > 0)
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: in interface %s found.",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  /* Freeing the old interface if specified, alloc and copy
				     the new value.
                     ####################################
                     More then one interface is NOT supported yet.
				     #################################### */
				  if (fcp_in_interface.name)
					free (fcp_in_interface.name);
				  fcp_in_interface.name =
					malloc (sizeof (config_list->value));
				  strcpy (fcp_in_interface.name, config_list->value);
				}
			  break;
			case argument_INTFOUT:
			  if (strlen (config_list->value) > 0)
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: out interface %s found.",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  /* Freeing the old interface if specified, alloc and copy
				     the new value.
                     ####################################
                     More then one interface is NOT supported yet.
				     #################################### */
				  if (fcp_out_interface.name)
					free (fcp_out_interface.name);
				  fcp_out_interface.name =
					malloc (sizeof (config_list->value));
				  strcpy (fcp_out_interface.name, config_list->value);
				}
			  break;
			case argument_INTFDMZ:
			  if (strlen (config_list->value) > 0)
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: dmz interface %s found.",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  /* Freeing the old interface if specified, alloc and copy
				     the new value. #################################### More
				     then one interface is NOT supported yet.
				     #################################### */
				  if (fcp_dmz_interface.name)
					free (fcp_dmz_interface.name);
				  fcp_dmz_interface.name =
					malloc (sizeof (config_list->value));
				  strcpy (fcp_dmz_interface.name, config_list->value);
				}
			  break;
			case argument_TIMEOUT:
			  conv = atoi (config_list->value);
			  if ((conv > FCP_MAX_TIMEOUT) || (conv < 0))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: the timeout value %i is grater then the"
                           " maximum %i or less 0",
						   conv, FCP_MAX_TIMEOUT);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  conv = FCP_DEFAULT_TIMEOUT;
				  sprintf (debug_msg_helper,
						   "CONFIGURE:  using standard timeout %i instead",
						   conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using %i as standard timeout value",
						   conv);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}
			  if (conv != fcp_timeout)
				/* is there anything else to do ??? should we calculate the
				   timeout of the existing states new? but how? we don't know
				   how much time is elapsed by every state. so i assume that
				   the new timeout is only valid for new states. :( */
				fcp_timeout = conv;
			  break;
			case argument_MAXPRIORITY:
			  conv = atoi (config_list->value);
			  if ((conv > FCP_MAX_PRIORITY_CLASSES) || (conv < 0))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: %i priority classes are grater then the"
                           " maximum %i or less 0",
						   conv, FCP_MAX_PRIORITY_CLASSES);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  conv = FCP_DEFAULT_PRIORITY_CLASSES;
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using %i priority classes instead. NOT"
                           " IMPLEMTED",
						   conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using %i priority classes. NOT"
                           " IMPLEMENTED",
						   conv);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}
			  if (conv != fcp_priorityclasses)
				/* ###################################### here we definetly
				   have to do some more things but at this time they are
				   unknown !!! ###################################### */
				fcp_priorityclasses = conv;
			  break;
			case argument_MAXLOG:
			  conv = atoi (config_list->value);
			  if ((conv > FCP_MAX_LOG_CLASSES) || (conv < 0))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: %i log classes are grater then the"
                           " maximum %i or less 0",
						   conv, FCP_MAX_LOG_CLASSES);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  conv = FCP_DEFAULT_LOG_CLASSES;
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using %i log classes instead. NOT"
                           " IMPLEMTED",
						   conv);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: using %i logging classes. NOT"
                           " IMPLEMTED",
						   conv);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}
			  if (fcp_logclasses != conv)
				/* ###################################### here we definetly
				   have to do some more things but at this time they are
				   unknown !!! ###################################### */
				fcp_logclasses = conv;
			  break;
			case argument_INTERNALIPS:
			  sprintf (debug_msg_helper, "CONFIGURE: internal IPs are %s.",
					   config_list->value);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* Seperate the string by the commas */
			  csv_list = (struct name_value *) scan_csv (config_list->value);
			  if (csv_list)
				{
				  /* First of all free the existing internal_ips. */
				  this_address_list = fcp_internal_ips.next;
				  while (this_address_list)
					{
					  tmp = this_address_list->next;
					  free (this_address_list);
					  this_address_list = tmp;
					}
				  /* Convert the strings into IPs and netmasks and put them
				     into the internal_ips. */
				  this_name_value = csv_list;
				  fcp_internal_ips.next =
					malloc (sizeof (struct fcp_address_list));
				  this_address_list = fcp_internal_ips.next;
				  this_address_list->next = NULL;
				  ret =
					parse_ip_netmask (this_name_value->name,
									  &this_address_list->netmask);
				  if (ret == 1)
					{
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in INTERNALIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else if (ret == 0)
					{
					  this_address_list->netmask = 0xFFFFFFFF;
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in INTERNALIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else
					{
					  fcp_log (LOG_ERR,
							   "CONFIGURE: netmask in INTERNALIPS isn't"
                               " valid");
					  this_address_list->netmask = 0xFFFFFFFF;
					  this_address_list->address = 0;
					}
				  this_name_value = this_name_value->next;
				  /* The first element is now in the list, now do the same
				     for the rest. */
				  while (this_name_value)
					{
					  this_address_list->next =
						malloc (sizeof (struct fcp_address_list));
					  this_address_list = this_address_list->next;
					  this_address_list->next = NULL;
					  ret =
						parse_ip_netmask (this_name_value->name,
										  &this_address_list->netmask);
					  if (ret == 1)
						{
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in INTERNALIPS isn't"
                                       " valid");
							  this_address_list->address = 0;
							}
						}
					  else if (ret == 0)
						{
						  this_address_list->netmask = 0xFFFFFFFF;
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in INTERNALIPS isn't"
                                       " valid");
							  this_address_list->address = 0;
							}
						}
					  else
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: netmask in INTERNALIPS isn't"
                                   " valid");
						  this_address_list->netmask = 0xFFFFFFFF;
						  this_address_list->address = 0;
						}
					  this_name_value = this_name_value->next;
					}
				  /* Everything is in the internal_ips now freeing the
				     name_value_list where the strings were in. */
				  while (csv_list)
					{
					  this_name_value = csv_list->next;
					  free (csv_list->name);
					  free (csv_list);
					  csv_list = this_name_value;
					}
				}
			  else
				{
				  fcp_log (LOG_ERR,
						   "CONFIGURE: INTERNALIPS couldn't be converted");
				  /* Free the existing internal_ips if exists. */
				  if (fcp_internal_ips.next)
					{
					  this_address_list = fcp_internal_ips.next;
					  while (this_address_list)
						{
						  tmp = this_address_list->next;
						  free (this_address_list);
						  this_address_list = tmp;
						}
					  fcp_internal_ips.next = NULL;
					}
				}
			  break;
			case argument_MASQUIPS:
			  sprintf (debug_msg_helper,
					   "CONFIGURE: this IPS %s will be masqueraded.",
					   config_list->value);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* Seperate the string by the commas */
			  csv_list = (struct name_value *) scan_csv (config_list->value);
			  if (csv_list)
				{
				  /* First of all free the existing masqu_ips. */
				  this_address_list = fcp_masq_ips.next;
				  while (this_address_list)
					{
					  tmp = this_address_list->next;
					  free (this_address_list);
					  this_address_list = tmp;
					}
				  /* Convert the strings into IPs and netmasks and put them
				     into the masqu_ips. */
				  this_name_value = csv_list;
				  fcp_masq_ips.next =
					malloc (sizeof (struct fcp_address_list));
				  this_address_list = fcp_masq_ips.next;
				  this_address_list->next = NULL;
				  ret =
					parse_ip_netmask (this_name_value->name,
									  &this_address_list->netmask);
				  if (ret == 1)
					{
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in MASQUIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else if (ret == 0)
					{
					  this_address_list->netmask = 0xFFFFFFFF;
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in MASQUIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else
					{
					  fcp_log (LOG_ERR,
							   "CONFIGURE: netmask in MASQUIPS isn't valid");
					  this_address_list->netmask = 0xFFFFFFFF;
					  this_address_list->address = 0;
					}
				  this_name_value = this_name_value->next;
				  /* The first element is now in the list, now do the same
				     for the rest. */
				  while (this_name_value)
					{
					  this_address_list->next =
						malloc (sizeof (struct fcp_address_list));
					  this_address_list = this_address_list->next;
					  this_address_list->next = NULL;
					  ret =
						parse_ip_netmask (this_name_value->name,
										  &this_address_list->netmask);
					  if (ret == 1)
						{
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in MASQUIPS isn't"
                                       " valid");
							  this_address_list->address = 0;
							}
						}
					  else if (ret == 0)
						{
						  this_address_list->netmask = 0xFFFFFFFF;
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in MASQUIPS isn't"
                                       " valid");
							  this_address_list->address = 0;
							}
						}
					  else
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: netmask in MASQUIPS isn't"
                                   " valid");
						  this_address_list->netmask = 0xFFFFFFFF;
						  this_address_list->address = 0;
						}
					  this_name_value = this_name_value->next;
					}
				  /* Everything is in the masqu_ips now freeing the
				     name_value_list where the strings were in. */
				  while (csv_list)
					{
					  this_name_value = csv_list->next;
					  free (csv_list->name);
					  free (csv_list);
					  csv_list = this_name_value;
					}
				}
			  else
				{
				  fcp_log (LOG_ERR,
						   "CONFIGURE: MASQIPS couldn't be converted");
				  /* Free the existing masq_ips if exists. */
				  if (fcp_masq_ips.next)
					{
					  this_address_list = fcp_masq_ips.next;
					  while (this_address_list)
						{
						  tmp = this_address_list->next;
						  free (this_address_list);
						  this_address_list = tmp;
						}
					  fcp_masq_ips.next = NULL;
					}
				}
			  break;
			case argument_IPIN:
			  if (parse_ip_address (config_list->value, &conv))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: IP of internal interface is %s",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  fcp_internal_IP = conv;
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: couldn't convert IP (%s) of internal"
                           " interface",
						   config_list->value);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  break;
			case argument_IPOUT:
			  if (parse_ip_address (config_list->value, &conv))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: IP of outer (external) interface is %s",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  fcp_outer_IP = conv;
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: couldn't convert IP (%s) of outer"
                           " (external) interface",
						   config_list->value);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  break;
			case argument_IPDMZ:
			  if (parse_ip_address (config_list->value, &conv))
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: IP of DMZ interface is %s",
						   config_list->value);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  fcp_demilitary_IP = conv;
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "CONFIGURE: couldn't convert IP (%s) of DMZ"
                           " interface",
						   config_list->value);
				  fcp_log (LOG_ERR, debug_msg_helper);
				}
			  break;
			case argument_DMZIPS:
			  sprintf (debug_msg_helper,
					   "CONFIGURE: this IPS %s are in the DMZ.",
					   config_list->value);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* Seperate the string by the commas */
			  csv_list = (struct name_value *) scan_csv (config_list->value);
			  if (csv_list)
				{
				  /* First of all free the existing dmz_ips. */
				  this_address_list = fcp_dmz_ips.next;
				  while (this_address_list)
					{
					  tmp = this_address_list->next;
					  free (this_address_list);
					  this_address_list = tmp;
					}
				  /* Convert the strings into IPs and netmasks and put them
				     into the dmz_ips. */
				  this_name_value = csv_list;
				  fcp_dmz_ips.next =
					malloc (sizeof (struct fcp_address_list));
				  this_address_list = fcp_dmz_ips.next;
				  this_address_list->next = NULL;
				  ret =
					parse_ip_netmask (this_name_value->name,
									  &this_address_list->netmask);
				  if (ret == 1)
					{
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in DMZIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else if (ret == 0)
					{
					  this_address_list->netmask = 0xFFFFFFFF;
					  if (!parse_ip_address
						  (this_name_value->name,
						   &this_address_list->address))
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: IP in DMZIPS isn't valid");
						  this_address_list->address = 0;
						}
					}
				  else
					{
					  fcp_log (LOG_ERR,
							   "CONFIGURE: netmask in DMZIPS isn't valid");
					  this_address_list->netmask = 0xFFFFFFFF;
					  this_address_list->address = 0;
					}
				  this_name_value = this_name_value->next;
				  /* The first element is now in the list, now do the same
				     for the rest. */
				  while (this_name_value)
					{
					  this_address_list->next =
						malloc (sizeof (struct fcp_address_list));
					  this_address_list = this_address_list->next;
					  this_address_list->next = NULL;
					  ret =
						parse_ip_netmask (this_name_value->name,
										  &this_address_list->netmask);
					  if (ret == 1)
						{
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in DMZIPS isn't valid");
							  this_address_list->address = 0;
							}
						}
					  else if (ret == 0)
						{
						  this_address_list->netmask = 0xFFFFFFFF;
						  if (!parse_ip_address
							  (this_name_value->name,
							   &this_address_list->address))
							{
							  fcp_log (LOG_ERR,
									   "CONFIGURE: IP in DMZIPS isn't valid");
							  this_address_list->address = 0;
							}
						}
					  else
						{
						  fcp_log (LOG_ERR,
								   "CONFIGURE: netmask in DMZIPS isn't valid");
						  this_address_list->netmask = 0xFFFFFFFF;
						  this_address_list->address = 0;
						}
					  this_name_value = this_name_value->next;
					}
				  /* Everything is in the dmz_ips now freeing the
				     name_value_list where the strings were in. */
				  while (csv_list)
					{
					  this_name_value = csv_list->next;
					  free (csv_list->name);
					  free (csv_list);
					  csv_list = this_name_value;
					}
				}
			  else
				{
				  fcp_log (LOG_ERR,
						   "CONFIGURE: DMZIPS couldn't be converted");
				  /* Free the existing dmz_ips if exists. */
				  if (fcp_dmz_ips.next)
					{
					  this_address_list = fcp_dmz_ips.next;
					  while (this_address_list)
						{
						  tmp = this_address_list->next;
						  free (this_address_list);
						  this_address_list = tmp;
						}
					  fcp_dmz_ips.next = NULL;
					}
				}
			  break;
			case argument_LOG_S:
			  fcp_log_per_sec = atoi (config_list->value);
			  sprintf (debug_msg_helper,
					   "CONFIGURE: log class 1 will log %i packets/second",
					   fcp_log_per_sec);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  break;
			case argument_LOG_M:
			  fcp_log_per_min = atoi (config_list->value);
			  sprintf (debug_msg_helper,
					   "CONFIGURE: log class 2 will log %i packets/minute",
					   fcp_log_per_min);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  break;
			case argument_LOG_H:
			  fcp_log_per_hou = atoi (config_list->value);
			  sprintf (debug_msg_helper,
					   "CONFIGURE: log class 3 will log %i packets/hour",
					   fcp_log_per_hou);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  break;
			case argument_LOG_D:
			  fcp_log_per_day = atoi (config_list->value);
			  sprintf (debug_msg_helper,
					   "CONFIGURE: log class 4 will log %i packets/day",
					   fcp_log_per_day);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  break;
			default:
			  sprintf (debug_msg_helper,
					   "CONFIGURE: don't know what to do with parameter %s",
					   config_list->name);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  break;
			}
		}						/* if result */
	  else
		{
		  sprintf (debug_msg_helper,
				   "CONFIGURE: unknown parameter %s found in config file\n",
				   config_list->name);
		  fcp_log (LOG_CRIT, debug_msg_helper);
		}						/* if result */
	  config_list = config_list->next;
	}							/* while */

  fcp_log (LOG_DEBUG, "CONFIGURE: end of changing configuration\n");
}

/* this function tryes to read the config file and to interpret its content */
int configure ()
{
  char config_file_line[FCP_CONFIGURE_LINE_LENGTH + 1];
  char *comment_pointer;
  int line_size;
  struct name_value *conf_para;
  struct name_value *conf_para_begin;

  /* intialies some variables correct */
  comment_pointer = NULL;
  config_file_line[0] = '\0';

  /* try to open the config file */
  if ((config_file = fopen (fcp_config_file, "r")) == NULL)
	{
	  sprintf (debug_msg_helper, "CONFIGURE: could not open %s",
			   fcp_config_file);
	  fcp_log (LOG_CRIT, debug_msg_helper);
	  return 0;
	}
  else
	{
	  sprintf (debug_msg_helper, "CONFIGURE: %s succesfully opened",
			   fcp_config_file);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	}

  /* allocate the first structure were we store the read lines */
  conf_para = malloc (sizeof (struct name_value));
  conf_para->next = NULL;
  conf_para->name = NULL;
  conf_para->value = NULL;

  conf_para_begin = conf_para;

  /* read the first line */
  /* ###################################### ATTENTION: we don't known how
     long the next line is. so we FCP_CONFIGURE_LINE_LENGTH read characters
     and hope the best... ###################################### */
  fgets (config_file_line, FCP_CONFIGURE_LINE_LENGTH, config_file);

  while (!feof (config_file))
	{
	  /* cut from the comment character to the end of line */
	  comment_pointer = strchr (config_file_line, '#');
	  if (comment_pointer != NULL)
		*comment_pointer = '\0';

	  line_size = strlen (config_file_line);

	  /* if there was more then a comment put in the structure and read the
	     next line */
	  if (line_size > 1)
		{
		  conf_para->name = malloc (line_size);
		  conf_para->name[0] = '\0';
		  conf_para->value = malloc (line_size);
		  conf_para->value[0] = '\0';
		  conf_para->next = malloc (sizeof (struct name_value));
		  conf_para->next->next = NULL;
		  conf_para->next->name = NULL;
		  conf_para->next->value = NULL;

		  sscanf (config_file_line, "%s = %s", conf_para->name,
				  conf_para->value);

		  conf_para = conf_para->next;
		}

	  comment_pointer = NULL;
	  fgets (config_file_line, FCP_CONFIGURE_LINE_LENGTH, config_file);
	}

  conf_para = conf_para_begin;

  /* now try to interpret what we read */
  change_config (conf_para);

  /* try to close the config file */
  if (fclose (config_file))
	{
	  sprintf (debug_msg_helper, "CONFIGURE: error while closing %s",
			   fcp_config_file);
	  fcp_log (LOG_CRIT, debug_msg_helper);
	}
  else
	{
	  sprintf (debug_msg_helper, "CONFIGURE: %s succesful read",
			   fcp_config_file);
	  fcp_log (LOG_INFO, debug_msg_helper);
	}

  /* and finaly free the allocated memory */
  while (conf_para != NULL)
	{
	  conf_para_begin = conf_para->next;
	  free (conf_para->name);
	  free (conf_para->value);
	  free (conf_para);
	  conf_para = conf_para_begin;
	}

  return 1;
}
