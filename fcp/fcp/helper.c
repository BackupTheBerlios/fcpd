/***************************************************************************
                          helper.c
                             -------------------
    begin                : Sun Jan 28 2001
    copyright            : (C) 2001 by Ulrich Abend, Nils Ohlmeier
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
#include <string.h>
#include <ctype.h>

#include "helper.h"
#include "debug.h"
#include "parse.h"

/* this function inserts the state at position time in the time ordered list.
   it determines with time the right place in the time list, sets the pointer
   of the states in the time list and determine the distances correct */
void time_list_insert (struct state_list *state, unsigned int time)
{
  unsigned int distance_ttl_sum;
  struct state_list *time_list;

  distance_ttl_sum = 0;
  time_list = state_list_base;

  while ((distance_ttl_sum <= time) && (time_list->time_next != NULL))
	{
	  time_list = time_list->time_next;
	  distance_ttl_sum += time_list->distance_ttl;
	}
  if (time_list->time_next == NULL)	/* end of time list */
	{
	  time_list->time_next = state;
	  state->time_prev = time_list;
	  state->time_next = NULL;
	  state->distance_ttl = time - distance_ttl_sum;
	  fcp_log (LOG_DEBUG, "HELPER: inserted at last in time list");
	}
  else							/* in the middle of the time list */
	{
	  state->distance_ttl =
		time - (distance_ttl_sum - time_list->distance_ttl);
	  time_list->distance_ttl = time_list->distance_ttl - state->distance_ttl;
	  time_list->time_prev->time_next = state;
	  state->time_next = time_list;
	  state->time_prev = time_list->time_prev;
	  time_list->time_prev = state;
	  fcp_log (LOG_DEBUG, "HELPER: inserted in the middle of time list");
	}
}

/* this funtion removes the state from the time ordered list. it determines
   if the state is in the time ordered list, sets the pointer of the states
   correct and sets the distance of the removed state to zero. but it don't
   free the used memory of the state. */
void time_list_remove (struct state_list *state)
{
  if (state->time_prev != NULL)	/* is the state in the time ordered list */
	{
	  if (state->time_next == NULL)	/* we are last element of the time list */
		{
		  state->time_prev->time_next = NULL;
		  fcp_log (LOG_DEBUG, "HELPER: removed last element of time list");
		}
	  else						/* we are in the middle of the time list */
		{
		  state->time_next->distance_ttl += state->distance_ttl;
		  state->time_next->time_prev = state->time_prev;
		  state->time_prev->time_next = state->time_next;
		  fcp_log (LOG_DEBUG,
				   "HELPER: removed element from the middle of time list");
		}
	}							/* end removing */
  else
	{
	  fcp_log (LOG_DEBUG,
			   "HELPER: time_list_remove called although not in time list");
	}
  state->time_next = NULL;
  state->time_prev = NULL;
  state->distance_ttl = 0;
}

/* Small help func takes ip-adress-string, determines its validity
   and write the integer represantation at address.
   Returns 1 if succseful converted, 0 if the dotted isn't valid.
   If you want to parse IP/netmask pairs, call parse_ip_netmask
   first - it will remove the netmask, then use this func */
int parse_ip_address (char *c, unsigned int *address)
{
  int quat, i, j, digit_bol;
  char buf[20];
  char *p, *q, *r;
  unsigned char *addrp;

  sprintf (debug_msg_helper, "HELPER: parsing ip: \"%s\"", c);
  fcp_log (LOG_DEBUG, debug_msg_helper);

  quat = 0;
  digit_bol = 1;
  buf[0] = '\0';
  /* cool dirty hack to address the bytes of the int easily */
  addrp = (unsigned char *) address;

  /* make a copy of the dotted string, because we modify it */
  strncpy (buf, c, 20);
  p = buf;

  /* search three times for a dot in the string */
  for (i = 0; i < 3; i++)
	{
	  if ((q = strchr (p, '.')) == NULL)
		return 0;
	  else
		{
		  *q = '\0';			/* cut off at the dot */
		  if (strlen (p))		/* is the distance between dots greater 0 */
			{
			  r = p;
			  for (j = 0; j < strlen (p); j++, r++)	/* are all char of the
													   byte digits */
				digit_bol = digit_bol && isdigit (*r);
			  if (digit_bol)
				{
				  quat = atoi (p);
				  if (quat > 255)	/* is it a byte or greater */
					return 0;
				  else
					addrp[i] = (unsigned char) quat;
				}
			  else
				return 0;
			}
		  else
			return 0;
		}
	  p = q + 1;
	}							/* for */

  /* and the last byte */
  if (strlen (p))
	{
	  r = p;
	  for (j = 0; j < strlen (p); j++, r++)
		digit_bol = digit_bol && isdigit (*r);
	  if (digit_bol)
		{
		  quat = atoi (p);
		  if (quat > 255)
			return 0;
		  else
			addrp[3] = (unsigned char) quat;
		  return 1;
		}
	  else
		return 0;
	}
  else
	return 0;
}

/* Small help func takes ip-adress-string, determines if a valid
   netmask is specified and inserts the netmask into mask.
   Cuts of the netmask of the string, if it founds a netmask !!!
   Returns 0 if no netmaks found, -1 if netmaks isn't valid, and
   1 if sucsessful.  */
int parse_ip_netmask (char *c, unsigned int *mask)
{
  char *p, *q;
  unsigned int netmask;

  p = c;

  if ((q = strchr (p, '/')) == NULL)
	return 0;
  else
	{
	  *q = '\0';				/* cut of the netmask */
	  q++;

	  sprintf (debug_msg_helper, "HELPER: netmask: \"%s\"", q);
	  fcp_log (LOG_DEBUG, debug_msg_helper);

	  if (parse_ip_address (q, &netmask) == 1)	/* and parse the netmask */
		{
		  *mask = netmask;
		  return 1;
		}
	  else
		{
		  *mask = 0;
		  return -1;
		}
	}
}

/* Small help func takes ip-port-string, determines if a valid
   port or range is specified and inserts the results into
   lower- and upperport. If it is one port, upperport will
   have the same value like the lowerport.
   Returns 0 if something is wrong, and 1 if everything is ok. */
int parse_tcp_ports (char *c, unsigned int *lowerport,
					 unsigned int *upperport)
{
  char *p, *q, *r;
  int digit_bol, i;
  char buf[14];

  digit_bol = 1;
  /* make a copy of th string, because we modify it */
  strncpy (buf, c, 14);
  p = buf;

  if ((q = strchr (p, '-')) == NULL)	/* is it a single port or range */
	{
	  if (strlen (p))			/* is the string longer 0 */
		{
		  q = p;
		  for (i = 0; i < strlen (p); i++, q++)	/* is all digit */
			digit_bol = digit_bol && isdigit (*q);
		  if (digit_bol)
			{
			  *lowerport = atoi (p);
			  if (*lowerport > 65535)	/* check port limits */
				return 0;
			  else
				{
				  *upperport = *lowerport;
				  return 1;
				}
			}
		  else
			return 0;
		}
	  else
		return 0;
	}
  else
	{
	  *q = '\0';				/* cut the two strings */
	  q++;						/* and convert them like above */
	  if ((strlen (p)) && (strlen (q)))
		{
		  r = p;
		  for (i = 0; i < strlen (p); i++, r++)
			digit_bol = digit_bol && isdigit (*r);
		  r = q;
		  for (i = 0; i < strlen (q); i++, r++)
			digit_bol = digit_bol && isdigit (*r);
		  if (digit_bol)
			{
			  *lowerport = atoi (p);
			  if (*lowerport > 65535)
				return 0;
			  *upperport = atoi (q);
			  if (*upperport > 65535)
				return 0;
			  if (*lowerport > *upperport)
				return 0;
			  else
				return 1;
			}
		  else
			return 0;
		}
	  else
		return 0;
	}
}

/* Small help func takes ip-adress-integer and returns string
   representation */
void ip2str (unsigned int address, char **rr)
{
  int i;
  char *hlp, hlp2[18];
  unsigned char *addrp = (unsigned char *) &address;
  hlp = malloc (18);
  hlp[0] = '\0';
  for (i = 0; i < 3; i++)
	{
	  sprintf (hlp2, "%i.", addrp[i]);
	  hlp = strcat (hlp, hlp2);
	}
  sprintf (hlp2, "%i", addrp[3]);
  hlp = strcat (hlp, hlp2);
  sprintf (debug_msg_helper, "HELPER: ip2str(%u) returns: \"%s\"", address,
		   hlp);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  *rr = hlp;
}

/* this function returns true (1) if the given ip is part of the network
   which is given by the adress and the netmask, otherwise it returns false
   (0). */
int ip_is_in_tuple (unsigned int address, unsigned int netmask,
					unsigned int ip)
{
  unsigned int network, comp;

  network = address & netmask;
  comp = ip & netmask;

  return (comp == network);
}

/* returns the network which is described by the address the netmask */
unsigned int give_net (unsigned int address, unsigned int netmask)
{
  return (address & netmask);
}

/* this function scans the given string for comma seperated values. every
   value will be returned in the name field of the name_value list. on error
   it will return NULL. */
struct name_value *scan_csv (char *string)
{
  struct name_value *ret, *this;
  char *str, *str_begin, *comma;

  /* is the string greater zero */
  if (strlen (string))
	{
	  /* make a copy of the string so that we can manupalte it */
	  str = malloc (strlen (string) + 1);
	  str_begin = str;
	  strcpy (str, string);
	  str[strlen (string)] = '\0';
	  /* alloc and intialise the first struct */
	  ret = malloc (sizeof (struct name_value));
	  ret->next = NULL;
	  ret->name = NULL;
	  ret->value = NULL;
	  this = ret;

	  /* check if the is any comma in the string */
	  if ((comma = strchr (str, ',')) == NULL)
		{
		  /* we haven't found any comma, so only copy the string in the first
		     name_value */
		  this->name = malloc (strlen (str) + 1);
		  strcpy (this->name, str);
		}
	  else
		{
		  /* to prevent seg fault delete last char if it is a comma */
		  str = str + strlen (str) - 1;
		  if (*str == ',')
			*str = '\0';
		  str = str_begin;
		  /* cut the two strings and copy the first half */
		  *comma = '\0';
		  this->name = malloc (strlen (str) + 1);
		  strcpy (this->name, str);
		  comma++;
		  str = comma;
		  /* until we found commas in the string do the same as above */
		  while ((comma = strchr (str, ',')) != NULL)
			{
			  this->next = malloc (sizeof (struct name_value));
			  this = this->next;
			  this->next = NULL;
			  this->value = NULL;
			  *comma = '\0';
			  this->name = malloc (strlen (str) + 1);
			  strcpy (this->name, str);
			  comma++;
			  str = comma;
			}
		  /* we haven't found a comma any more but their remain one string */
		  this->next = malloc (sizeof (struct name_value));
		  this = this->next;
		  this->next = NULL;
		  this->value = NULL;
		  this->name = malloc (strlen (str) + 1);
		  strcpy (this->name, str);
		}

	  free (str_begin);
	  return ret;
	}
  else
	return NULL;
}

/* This function returns 1 if the given ip is in the acl. Otherwise or on
   error it returns 0. */
int ip_in_acl (char *ip)
{
  unsigned int address;
  int ret;
  struct fcp_address_list *list;

  ret = 0;
  list = fcp_acl_list.next;

  if (!parse_ip_address (ip, &address))
	{
	  fcp_log (LOG_ERR,
			   "MAIN: ip_in_acl: couldn't convert the IP of the client");
	  return 0;
	}

  while (list && !ret)
	{
	  ret = ip_is_in_tuple (list->address, list->netmask, address);
	  list = list->next;
	}
  return ret;
}

/* Small help function takes a icmp-type string looks for the icmp-seperator :
	 and returns the type and code 0 if no code was found. If type and code
	 are found both will be returned.
	 Returns 0 if something is wrong, and 1 if only type was specified
	 and 2 if type and was specified. */
int parse_icmp_type (char *c, int *type, int *code)
{
	char *p, *q, *r;
	int digit_bol = 1;
	int i;
	char buf[5];

	/* make a copy of th string, because we modify it */
	strncpy (buf, c, 5);
	p = buf;

	if ((q = strchr (p, ':')) == NULL)	/* is it type only */
	{
		if (strlen (p))			/* is the string longer 0 */
		{
			q = p;
			for (i = 0; i < strlen (p); i++, q++)	/* is all digit */
				digit_bol = digit_bol && isdigit (*q);
			if (digit_bol)
			{
				*type = atoi (p);
				*code = 0;
				return 1;
			}
			else
				return 0;
		}
		else
			return 0;
	}
	else
	{
		*q = '\0';				/* cut the two strings */
		q++;						/* and convert them like above */
		if ((strlen (p)) && (strlen (q)))
		{
			r = p;
			for (i = 0; i < strlen (p); i++, r++)
				digit_bol = digit_bol && isdigit (*r);
			r = q;
			for (i = 0; i < strlen (q); i++, r++)
				digit_bol = digit_bol && isdigit (*r);
			if (digit_bol)
			{
				*type = atoi (p);
				*code = atoi (q);
				return 2;
			}
			else
				return 0;
		}
		else
			return 0;
	}
}
