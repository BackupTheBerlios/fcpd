/***************************************************************************
                          helper.h
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

#include "api.h"
#include "main.h"

#ifndef helper_h
#define helper_h 1

/* this function inserts the state at position time in the time ordered list.
   it determines with time the right place in the time list, sets the pointer
   of the states in the time list and determine the distances correct. it
   don't checks if no insert is needed because time is zero. */
void time_list_insert (struct state_list *state, unsigned int time);

/* this funtion removes the state from the time ordered list. it only sets
   the pointer of the states correct and sets the distance of the removed
   state to zero. but it don't free the used memory of the state. */
void time_list_remove (struct state_list *state);

/* Small help func takes ip-adress-string, determines its validity and write
   the integer represantation at address. Returns 1 if succseful converted, 0 
   if the dotted isn't valid. If you want to parse IP/netmask pairs, call
   parse_ip_netmask first - it will remove the netmask, then use this func */
int parse_ip_address (char *c, unsigned int *address);

/* Small help func takes ip-adress-string, determines if a valid netmask is
   specified and inserts the netmask into mask. Cuts of the netmask of the
   string, if it founds a netmask !!! Returns 0 if no netmaks found, -1 if
   netmaks isn't valid, and 1 if sucsessful.  */
int parse_ip_netmask (char *c, unsigned int *mask);

/* Small help func takes ip-port-string, determines if a valid port or range
   is specified and inserts the results into lower- and upperport. If it is
   one port, upperport will have the same value like the lowerport. Returns 0 
   if something is wrong, and 1 if everything is ok. */
int parse_tcp_ports (char *c, unsigned int *lowerport,
					 unsigned int *upperport);

/* Small help func takes ip-adress-integer and returns string representation */
void ip2str (unsigned int address, char **rr);

/* this function returns true (1) if the given ip is part of the network
   which is given by the adress and the netmask, otherwise it returns false
   (0). */
int ip_is_in_tuple (unsigned int address, unsigned int netmask,
					unsigned int ip);

/* returns the network which is described by the address the netmask */
unsigned int give_net (unsigned int address, unsigned int netmask);

/* this function scans the given string for comma seperated values. every
   value will be returned in the name field of the name_value list. on error
   it will return NULL. */
struct name_value *scan_csv (char *string);

/* This function returns 1 if the given ip is in the acl. Otherwise or on
   error it returns 0. */
int ip_in_acl (char *ip);

/* Small help function takes a icmp-type string c looks for the icmp-seperator
	 : and returns the type and code 0 if no code was found. If type and code
	 are found both will be returned.
	 Returns 0 if something is wrong, and 1 if only type was specified
	 and 2 if type and was specified. */
int parse_icmp_type (char *c, int *type, int *code);

#endif
