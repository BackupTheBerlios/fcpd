/***************************************************************************
                          main.h
                             -------------------
    begin                : Sat Nov 25 2000
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

#ifndef main_h
#define main_h 1

#include "api.h"

#define FCP_PROGRAM_VERSION "0.1"	/* change version of the program here */
#define FCP_VERSION "1.0"		/* change protocol version here */

/* the path and name of the config file. change it to your prefert */
#define FCP_CONFIG_FILE "/etc/fcpd.conf"

/* the path and name of the pid-file */
#define FCP_DEAMON_FILE "/var/run/fcpd"

/* the welcome string with which connections are welcomed */
#define FCP_WELCOME_STRING "fcpd v0.1 - GPLed\nWelcome Pilgrim.\n"

#define FCP_DEFAULT_PORT					12345
#define FCP_DEFAULT_DEBUGLEVEL				10
#define FCP_MAX_TIMEOUT						1000000
#define FCP_DEFAULT_TIMEOUT					60
#define FCP_MAX_PRIORITY_CLASSES			100
#define FCP_DEFAULT_PRIORITY_CLASSES		6
#define FCP_MAX_LOG_CLASSES					4
#define FCP_DEFAULT_LOG_CLASSES				4

/* Set the default Timeout for Nat Reservations here (secs) 60 is only for
   testing; 15 recommend for real use. */
#define FCP_NATQUERY_TIMEOUT 			30

/* Set the maximum length for each request */
#define FCP_MAX_REQUEST_LENGTH		1000

/* Set the maximum number of simultanous requests */
#define FCP_MAX_REQUESTS					100

/* global state-list - contains all rules controlled by fcpd */
struct state_list
{
  struct state_list *next;		/* double linked list of states */
  struct state_list *prev;
  struct state_list *time_next;	/* double link list ordered by timeout */
  struct state_list *time_prev;
  struct fcp_state *state;		/* the according state */
  struct reserved_list *my_reserved;	/* this is a link to the reservation
										   which was made for this rule. So
										   it's much more easier to remove
										   and reinsert the reservation
										   according to insertion and
										   removing of this rule. */
  struct reserved_list *res;	/* this is a link to a reserved struct, which
								   has dummy character, if set to NULL, this
								   is a normal struct, if it points to a
								   reserved item, this state is a dummy state
								   to be inserted into the timer-list. ->
								   NAT-Query's should timeout too, and we have 
								   only one alarm ;-) */
  unsigned int distance_ttl;	/* describes the time distance to the rule
								   time_prev */
};

struct state_list *state_list_base;	/* the fixed starting point of the list */

/* global list of IP+Port Reservations */
struct reserved_list
{
  struct reserved_list *next;	/* double linked list of reserved's */
  struct reserved_list *prev;
  struct fcp_reserved *res;		/* the according reservation */
  struct state_list *res_state;	/* the dummy state of the reservation to make
								   time handling. */
  struct state_list *my_state;	/* this is a link to the state of the
								   according rule, if one is present. If only 
								   a reservation is present this points to
								   NULL. */
};

struct reserved_list *reserved_list_base;	/* the fixed starting point of
											   the list */

/* the following variables will be set to default values and may be
   overridden by configure */

char *fcp_config_file;
int fcp_loglevel_override;		/* loglevel was specified on command line? */

/* the port on which the server listens */
int fcp_port;

/* the loglevel of the server, defined in debug */
int fcp_loglevel;

/* the default timeout until a rule will be removed automatically */
int fcp_timeout;

/* the number of priority classes, priority classes will be used to */
/* classify rules in blocks with same actions, in order to engage precedence */
int fcp_priorityclasses;

/* the number of log classes */
int fcp_logclasses;

/* This list contains the IPs which are allowed to connect to the fcpd. */
struct fcp_address_list fcp_acl_list;

/* This enumaration contains all valid method to check the access rights of a 
   client */
enum access_methods
{
  ACL
};

/* This enumaration contains the method which will be used to check the
   access rigths */
enum access_methods access_check_method;

/* priority_class_action represents the actual action of this priority class
   if any rules are in there. Zero means no action defined and no rule in
   this class. The actions are defined in api.h. rules_per_priority_class
   contains the number of rules which are actualy in this priority class. If
   there are no more rules in a class the priority_class_action have to
   reseted to zero. */
int priority_class_action[FCP_MAX_PRIORITY_CLASSES],
  rules_per_priority_class[FCP_MAX_PRIORITY_CLASSES];

#endif
