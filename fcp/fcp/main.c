/***************************************************************************
                          main.c
                             -------------------
    begin                : Sat Nov 25 18:39:28 CET 2000
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>

#include "main.h"
#include "debug.h"
#include "api.h"
#include "parse.h"
#include "interpret.h"
#include "configure.h"
#include "helper.h"
#include "network.h"


/* makes the network connection and contains the loop for evaluating the
   requests */
void srv_listen (void)
{

  int access_allowed;
  char error[256];
  char *buffer;

  int *socket;
  char *request, *ip_address;

  /* this is the reply of the parser. Must be dynamic due to possibly very
     large answers (e.g. to query requests) */
  char **reply;
  /* *reply is a normal char* if you like, the other * is used to be able to
     allocate a new string and copy the adress to *reply in interpret() */

  /* helper struct needed for freeing allocated memory */
  struct name_value *name_value_helper;

  /* allocate memory for the base of the name-value list, which will be
     filled */
  /* by the parser and interpreted in interpreter, */
  struct name_value *name_value_struct = malloc (sizeof (struct name_value));

  /* inititalize the state list */
  state_list_base = malloc (sizeof (struct state_list));
  state_list_base->next = NULL;	/* this is the beginning of the state list */
  state_list_base->prev = NULL;
  state_list_base->time_next = NULL;
  state_list_base->time_prev = NULL;
  state_list_base->state = NULL;
  state_list_base->distance_ttl = 0;
  state_list_base->res = NULL;	/* this will be no dummy... */

  /* inititalize the reserved list */
  reserved_list_base = malloc (sizeof (struct reserved_list));
  reserved_list_base->next = NULL;	/* this is the beginning of the state
									   list */
  reserved_list_base->prev = NULL;
  reserved_list_base->res = NULL;
  state_list_base->distance_ttl = 0;

  /* initialitze helper struct */
  name_value_helper = NULL;

  /* initialize the name-value pair list for the parser */
  name_value_struct->name = NULL;
  name_value_struct->value = NULL;
  name_value_struct->next = NULL;


  init_network ();

  socket = malloc (sizeof (int));
  ip_address = malloc (16);
  request = malloc (FCP_MAX_REQUEST_LENGTH);

  buffer = malloc (FCP_MAX_REQUEST_LENGTH);

  sprintf (debug_msg_helper, "MAIN: entering main loop.");
  fcp_log (LOG_INFO, debug_msg_helper);

  while (1)
	{


	  if (get_full_request (socket, request, ip_address) < 0)
		{
		  /* sprintf (debug_msg_helper, "MAIN: get_full_request failed, may
		     be due to port change"); fcp_log (LOG_INFO, debug_msg_helper);

		     this often occurs, because ALARM signal kills select - no prob,
		     simply go in next round...

		   */
		}
	  else
		{
		  sprintf (debug_msg_helper, "MAIN: received request from %s",
				   ip_address);
		  fcp_log (LOG_INFO, debug_msg_helper);

		  /* To prevent unallowed connections we assume no access rights
		     first. */
		  access_allowed = 0;

		  /* Use the definied method to check if the client is allowed to
		     connect. At this time ACL is the only method. */
		  switch (access_check_method)
			{
			case ACL:
			  access_allowed = ip_in_acl (ip_address);
			  break;
			default:
			  access_allowed = 0;
			  fcp_log (LOG_ERR,
					   "MAIN: unknown method to check access rights. access "
                       "denied.");
			  break;
			}

		  /* First check if the connecting client is allowed to connect. */
		  if (access_allowed)
			{
			  reply = malloc (sizeof (char *));

			  /* running parse and interpret - if one fails do nothing and */
			  /* return error to the connection */
			  if (!parse
				  (request, strlen (request), name_value_struct, error))
				{
				  if (!interpret (name_value_struct, reply, ip_address))
					{			/* everything's fine -> pass the answer to
								   the buffer */
					  sprintf (debug_msg_helper, "MAIN: Interpret succesful");
					  fcp_log (LOG_DEBUG, debug_msg_helper);

					  sprintf (buffer, "%s\r\n", *reply);
					  sprintf (debug_msg_helper,
							   "MAIN: Responselaenge: \"%i\"",
							   strlen (*reply));
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					}
				  else
					{
					  sprintf (debug_msg_helper,
							   "MAIN: Interpret returned error");
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					  sprintf (debug_msg_helper, "MAIN: Response: \"%s\"",
							   *reply);
					  fcp_log (LOG_INFO, debug_msg_helper);
					  sprintf (buffer, "%s\r\n", *reply);
					}
				  free (*reply);	/* freeing *reply malloc'ed in interpret */
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "MAIN: Parser returning: %s - aborting", error);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  sprintf (buffer, "%s\r\n", error);
				}

			  send_response (*socket, buffer);
			  free (reply);		/* freeing reply malloc'ed in main */

			  while (name_value_struct != NULL)
				{
				  name_value_helper = name_value_struct->next;
				  if (name_value_struct->name != NULL)
					free (name_value_struct->name);
				  if (name_value_struct->value != NULL)
					free (name_value_struct->value);
				  free (name_value_struct);
				  name_value_struct = name_value_helper;
				}


			  /* reallocate the name-value struct for the next request */
			  name_value_struct = malloc (sizeof (struct name_value));
			  name_value_struct->name = NULL;
			  name_value_struct->value = NULL;
			  name_value_struct->next = NULL;
			}
		  else					/* if (access_allowed) -> no access for the
								   client */
			{
			  sprintf (buffer, "FCP=%s SEQ=0 401 Unauthorized", FCP_VERSION);
			  send_response (*socket, buffer);
			  switch (access_check_method)
				{
				case ACL:
				  sprintf (buffer,
						   "your IP isn't in the Access Control List (ACL)"
                           ".\r\n");
				  break;
				default:
				  sprintf (buffer, "unknown authorization method. \r\n");
				  break;
				}
			  sprintf (debug_msg_helper,
					   "MAIN: unauthorized connection from %s", ip_address);
			  fcp_log (LOG_NOTICE, debug_msg_helper);
			  send_response (*socket, buffer);
			}
		}						/* if get_full_request */
	}							/* while (1) main loop */
}								/* srv_listen */

/* this function does some things to become a daemon process */
int daemon_init (void)
{
  FILE *pid_file;
  pid_t pid;
  char pid_file_line[7];

  /* check for existing pid-file */
  pid_file = fopen (FCP_DEAMON_FILE, "r");
  pid_file_line[0] = '\0';
  pid = getpid ();

  if (pid_file != NULL)
	{
	  fgets (pid_file_line, 6, pid_file);
	  fprintf (stderr, "\nERROR: found pidfile, there might be another fcpd"
			   " running with\n       pid %s, current pid is %i, "
			   "please make shure, there's no other\n       fcpd "
			   "running and then remove the file %s\n\n",
			   pid_file_line, pid, FCP_DEAMON_FILE);
	  fclose (pid_file);
	  exit (-1);
	}

  if ((pid = fork ()) < 0)
	return (-1);
  else if (pid != 0)
	exit (0);					/* parents goes bye-bye */

  /* child continues */
  setsid ();					/* become session leader */
  chdir ("/");					/* change working directory */
  umask (0);					/* clear our file mode creation mask */

  /* creating a pidfile under /var/run */
  pid = getpid ();
  if ((pid_file = fopen (FCP_DEAMON_FILE, "w")) == NULL)
	{
	  sprintf (debug_msg_helper, "MAIN: WARNING: unable to create %s",
			   FCP_DEAMON_FILE);
	  fcp_log (LOG_INFO, debug_msg_helper);
	}
  else
	{
	  sprintf (pid_file_line, "%i", pid);
	  fputs (pid_file_line, pid_file);
	  sprintf (debug_msg_helper, "MAIN: creating %s", FCP_DEAMON_FILE);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	  fclose (pid_file);
	}
  return (0);
}								/* daemon_init */

/* this function is called by signal KILL and terminated ourself */
/* this is the "official" way to end the server process */
static void sig_term ()
{
  fcp_log (LOG_INFO, "MAIN: sig_term: received signal TERM");
  /* close all file descriptors */
  stop_network ();
  /* remove the pidfile */
  unlink (FCP_DEAMON_FILE);
  fcp_log (LOG_INFO, "MAIN: sig_term: everything cleaned up. exiting");
  closelog ();
  exit (0);
}								/* sig_term */

/* this function is called by signal HUP and reads the config file */
static void sig_hup ()
{
  configure ();
}								/* sig_hup */

/* sig_alarm is called if a timer exceeds, what most likely means, that a
   rule timed out and have to be deleted */
static void sig_alarm ()
{
  struct state_list *alarm_list;
  unsigned int rem_time;
  char api_error[256];

  api_error[0] = '\0';
  fcp_log (LOG_DEBUG, "MAIN: sig_alarm: got signal ALRM");
  rem_time = alarm (0);
  sprintf (debug_msg_helper, "MAIN: sig_alarm: remaining time is %u",
		   rem_time);
  fcp_log (LOG_DEBUG, debug_msg_helper);
  if (rem_time == 0)			/* is it really the time to delete the next
								   state of the time list */
	{
	  if (state_list_base->time_next != NULL)	/* is there any state in the
												   time list */
		{
		  alarm_list = state_list_base->time_next;
		  alarm_list->distance_ttl = 0;
		  /* delete rules and states while their distance is zero */
		  while ((alarm_list != NULL) && (alarm_list->distance_ttl == 0))
			{
			  /* first check if this is a dummy state for reserved */
			  if (alarm_list->res == NULL)
				{

				  /* try to delete rule from firewall */
				  if (fcp_rule_delete (alarm_list->state, &api_error[0]))
					{
					  /* Decrease number of rule and remove action of the
					     priority class if necessarry */
					  if (alarm_list->state->sop->pri_class_def)
						{
						  rules_per_priority_class[alarm_list->state->sop->
												   pri_class] -= 1;
						  if (rules_per_priority_class
							  [alarm_list->state->sop->pri_class] == 0)
							priority_class_action[alarm_list->state->sop->
												  pri_class] = 0;
						}
					  /* remove from the normal list */
					  alarm_list->prev->next = alarm_list->next;
					  if (alarm_list->next != NULL)	/* maybe we are last of
													   the normal list */
						alarm_list->next->prev = alarm_list->prev;
					  /* remove from time ordered list */
					  time_list_remove (alarm_list);
					  /* if an according reservation exist, free it also
					     complet */
					  if (alarm_list->my_reserved)
						{
						  /* remove from the reservation list */
						  alarm_list->my_reserved->prev->next =
							alarm_list->my_reserved->next;
						  if (alarm_list->my_reserved->next)
							alarm_list->my_reserved->next->prev =
							  alarm_list->my_reserved->prev;
						  /* try to free the allocated port */
						  if (!fcp_port_release
							  (alarm_list->my_reserved->res, &api_error[0]))
							{
							  sprintf (debug_msg_helper,
									   "MAIN: sig_alarm: automatic deleting of"
                                       " port reservation failed with %s",
									   api_error);
							  fcp_log (LOG_ERR, debug_msg_helper);
							}
						  /* freeing all memory of the reservation */
						  free (alarm_list->my_reserved->res_state);
						  free (alarm_list->my_reserved->res);
						  free (alarm_list->my_reserved);
						  fcp_log (LOG_DEBUG,
								   "MAIN: sig_alarm: deleting of reservation "
                                   "complete");
						}
					  /* freeing the memory of the deleted state */
					  free (alarm_list->state->pme);
					  free (alarm_list->state->sop);
					  free (alarm_list->state->owner_ip);
					  free (alarm_list->state);
					  free (alarm_list);
					  fcp_log (LOG_DEBUG,
							   "MAIN: sig_alarm: deleting of rule and state "
                               "complete");
					  /* step to next element in time list */
					  alarm_list = state_list_base->time_next;
					}
				  else
					{
					  sprintf (debug_msg_helper,
							   "MAIN: sig_alarm: automatic deleting of rule "
                               "failed with %s",
							   api_error);
					  fcp_log (LOG_ERR, debug_msg_helper);
					  /* what should we do with the state of this rule? we
					     remove it from time list to prevent endless failing
					     by automatic remove. *FIXME* If deletion failed and
					     we get the same request, we response with a Keep
					     Alive... hmmm not what i suspected */
					  time_list_remove (alarm_list);
					  /* step to next element in time list */
					  alarm_list = state_list_base->time_next;
					}
				}
			  else				/* dummy state */
				/* here */
				{
				  /* remove from the reservation list */
				  alarm_list->res->prev->next = alarm_list->res->next;
				  if (alarm_list->res->next != NULL)
					alarm_list->res->next->prev = alarm_list->res->prev;
				  /* remove the dummy from the normal state list */
				  // alarm_list->prev->next = alarm_list->next;
				  // if (alarm_list->next != NULL) /* maybe we are last of
				  // the normal list */
				  // alarm_list->next->prev = alarm_list->prev;
				  time_list_remove (alarm_list);

				  if (!fcp_port_release (alarm_list->res->res, &api_error[0]))
					{
					  sprintf (debug_msg_helper,
							   "MAIN: sig_alarm: automatic deleting of port "
                               "reservation failed with %s",
							   api_error);
					  fcp_log (LOG_ERR, debug_msg_helper);
					}

				  free (alarm_list->res->res);
				  free (alarm_list->res);
				  free (alarm_list);

				  fcp_log (LOG_DEBUG,
						   "MAIN: sig_alarm: deleting of reservation structure"
                           " complete");
				  /* step to next element in time list */
				  alarm_list = state_list_base->time_next;
				}
			}
		  /* finaly set the alarm to the new value */
		  if (state_list_base->time_next != NULL)
			{
			  sprintf (debug_msg_helper,
					   "MAIN: sig_alarm: setting alarm to %i",
					   state_list_base->time_next->distance_ttl);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  alarm (state_list_base->time_next->distance_ttl);
			}
		  else
			{
			  fcp_log (LOG_DEBUG, "MAIN: sig_alarm: setting alarm to 0");
			  alarm (0);
			}
		}
	  else
		{
		  /* this have to be a bug, because we send us an ALRM but there are
		     no states left */
		  fcp_log (LOG_WARNING,
				   "MAIN: sig_alarm: state list is empty but we got ALRM ???");
		  alarm (0);
		}
	}
  else
	{
	  /* someone or something has send our process the ALRM signal, but not
	     me */
	  sprintf (debug_msg_helper,
			   "MAIN: sig_alarm: we got SIG_ALRM but %u seconds left until "
               "next delete",
			   rem_time);
	  fcp_log (LOG_WARNING, debug_msg_helper);
	}
}								/* sig_alarm */

/* the server takes no command line args at the moment */
int main (int argc, char *argv[])
{
  int return_value, i;
  int no_daemon = 0;

  /* Initialize some global variables with (compile-time) defaults */
  fcp_loglevel = FCP_DEFAULT_DEBUGLEVEL;
  fcp_port = FCP_DEFAULT_PORT;
  fcp_timeout = FCP_DEFAULT_TIMEOUT;
  fcp_priorityclasses = FCP_DEFAULT_PRIORITY_CLASSES;
  fcp_logclasses = FCP_DEFAULT_LOG_CLASSES;
  fcp_config_file = FCP_CONFIG_FILE;
  fcp_loglevel_override = 0;
  fcp_acl_list.address = 0;
  fcp_acl_list.netmask = 0;
  fcp_acl_list.next = NULL;
  fcp_internal_ips.address = 0;
  fcp_internal_ips.netmask = 0;
  fcp_internal_ips.next = NULL;
  fcp_masq_ips.address = 0;
  fcp_masq_ips.netmask = 0;
  fcp_masq_ips.next = NULL;
  fcp_dmz_ips.address = 0;
  fcp_dmz_ips.netmask = 0;
  fcp_dmz_ips.next = NULL;
  fcp_in_interface.name = NULL;
  fcp_in_interface.next = NULL;
  fcp_out_interface.name = NULL;
  fcp_out_interface.next = NULL;
  fcp_dmz_interface.name = NULL;
  fcp_dmz_interface.next = NULL;
  fcp_internal_IP = 0;
  fcp_outer_IP = 0;
  fcp_demilitary_IP = 0;
  /* The only allowed method until now is ACL. */
  access_check_method = ACL;
  memset (&priority_class_action[0], 0,
		  sizeof (priority_class_action[FCP_MAX_PRIORITY_CLASSES]));
  memset (&rules_per_priority_class[0], 0,
		  sizeof (rules_per_priority_class[FCP_MAX_PRIORITY_CLASSES]));
  fcp_log_per_sec = 0;
  fcp_log_per_min = 0;
  fcp_log_per_hou = 0;
  fcp_log_per_day = 0;

  while ((i = getopt (argc, argv, "hdvf:l:")) != EOF)
	{
	  switch (i)
		{
		case 'h':
		  printf ("\nusage: %s [-h] [-d] [-l] [-v]\n"
				  "  -h display this help message\n"
				  "  -d don't run in dameon mode\n"
				  "  -l specify debug level\n"
				  "  -f specify config file\n"
				  "  -v prints out protocol version number and exits\n\n"
				  "example: %s -d -l 7 -f /etc/fcpd.conf.2 \n"
				  "  this runs the server in non-damon mode with full "
                  "debugging\n"
				  "  using non-default config file /etc/fcpd.conf.2\n\n",
				  argv[0], argv[0]);
		  return (0);
		  break;
		case 'd':
		  no_daemon = 1;
		  break;
		case 'l':
		  fcp_loglevel = atoi (optarg);
		  fcp_loglevel_override = 1;
		  break;
		case 'f':
		  fcp_config_file = optarg;
		  break;
		case 'v':
		  printf ("fcpd version %s; supporting FCP %s\n", FCP_PROGRAM_VERSION,
				  FCP_VERSION);
		  return (0);
		  break;
		}
	}


  /* open syslogger */
  fcp_openlog ("fcpd", LOG_PID, LOG_DAEMON);

  /* initialize the signal handler */
  if (signal (SIGTERM, sig_term) == SIG_ERR)
	fcp_log (LOG_CRIT, "MAIN: main: TERM signal error");
  if (signal (SIGHUP, sig_hup) == SIG_ERR)
	fcp_log (LOG_CRIT, "MAIN: main: HUP signal error");
  if (signal (SIGALRM, sig_alarm) == SIG_ERR)
	fcp_log (LOG_CRIT, "MAIN: main: ALRM signal error");

  /* try to become a deamon process */
  if (!no_daemon)
	{
	  if ((return_value = daemon_init ()) < 0)
		{
		  fcp_log (LOG_CRIT, "MAIN: main: fork error");
		  exit (-1);
		}
	  else
		{
		  fcp_log (LOG_INFO, "MAIN: fcpd startet as a daemon process");
		}
	  sprintf (debug_msg_helper, "MAIN: daemon_init returned %i",
			   return_value);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	}
  else
	{
	  sprintf (debug_msg_helper, "MAIN: fcpd startet as non-daemon process");
	  fcp_log (LOG_INFO, debug_msg_helper);
	}

  /* read the config file */
  if (!configure ())
	/* If the initale reading of the config file fails we kill ourself,
	   because we didn't have enough information to run correctly. */
	raise (SIGTERM);

  /* start to listen on the tcp port defined */
  srv_listen ();

  fcp_log (LOG_DEBUG, "returned from srv_listen in main");
  fcp_closelog ();

  return (0);
}								/* main */
