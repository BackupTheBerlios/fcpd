/***************************************************************************
                          interpret.c
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
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "debug.h"
#include "interpret.h"
#include "main.h"
#include "validity.h"
#include "helper.h"

/* assign int values for all known Name-Tokens, needed for switch */
#define fcp_token_unknown 			0
#define fcp_token_SET 					1
#define fcp_token_RELEASE 			2
#define fcp_token_QUERY 				3
#define fcp_token_QUERYNAT 			4
#define fcp_token_RELEASENAT		5
#define fcp_token_IP						6
#define fcp_token_PORT					7
#define fcp_token_FCP 					8
#define fcp_token_SEQ						9
#define fcp_token_PROTO					10
#define fcp_token_SRCIP					11
#define fcp_token_DSTIP					12
#define fcp_token_SRCPORT				13
#define fcp_token_DSTPORT				14
#define fcp_token_TOSFLD				15
#define fcp_token_TCPSYNALLOWED	16
#define fcp_token_ICMPTYPE			17
#define fcp_token_ININTERFACE		18
#define fcp_token_OUTINTERFACE	19
#define fcp_token_ACTION				20
#define fcp_token_TIMER					21
#define fcp_token_REFLEXIVE			22
#define fcp_token_PRIORITYCLASS	23
#define fcp_token_LOG						24
#define fcp_token_ICMPMESSAGE		25
#define fcp_token_UPPERPORT			26

/* overall number of known name-tokens */
#define fcp_token_at_all				26

/* define ints representing the Request type */
#define fcp_req_type_SET				1
#define fcp_req_type_RELEASE		2
#define fcp_req_type_QUERY			3
#define fcp_req_type_QUERYNAT		4
#define fcp_req_type_RELEASENAT	5

/* Interpreter information needed to determine the position within protocol */
#define fcp_nowhere			0	/* undetermined yet */
#define fcp_in_REQH			1	/* request header */
#define fcp_in_PME			2	/* PacketMatchingExpression */
#define fcp_in_SETOPTS	3		/* SetOptions */
#define fcp_in_PCKMODF	4		/* PacketModifier */
#define fcp_in_NATADDS	5		/* IP, PORT, ... */

/* Freeing the following memory allocations is needed every time the */
/* interpreter exits with errors, so we define a macro */
#define FCP_FREE_MEM free(pme);free(sop);free(state->owner_ip);free(state);free(reserved);
// free(sop->packet_modf);

/* uncomment this for extra ammount of debug from compare_pme */
/* #define compare_pme_extra_debug 1 */

/* Following definition assigns the strings to the keyword defines above */
static char *token_names[] = { "",	// zero is defined as unknown
  "SET", "RELEASE", "QUERY", "QUERYNAT", "RELEASENAT", "IP",
  "PORT", "FCP", "SEQ", "PROTO", "SRCIP", "DSTIP", "SRCPORT",
  "DSTPORT", "TOSFLD", "TCPSYNALLOWED", "ICMPTYPE", "ININTERFACE",
  "OUTINTERFACE", "ACTION", "TIMER", "REFLEXIVE", "PRIORITYCLASS",
  "LOG", "ICMPMESSAGE", "UPPERPORT"
};

/* structures from api.h */
struct fcp_pme *pme;			/* Holds the PackeMatchingExpression */
struct fcp_sop *sop;			/* Holds the SetOptions */
struct fcp_state *state;		/* the current request's state */
struct fcp_reserved *reserved;	/* NAT */

struct state_list *states;
struct state_list *states_helper;
struct reserved_list *reservations;

int req_type;					/* Request type (SET, RELEASE, ..) */
int in_where;					/* Where we are (PME, SetOptions, ..) */
int seq;						/* Current sequence number */
int seq_isdef;					/* Was a sequence defined ? */

int fcp_icmpmessage_allowed;	/* little helpers for sematik interpretion */
int fcp_packetmodifier_allowed;

char api_error[256];


/* function compares the given string with all defines from above */
/* if one matches exactly it's int code is returned */
/* _IMPORTANT_: the protocol _is_ case-insensitiva (SET == sEt) */
int compare_to_defs (char *token)
{
  int i;
  for (i = 1; i <= fcp_token_at_all; i++)
	{
	  if (!strcasecmp (token, token_names[i]))
		return i;
	}
  return fcp_token_unknown;
};

/* small help func to compare two pme's - completely rewritten for use in
   QUERY (set new parameter "type" to 1) type is defined as follows: 0: equal 
   if all fields are equal and all defines are equal !0: equal if all fields
   are equal where pme1's define-param is set */
int compare_pme (struct fcp_pme *pme1, struct fcp_pme *pme2, int type)
{
  int diff_found;
  void ll (char *tt)
  {
#ifdef compare_pme_extra_debug
	if (diff_found)
	  {
		diff_found = 0;
		sprintf (debug_msg_helper, "INTERPRET: compare_pme: first diff at %s",
				 tt);
		fcp_log (LOG_DEBUG, debug_msg_helper);
	  }
#endif
  }
  int retval = 1;
  diff_found = 1;
  if ((!type) || (pme1->proto_def))
	{
	  retval = retval && ((pme1->proto_def == pme2->proto_def) || type);
	  retval = retval && (pme1->proto == pme2->proto);
	  if (!retval)
		ll ("proto");
	}
  if ((!type) || (pme1->src_ip_def))
	{
	  retval = retval && ((pme1->src_ip_def == pme2->src_ip_def) || type);
	  retval = retval && (pme1->src_ip == pme2->src_ip);
	  if (!retval)
		ll ("src_ip");
	}
  if ((!type) || (pme1->src_netmask_def))
	{
	  retval = retval && ((pme1->src_netmask_def == pme2->src_netmask_def)
						  || type);
	  retval = retval && (pme1->src_netmask == pme2->src_netmask);
	  if (!retval)
		ll ("src_netmask");
	}
  if ((!type) || (pme1->src_pt_def))
	{
	  retval = retval && ((pme1->src_pt_def == pme2->src_pt_def) || type);
	  retval = retval && (pme1->src_pt == pme2->src_pt);
	  if (!retval)
		ll ("src_pt");
	}
  if ((!type) || (pme1->src_uppt_def))
	{
	  retval = retval && ((pme1->src_uppt_def == pme2->src_uppt_def) || type);
	  retval = retval && (pme1->src_uppt == pme2->src_uppt);
	  if (!retval)
		ll ("src_uppt");
	}
  if ((!type) || (pme1->dst_ip_def))
	{
	  retval = retval && ((pme1->dst_ip_def == pme2->dst_ip_def) || type);
	  retval = retval && (pme1->dst_ip == pme2->dst_ip);
	  if (!retval)
		ll ("dst_ip");
	}
  if ((!type) || (pme1->dst_netmask_def))
	{
	  retval = retval && ((pme1->dst_netmask_def == pme2->dst_netmask_def)
						  || type);
	  retval = retval && (pme1->dst_netmask == pme2->dst_netmask);
	  if (!retval)
		ll ("src_netmask");
	}
  if ((!type) || (pme1->dst_pt_def))
	{
	  retval = retval && ((pme1->dst_pt_def == pme2->dst_pt_def) || type);
	  retval = retval && (pme1->dst_pt == pme2->dst_pt);
	  if (!retval)
		ll ("dst_ip");
	}
  if ((!type) || (pme1->dst_uppt_def))
	{
	  retval = retval && ((pme1->dst_uppt_def == pme2->dst_uppt_def) || type);
	  retval = retval && (pme1->dst_uppt == pme2->dst_uppt);
	  if (!retval)
		ll ("dst_uppt");
	}
  if ((!type) || (pme1->tos_fld_def))
	{
	  retval = retval && ((pme1->tos_fld_def == pme2->tos_fld_def) || type);
	  retval = retval && (pme1->tos_fld == pme2->tos_fld);
	  if (!retval)
		ll ("tos_fld");
	}
  if ((!type) || (pme1->syn_flg_def))
	{
	  retval = retval && ((pme1->syn_flg_def == pme2->syn_flg_def) || type);
	  retval = retval && (pme1->syn_flg == pme2->syn_flg);
	  if (!retval)
		ll ("syn_flg");
	}
  if ((!type) || (pme1->icmp_type_def))
	{
	  retval = retval && ((pme1->icmp_type_def == pme2->icmp_type_def)
						  || type);
	  retval = retval && (pme1->icmp_type == pme2->icmp_type);
	  if (!retval)
		ll ("icmp_type");
	}
  if ((!type) || (pme1->in_if_def))
	{
	  retval = retval && ((pme1->in_if_def == pme2->in_if_def) || type);
	  retval = retval && (pme1->in_if == pme2->in_if);
	  if (!retval)
		ll ("in_if");
	}
  if ((!type) || (pme1->out_if_def))
	{
	  retval = retval && ((pme1->out_if_def == pme2->out_if_def) || type);
	  retval = retval && (pme1->out_if == pme2->out_if);
	  if (!retval)
		ll ("out_if");
	}
  return retval;
}


/* small help func to compare two setoptions, currently only ACTION is being
   compared - more will follow in future versions returns 1 on no difference
   or 0 on difference */
int compare_setopts (struct fcp_sop *sop1, struct fcp_sop *sop2)
{
  int diff_found;
  void ll (char *tt)
  {
	if (diff_found)
	  {
		diff_found = 0;
		sprintf (debug_msg_helper,
				 "INTERPRET: compare_setopts: first diff at %s", tt);
		fcp_log (LOG_DEBUG, debug_msg_helper);
	  }
  }
  int retval = 1;
  diff_found = 1;
  if (sop1->action_def)
	{
	  retval = retval && (sop1->action == sop2->action);
	  if (!retval)
		ll ("action");
	}
  else
	{
	  retval = retval && (fcp_action_pass == sop2->action);
	  if (!retval)
		ll ("action");
	}

  return retval;
}

/* This function takes a state with the action SET and insert it into the
   firewall or do anything other which is relevant. If it fails it return 1
   and the according FCP status code in the reply string. Otherwise it
   returns 0 and the FCP status code in the reply string. */
int set_action (struct fcp_state *st, char *reply)
{
  struct state_list *state_l;
  struct reserved_list *reservs;
  unsigned int req_time, alm_rem;
  int ret = 0;
  int is_keep_alive = 0;		/* a SET might be a keep-alive */

  sprintf (debug_msg_helper, "INTERPRET: processing SET command");
  fcp_log (LOG_INFO, debug_msg_helper);

  /* check if we have a keep alive or a real SET */
  state_l = state_list_base;
  while (state_l->next != NULL)
	{
	  state_l = state_l->next;
	  if (compare_pme (state_l->state->pme, st->pme, 0))	/* hit! =>
															   keep-alive or
															   rule change */
		if (compare_setopts (state_l->state->sop, st->sop))	/* keep alive! */
		  {
			fcp_log (LOG_INFO,
					 "INTERPRET: found matching rule -> KEEP ALIVE");
			is_keep_alive = 1;
			if (st->sop->timer_def)
			  {
				req_time = st->sop->timer;
				sprintf (debug_msg_helper,
						 "INTERPRET: new timeout set to %i", st->sop->timer);
				fcp_log (LOG_DEBUG, debug_msg_helper);
			  }
			else
			  {
				req_time = FCP_DEFAULT_TIMEOUT;
				sprintf (debug_msg_helper,
						 "INTERPRET: TIMER not specified - defaulting to %i sec",
						 FCP_DEFAULT_TIMEOUT);
				fcp_log (LOG_DEBUG, debug_msg_helper);
			  }
			/* have to set the distance of the first state cause we don't
			   know what state we manupalte */
			alm_rem = alarm (0);
			sprintf (debug_msg_helper, "INTERPRET: %u left to next alarm",
					 alm_rem);
			fcp_log (LOG_DEBUG, debug_msg_helper);
			if (state_list_base->time_next)
			  state_list_base->time_next->distance_ttl = alm_rem;
			if (req_time == 0)	/* the rule should now stay forever */
			  {
				if (state_l->time_prev != NULL)	/* we determine if the state
												   is in the time list only
												   for logging */
				  {
					/* remove the state from the time ordered list */
					time_list_remove (state_l);
					fcp_log (LOG_DEBUG,
							 "INTERPRET: rule will no longer be automatically"
                             " deleted");
				  }
				else			/* why we get a keep-alive with 0 for a state
								   with 0 ??? */
				  {
					fcp_log (LOG_NOTICE,
							 "INTERPRET: we got a keep-alive with timeout zero"
                             " for a rule with timeout zero ???");
				  }
			  }
			else				/* the rule should stay for amount of time */
			  {
				/* remove the state from teh time ordered list */
				time_list_remove (state_l);
				/* insert the state int the time ordered list */
				time_list_insert (state_l, req_time);
			  }					/* end stay for a time */
			/* set the new alarm */
			if (state_list_base->time_next != NULL)
			  {
				alarm (state_list_base->time_next->distance_ttl);
				sprintf (debug_msg_helper, "INTERPRET: alarm set to %i",
						 state_list_base->time_next->distance_ttl);
				fcp_log (LOG_DEBUG, debug_msg_helper);
			  }
			else
			  {
				alarm (0);
				fcp_log (LOG_DEBUG,
						 "INTERPRET: alarm set to 0 cause not state left");
			  }
		  }						/* end compare_pme */
	  if ((!compare_setopts (state_l->state->sop, st->sop))
        && (compare_pme (state_l->state->pme, st->pme, 0)))	/* rule change */
		{
		  fcp_log (LOG_INFO,
				   "INTERPRET: found matching rule -> change SETOPTS");
		  is_keep_alive = 1;	/* not really - dirty code */
		  /* now deleting editing and reinserting rule */
		  if ((ret = fcp_rule_delete (state_l->state, &api_error[0])) == 1)
			{
			  state_l->state->sop->action = st->sop->action;
			  /* insert *future* changes here */
			  if ((ret =
				   fcp_rule_insert (state_l->state, &api_error[0])) == 1)
				sprintf (reply, "FCP=%s SEQ=%i 202 Rule Changed", FCP_VERSION,
						 seq);
			  else
				sprintf (reply, "FCP=%s SEQ=%i %s", FCP_VERSION, seq,
						 api_error);
			}
		  else
			sprintf (reply, "FCP=%s SEQ=%i %s", FCP_VERSION, seq, api_error);
		  free (st->pme);
		  free (st->sop);
		  free (st->owner_ip);
		  free (st);
		  return ret;
		}

	}							/* end while */

  if (is_keep_alive == 1)		/* keep alive succeded */
	{
	  sprintf (reply, "FCP=%s SEQ=%i 201 Keeping Alive", FCP_VERSION, seq);
	  free (st->pme);
	  free (st->sop);
	  free (st->owner_ip);
	  free (st);
	  return 0;
	}

  if (is_keep_alive == 0)		/* normal insert */
	{
	  /* We have to check if a reserveration is present for this SET command.
	   */
	  reservs = reserved_list_base;
	  ret = 1;

	  fcp_log (LOG_INFO,
			   "INTERPRET: searching for a reservation for this rule");
	  while (reservs->next != NULL && ret)
		{
		  reservs = reservs->next;
			/* Is in every reservation the origin ip not zero?
				If not the following compare could be a problem. */
		  if (reservs->res->origin_ip == st->pme->src_ip
			  || reservs->res->origin_ip == st->pme->dst_ip)
			{
			  time_list_remove (reservs->res_state);
			  if (state_list_base->time_next != NULL)
				{
				  alarm (state_list_base->time_next->distance_ttl);
				  sprintf (debug_msg_helper, "INTERPRET: setting alarm to %u",
						   state_list_base->time_next->distance_ttl);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}
			  else
				{
				  alarm (0);
				  fcp_log (LOG_DEBUG,
						   "INTERPRET: setting alarm to 0 cause no rule left "
							"to delete automaticly");
				}
			  st->masq_ip = reservs->res->masq_ip;
			  st->masq_port = reservs->res->masq_port;
			  st->masq_uppt = reservs->res->masq_uppt;
			  fcp_log (LOG_INFO,
					   "INTERPRET: reservation for rule found. masqueradings"
						" copied.");
			  ret = 0;
			}
		}
	  if (ret)
		{
			/* Should it be possible to set up a rule without a reservation?
				If not we have to return an error here.
				At this time we have no reservations for NAT_REQUESTS which we don't
				have to masquerade.  */
		  fcp_log (LOG_WARNING,
				   "INTERPRET: no according reservation for this rule found.");
		}
	  fcp_log (LOG_INFO, "INTERPRET: no match - setting up new rule");
	  if (fcp_rule_insert (st, &api_error[0]) == 0)
		{
		  sprintf (debug_msg_helper, "INTERPRET: %s", api_error);
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (reply, "FCP=%s SEQ=%i %s", FCP_VERSION, seq, api_error);
		  free (st->pme);
		  free (st->sop);
		  free (st->owner_ip);
		  free (st);
		  return 1;
		}
	  else
		{
		  /* Increase number of rules of this priority class if necessarry */
		  if (st->sop->pri_class_def)
			rules_per_priority_class[st->sop->pri_class] += 1;
		  /* insert in the normal list */
		  state_l->next = malloc (sizeof (struct state_list));
		  state_l->next->next = NULL;
		  state_l->next->state = st;
		  state_l->next->prev = state_l;
		  state_l->next->res = NULL;
		  if (!ret)
			{
			  state_l->next->my_reserved = reservs;
			  reservs->my_state = state_l->next;
			}
		  else
			state_l->next->my_reserved = NULL;
		  /* insert at the right place in the time list */
		  if (st->sop->timer_def)
			req_time = st->sop->timer;
		  else
			req_time = FCP_DEFAULT_TIMEOUT;
		  if (req_time > 0)
			{
			  /* is left time to next alarm greater 0 write it to the first
			     element of the time list because eventuelly we insert at the
			     first position */
			  alm_rem = alarm (0);
			  if (alm_rem > 0)
				{
				  sprintf (debug_msg_helper,
						   "INTERPRET: %u left to next alarm", alm_rem);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  state_list_base->time_next->distance_ttl = alm_rem;
				}
			  /* insert the state in the time ordered list */
			  time_list_insert (state_l->next, req_time);
			  /* there should be a time_next state cause we inserted just one
			   */
			  alarm (state_list_base->time_next->distance_ttl);
			  sprintf (debug_msg_helper,
					   "INTERPRET: rule insert complete and alarm set to %i",
					   state_list_base->time_next->distance_ttl);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			}
		  else					/* req_time=0 => rule should not automaticly
								   be deleted */
			{
			  fcp_log (LOG_DEBUG,
					   "INTERPRET: rule will not automatically be deleted");
			  state_l->next->distance_ttl = req_time;
			  state_l->next->time_next = NULL;
			  state_l->next->time_prev = NULL;
			}
		  sprintf (reply, "FCP=%s SEQ=%i 200 OK", FCP_VERSION, seq);
		  return 0;
		}
	}							/* normal insert */
	return 1;
}								/* set_action */

/* This function takes a state with the action RELEASE and removes it from
   the firewall or do anything other which is relevant. If it fails it return
   1 and the according FCP status code in the reply string. Otherwise it
   returns 0 and the FCP status code in the reply string. */
int release_action (struct fcp_state *st, char *reply, char *own, int *reflex)
{
  struct state_list *state_l;
  unsigned int alm_rem;
  int deletion_complete = 0;	/* helper for loop */

  sprintf (debug_msg_helper, "INTERPRET: processing RELEASE command");
  fcp_log (LOG_INFO, debug_msg_helper);

  /* search for the according rule */
  state_l = state_list_base;
  while (state_l->next != NULL)
	{
	  state_l = state_l->next;
	  if (compare_pme (state_l->state->pme, st->pme, 0))	/* hit! */
		{
		  sprintf (debug_msg_helper, "INTERPRET: matching rule found");
		  fcp_log (LOG_INFO, debug_msg_helper);

		  if (strcmp (state_l->state->owner_ip, own) != 0)
			{
			  sprintf (debug_msg_helper,
					   "INTERPRET: rule owned by %s - ignoring",
					   state_l->state->owner_ip);
			  fcp_log (LOG_INFO, debug_msg_helper);
			}
		  else if (!fcp_rule_delete (state_l->state, &api_error[0]))
			{
			  sprintf (debug_msg_helper, "INTERPRET: %s", api_error);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (reply, "FCP=%s SEQ=%i %s", FCP_VERSION, seq,
					   api_error);
			  fcp_log (LOG_DEBUG, "INTERPRET: exiting");
			  free (st->pme);
			  free (st->sop);
			  free (st->owner_ip);
			  free (st);
			  return 1;
			}
		  else
			{
			  if (state_l->state->sop->reflexive == 1)
				{
				  *reflex = 1;
				}
			  /* Decrease number of rule and remove action of the priority
			     class if necessarry */
			  if (state_l->state->sop->pri_class_def)
				{
				  rules_per_priority_class[state_l->state->sop->pri_class] -=
					1;
				  if (rules_per_priority_class[state_l->state->sop->pri_class]
					  == 0)
					priority_class_action[state_l->state->sop->pri_class] = 0;
				}
			  /* deleting from the normal list */
			  if (state_l->next != NULL)
				{
				  state_l->next->prev = state_l->prev;
				  state_l->prev->next = state_l->next;
				}
			  else
				{
				  state_l->prev->next = NULL;
				}
			  if (state_l->my_reserved)
				{
				  /* reinsert the according reserved with default NAT timeout
				   */
				  fcp_log (LOG_DEBUG,
						   "INTERPRET: reinserting the according reservation");
				  state_l->my_reserved->my_state = NULL;
				  time_list_insert (state_l->my_reserved->res_state,
									FCP_NATQUERY_TIMEOUT);
				}
			  /* maybe there is no state in the time list */
			  if (state_list_base->time_next != NULL)
				{
				  /* setting remaining time to the first element of time list
				     so we don't have to handle deleting of first element
				     speratly */
				  alm_rem = alarm (0);
				  state_list_base->time_next->distance_ttl = alm_rem;
				  sprintf (debug_msg_helper,
						   "INTERPRET: %u seconds left until next alarm",
						   alm_rem);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  /* remove from the time ordered list */
				  time_list_remove (state_l);
				  if (state_list_base->time_next != NULL)
					{
					  alarm (state_list_base->time_next->distance_ttl);
					  sprintf (debug_msg_helper,
							   "INTERPRET: setting alarm to %u",
							   state_list_base->time_next->distance_ttl);
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					}
				  else
					{
					  alarm (0);
					  fcp_log (LOG_DEBUG,
							   "INTERPRET: setting alarm to 0 cause no rule "
								"left to delete automaticly");
					}
				}
			  else
				{
				  alarm (0);
				  fcp_log (LOG_DEBUG,
						   "INTERPRET: setting alarm to 0 because no state "
                           "left to delete");
				}
			  /* freeing the memory of the state */
			  free (state_l->state->pme);
			  free (state_l->state->sop);
			  free (state_l->state->owner_ip);
			  free (state_l->state);
			  free (state_l);
			  deletion_complete = 1;
			  fcp_log (LOG_INFO, "INTERPRET: rule removal complete");
			  break;
			}
		}
	}
  if (deletion_complete == 0)
	{
	  fcp_log (LOG_INFO, "INTERPRET: no matching rule found to remove");
	  sprintf (reply,
			   "FCP=%s SEQ=%i 400 Bad Request: no matching rule found to "
				"release",
			   FCP_VERSION, seq);
	  free (st->pme);
	  free (st->sop);
	  free (st->owner_ip);
	  free (st);
	  return 1;
	}
  else
	{
	  sprintf (reply, "FCP=%s SEQ=%i 200 OK", FCP_VERSION, seq);
	  free (st->pme);
	  free (st->sop);
	  free (st->owner_ip);
	  free (st);
	  return 0;
	}
}								/* release_action */

/* This funtion makes a copy of a state and turns every relevant values so
   that this new returned state is the reflexive copy of the given state. */
struct fcp_state *create_reflex (struct fcp_state *st)
{
  struct fcp_pme *reflex_pme;
  struct fcp_sop *reflex_sop;
  struct fcp_state *reflex_state;
  char *reflex_own;

  /* First allocate memory and make a copy of the state */
  reflex_pme = malloc (sizeof (struct fcp_pme));
  reflex_sop = malloc (sizeof (struct fcp_sop));
  reflex_state = malloc (sizeof (struct fcp_state));
  reflex_own = malloc (sizeof (st->owner_ip));

  memcpy (reflex_pme, st->pme, sizeof (struct fcp_pme));
  memcpy (reflex_sop, st->sop, sizeof (struct fcp_sop));
  memcpy (reflex_state, st, sizeof (struct fcp_state));
  strcpy (reflex_own, st->owner_ip);

  reflex_state->pme = reflex_pme;
  reflex_state->sop = reflex_sop;
  reflex_state->owner_ip = reflex_own;

  /* turn the direction of the copy */
  switch (st->direction)
	{
	case IN_OUT:
	  reflex_state->direction = OUT_IN;
	  break;
	case IN_DMZ:
	  reflex_state->direction = DMZ_IN;
	  break;
	case IN_LOOP:
	  reflex_state->direction = LOOP_IN;
	  break;
	case OUT_IN:
	  reflex_state->direction = IN_OUT;
	  break;
	case OUT_DMZ:
	  reflex_state->direction = DMZ_OUT;
	  break;
	case OUT_LOOP:
	  reflex_state->direction = LOOP_OUT;
	  break;
	case DMZ_IN:
	  reflex_state->direction = IN_DMZ;
	  break;
	case DMZ_OUT:
	  reflex_state->direction = OUT_DMZ;
	  break;
	case DMZ_LOOP:
	  reflex_state->direction = LOOP_DMZ;
	  break;
	case LOOP_IN:
	  reflex_state->direction = IN_LOOP;
	  break;
	case LOOP_OUT:
	  reflex_state->direction = OUT_LOOP;
	  break;
	case LOOP_DMZ:
	  reflex_state->direction = DMZ_LOOP;
	  break;
	default:
		break;
	}

  /* what is destination becomes source */
  reflex_state->pme->src_ip = st->pme->dst_ip;
  reflex_state->pme->src_ip_def = st->pme->dst_ip_def;
  reflex_state->pme->src_netmask = st->pme->dst_netmask;
  reflex_state->pme->src_netmask_def = st->pme->dst_netmask_def;
  reflex_state->pme->src_pt = st->pme->dst_pt;
  reflex_state->pme->src_pt_def = st->pme->dst_pt_def;
  reflex_state->pme->src_uppt = st->pme->dst_uppt;
  reflex_state->pme->src_uppt_def = st->pme->dst_uppt_def;

  /* and what is source becomes destination */
  reflex_state->pme->dst_ip = st->pme->src_ip;
  reflex_state->pme->dst_ip_def = st->pme->src_ip_def;
  reflex_state->pme->dst_netmask = st->pme->src_netmask;
  reflex_state->pme->dst_netmask_def = st->pme->src_netmask_def;
  reflex_state->pme->dst_pt = st->pme->src_pt;
  reflex_state->pme->dst_pt_def = st->pme->src_pt_def;
  reflex_state->pme->dst_uppt = st->pme->src_uppt;
  reflex_state->pme->dst_uppt_def = st->pme->src_uppt_def;

  /* turn the interfaces */
  reflex_state->pme->in_if = st->pme->out_if;
  reflex_state->pme->in_if_def = st->pme->out_if_def;
  reflex_state->pme->out_if = st->pme->in_if;
  reflex_state->pme->out_if_def = st->pme->in_if_def;

  /* *FIXME* What should we do with the syn_flag? Invert seems to be the
     right thing, because syn packets in both direction seem to be sensless. */
  return reflex_state;
}

/* takes name_value_list and produces rep(ly)
   it should fill the global-state list defined in main.h
   if not commented please take a look at the according error message */
int interpret (struct name_value *pairs, char **rep_input, char *owner)
{
  int res;
  unsigned int alarm_rem;

  char *rep, *rep_hlp, *rep_hlp2, **doublestar, *errstr;
  int ret, is_first;
  int src_ip, dst_ip;
  struct fcp_address_list *list;
  struct fcp_state *reflex_state;

  sprintf (debug_msg_helper, "INTERPRET: starting up");
  fcp_log (LOG_DEBUG, debug_msg_helper);

  rep = malloc (2000);
  api_error[0] = '\0';

  in_where = 0;
  req_type = 0;
  seq = 0;
  seq_isdef = 0;				/* SEQ=xx not set yet */
  src_ip = 0;
  dst_ip = 0;
  /* following are used to allow the optional parameters only once and at */
  /* the right place Ü */
  fcp_icmpmessage_allowed = 0;
  fcp_packetmodifier_allowed = 0;

  /* allocate and initialize memory */
  pme = malloc (sizeof (struct fcp_pme));
  memset (pme, 0, sizeof (struct fcp_pme));

  sop = malloc (sizeof (struct fcp_sop));
  memset (sop, 0, sizeof (struct fcp_sop));


  state = malloc (sizeof (struct fcp_state));
  memset (state, 0, sizeof (struct fcp_state));

  reserved = malloc (sizeof (struct fcp_reserved));
  memset (reserved, 0, sizeof (struct fcp_reserved));


  state->pme = pme;
  state->sop = sop;
  state->owner_ip = malloc (sizeof owner);
  strcpy (state->owner_ip, owner);

  /* check all name-value pairs */
  while (pairs->name != NULL)
	{
	  res = compare_to_defs (pairs->name);	/* retrieve type of token */

	  if (res)					/* res==0 -> token unknown */
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: token \"%s\", of type %i, has value: \"%s\"",
				   pairs->name, res, pairs->value);
		  fcp_log (LOG_DEBUG, debug_msg_helper);

		  if ((res > 5) && (pairs->value == NULL))
			{
			  sprintf (rep,
					   "FCP=%s SEQ=%i 402 Invalid Control State Field Value: "
						"Must specify value for %s",
					   FCP_VERSION, seq, token_names[res]);
			  *rep_input = rep;
			  FCP_FREE_MEM return 1;
			}

		  if ((res <= 5) && (pairs->value != NULL))
			{
			  sprintf (rep,
					   "FCP=%s SEQ=%i 402 Invalid Control State Field Value: "
						"Must not specify value for %s",
					   FCP_VERSION, seq, token_names[res]);
			  *rep_input = rep;
			  FCP_FREE_MEM return 1;
			}

		  switch (res)
			{
			case fcp_token_SET:;
			case fcp_token_RELEASE:;
			case fcp_token_QUERY:;
			case fcp_token_RELEASENAT:;
			case fcp_token_QUERYNAT:;
			  if (req_type)		/* error: req-type already set */
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s only allowed "
							"initially",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  req_type = res;	/* now we have a particular type */
			  break;
			case fcp_token_FCP:
			  if (in_where != fcp_nowhere)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must follow SET,"
							" RELEASE, QUERYNAT, RELEASENAT or QUERY",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  in_where = fcp_in_REQH;
			  if (strcmp (pairs->value, FCP_VERSION))
				{
				  sprintf (rep, "FCP=%s SEQ=%i 503 Version Not Supported: %s",
						   FCP_VERSION, seq, pairs->value);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				};
			  break;
			case fcp_token_TCPSYNALLOWED:;
			  /* handle parms only (distinct) in PME */
			case fcp_token_ICMPTYPE:;
			case fcp_token_ININTERFACE:;
			case fcp_token_OUTINTERFACE:
			  if (!((in_where == fcp_in_REQH) || (in_where == fcp_in_PME)))
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must not be "
							"specified outside PME",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  in_where = fcp_in_PME;
			  if (req_type != fcp_req_type_SET)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s may be only used"
							" in SET directive",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  switch (res)
				{
				case fcp_token_TCPSYNALLOWED:
				  if (!strcasecmp (pairs->value, "yes"))
					{
					  pme->syn_flg_def = 1;
					  pme->syn_flg = 1;
					  fcp_log (LOG_DEBUG, "INTERPRET: set <-y>");
					}
				  else if (!strcasecmp (pairs->value, "no"))
					{
					  pme->syn_flg_def = 1;
					  pme->syn_flg = 0;
					  fcp_log (LOG_DEBUG, "INTERPRET: set <! -y>");
					}
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s may only be"
								" set to yes or no",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					};
				  break;
				case fcp_token_ICMPTYPE:
					if ((ret = parse_icmp_type (pairs->value, &pme->icmp_type,
											&pme->icmp_code)) != 0)
					{
						if (ret == 1)
							pme->icmp_type_def = 1;
						if (ret == 2)
							pme->icmp_type_def = pme->icmp_code_def = 1;
					}
					else
					{
						sprintf (rep,
									"FCP=%s SEQ=%i 400 Bad Request: invalid %s "
									"specified",
									FCP_VERSION, seq, token_names[res]);
						*rep_input = rep;
						FCP_FREE_MEM return 1;
					}
				  break;
				case fcp_token_ININTERFACE:
				  pme->in_if_def = 1;
				  if (!strcmp (pairs->value, "in"))
					pme->in_if = FCP_INTERFACE_IN;
				  else if (!strcmp (pairs->value, "out"))
					pme->in_if = FCP_INTERFACE_OUT;
				  else if (!strcmp (pairs->value, "dmz"))
					pme->in_if = FCP_INTERFACE_DMZ;
				  else if (!strcmp (pairs->value, "loopback"))
					pme->in_if = FCP_INTERFACE_LOOPBACK;
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be in, "
								"out, dmz or loopback",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				  break;
				case fcp_token_OUTINTERFACE:
				  pme->out_if_def = 1;
				  if (!strcmp (pairs->value, "in"))
					pme->out_if = FCP_INTERFACE_IN;
				  else if (!strcmp (pairs->value, "out"))
					pme->out_if = FCP_INTERFACE_OUT;
				  else if (!strcmp (pairs->value, "dmz"))
					pme->out_if = FCP_INTERFACE_DMZ;
				  else if (!strcmp (pairs->value, "loopback"))
					pme->out_if = FCP_INTERFACE_LOOPBACK;
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be in, "
								"out, dmz or loopback",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				  break;
				}
			  break;

			  /* handle parms in PME and PMODF */

			case fcp_token_PROTO:
			  if (in_where == fcp_in_REQH)
				{
				  in_where = fcp_in_PME;
				}
			  if (in_where == fcp_in_PME)
				{
				  pme->proto_def = 1;
				  if (!strcmp (pairs->value, "1"))
					{
					  if (req_type == fcp_req_type_QUERYNAT)
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s=1 makes "
									"no sense in QUERYNAT",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					  pme->proto = 1;
					}
				  else if (!strcmp (pairs->value, "6"))
					pme->proto = 6;
				  else if (!strcmp (pairs->value, "17"))
					pme->proto = 17;
				  else if (!strcmp (pairs->value, "50"))
					pme->proto = 50;
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be 1, "
								"6, 17 or 50 (ICMP,TCP, UDP or IPSEC)",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				}
			  else if (in_where == fcp_in_NATADDS)
				{
				  pme->proto_def = 1;
				  if (!strcmp (pairs->value, "1"))
					{
					  if (req_type == fcp_req_type_QUERYNAT)
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s=1 makes "
									"no sense in QUERYNAT",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					  if (req_type == fcp_req_type_RELEASENAT)
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s=1 makes "
									"no sense in RELEASENAT",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					  reserved->proto = 1;
					}
				  else if (!strcmp (pairs->value, "6"))
					reserved->proto = 6;
				  else if (!strcmp (pairs->value, "17"))
					reserved->proto = 17;
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be 6 or"
								" 17 (TCP or UDP)",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s only allowed in "
							"PME or QUERYNAT statement",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_SRCIP:
			  if (req_type == fcp_req_type_QUERYNAT)
			  {
				  if ((in_where == fcp_in_NATADDS) ||
					  ((in_where == fcp_in_REQH) &&
					   ((req_type == fcp_req_type_QUERYNAT) ||
						(req_type == fcp_req_type_RELEASENAT))))
					{
					  in_where = fcp_in_NATADDS;
					  // pme->src_ip_def = 1;
					  if (!parse_ip_address
						  (pairs->value, &(reserved->origin_ip)))
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
									"type ip-adress",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					  if (parse_ip_netmask (pairs->value, &(pme->src_netmask)))
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
									"type ip-adress",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					}
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must only be "
								"specified in QUERYNAT or RELEASENAT statement",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
			  }
			  else
			  {
				  if (in_where == fcp_in_REQH)
					{
					  in_where = fcp_in_PME;
					}
				  if (in_where == fcp_in_PME)
					{
					  ret = parse_ip_netmask (pairs->value, &(pme->src_netmask));
					  if (ret == 1)
						{
						  pme->src_netmask_def = 1;
						}
					  if (ret == -1)
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
									"type ip-adress[/netmask]",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					  pme->src_ip_def = 1;
					  if (parse_ip_address (pairs->value, &(pme->src_ip)) == 0)
						{
						  sprintf (rep,
								   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
									"type ip-adress[/netmask]",
								   FCP_VERSION, seq, token_names[res]);
						  *rep_input = rep;
						  FCP_FREE_MEM return 1;
						}
					}
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
	                           "specified in PME",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
			  }
			  break;

			case fcp_token_DSTIP:
			  if (in_where == fcp_in_REQH)
				{
				  in_where = fcp_in_PME;
				}
			  if (in_where == fcp_in_PME)
				{
				  ret = parse_ip_netmask (pairs->value, &(pme->dst_netmask));
				  if (ret == 1)
					{
					  pme->dst_netmask_def = 1;
					}
				  if (ret == -1)
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
								"type ip-adress[/netmask]",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				  pme->dst_ip_def = 1;
				  if (parse_ip_address (pairs->value, &(pme->dst_ip)) == 0)
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
								"type ip-adress[/netmask]",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in PME",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_SRCPORT:
				if (req_type == fcp_req_type_QUERYNAT)
				{
					if (in_where == fcp_in_NATADDS)
					{
						if (!parse_tcp_ports
							(pairs->value, &(reserved->origin_port),
								&(reserved->origin_uppt)))
						{
							sprintf (rep,
									"FCP=%s SEQ=%i 400 Bad Request: %s is invalid",
									FCP_VERSION, seq, token_names[res]);
							*rep_input = rep;
							FCP_FREE_MEM
							return 1;
						}
					}
					else
					{
						if ((req_type != fcp_req_type_QUERYNAT) &&
							(req_type != fcp_req_type_RELEASENAT))
						{
							sprintf (rep,
										"FCP=%s SEQ=%i 400 Bad Request: %s must only be"
										" specified in QUERYNAT or RELEASENAT statement",
										FCP_VERSION, seq, token_names[res]);
							*rep_input = rep;
							FCP_FREE_MEM
							return 1;
						}
						else
						{
							sprintf (rep,
									"FCP=%s SEQ=%i 400 Bad Request: %s must follow IP",
									FCP_VERSION, seq, token_names[res]);
							*rep_input = rep;
							FCP_FREE_MEM
							return 1;
						}
					}
				}
				else
				{
					if (in_where == fcp_in_REQH)
					{
						in_where = fcp_in_PME;
					}
					if (in_where == fcp_in_PME)
					{
						pme->src_pt_def = 1;
						if (!parse_tcp_ports
							(pairs->value, &(pme->src_pt), &(pme->src_uppt)))
						{
							sprintf (rep,
									"FCP=%s SEQ=%i 400 Bad Request: %s must be of "
									"type <port> | <port-range>",
									FCP_VERSION, seq, token_names[res]);
							*rep_input = rep;
							FCP_FREE_MEM
							return 1;
						}
						else
						{
							if (pme->src_pt != pme->src_uppt)
								pme->src_uppt_def = 1;
						}
					}
					else
					{
						sprintf (rep,
								"FCP=%s SEQ=%i 400 Bad Request: %s must be specified in PME",
								FCP_VERSION, seq, token_names[res]);
						*rep_input = rep;
						FCP_FREE_MEM
						return 1;
					}
				}
				break;

			case fcp_token_DSTPORT:
			  if (in_where == fcp_in_REQH)
				{
				  in_where = fcp_in_PME;
				}
			  if (in_where == fcp_in_PME)
				{
				  pme->dst_pt_def = 1;
				  if (!parse_tcp_ports
					  (pairs->value, &(pme->dst_pt), &(pme->dst_uppt)))
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be of "
								"type <port> | <port-range>",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				  else
					{
					  if (pme->dst_pt != pme->dst_uppt)
						pme->dst_uppt_def = 1;
					}
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in PME",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_TOSFLD:
			  if (in_where == fcp_in_REQH)
				{
				  in_where = fcp_in_PME;
				}
			  if (in_where == fcp_in_PME)
				{
				  pme->tos_fld_def = 1;
				  pme->tos_fld = atoi (pairs->value);
				  if ((pme->tos_fld < 0) || (pme->tos_fld > 255))
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be 0 .."
								" 255",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				}
			  else
				if ((in_where == fcp_in_PCKMODF) ||
					((in_where == fcp_in_SETOPTS)
					 && (fcp_packetmodifier_allowed)))
				{
				  in_where = fcp_in_PCKMODF;
				  fcp_packetmodifier_allowed = 0;
				  sop->packet_modf.tos_fld_def = 1;
				  sprintf (debug_msg_helper, "INTERPRET: tosfld success");
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  sop->packet_modf.tos_fld = atoi (pairs->value);

				  sprintf (debug_msg_helper, "INTERPRET: tosfld success");
				  fcp_log (LOG_DEBUG, debug_msg_helper);

				  if ((sop->packet_modf.tos_fld < 0)
					  || (sop->packet_modf.tos_fld > 255))
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must be 0 .."
								" 255",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM return 1;
					}
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in PME or PacketModifier",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;


			case fcp_token_ACTION:
			  if ((in_where == fcp_in_REQH) || (in_where == fcp_in_PME))
				{
				  in_where = fcp_in_SETOPTS;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in SetOptions",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  if (req_type != fcp_req_type_SET)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s is not allowed "
							"with RELEASE or QUERY",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  sop->action_def = 1;
			  if (!strcasecmp (pairs->value, "pass"))
				{
				  sop->action = fcp_action_pass;
				  fcp_packetmodifier_allowed = 1;
				  fcp_icmpmessage_allowed = 0;
				}
			  else if (!strcasecmp (pairs->value, "drop"))
				{
				  sop->action = fcp_action_drop;
				  fcp_icmpmessage_allowed = 0;
				  fcp_packetmodifier_allowed = 0;
				}
			  else if (!strcasecmp (pairs->value, "reject"))
				{
				  sop->action = fcp_action_reject;
				  fcp_icmpmessage_allowed = 1;
				  fcp_packetmodifier_allowed = 0;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be drop, "
							"pass or reject",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_ICMPMESSAGE:
			  if ((in_where == fcp_in_SETOPTS) && (fcp_icmpmessage_allowed))
				{
				  fcp_icmpmessage_allowed = 0;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified after ACTION=reject",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
				if ((ret = parse_icmp_type (pairs->value, &sop->icmp_msg,
										&sop->icmp_msg_code)) != 0)
				{
					if (ret == 1)
						sop->icmp_msg_def = 1;
					if (ret == 2)
						sop->icmp_msg_def = sop->icmp_msg_code_def = 1;
				}
				else
				{
					sprintf (rep,
								"FCP=%s SEQ=%i 400 Bad Request: invalid %s "
								"specified",
								FCP_VERSION, seq, token_names[res]);
					*rep_input = rep;
					FCP_FREE_MEM return 1;
				}
				break;

			case fcp_token_TIMER:
			  if ((in_where == fcp_in_SETOPTS) || (in_where == fcp_in_PCKMODF)
				  || (in_where == fcp_in_PME))
				{
				  fcp_icmpmessage_allowed = 0;
				  fcp_packetmodifier_allowed = 0;
				  in_where = fcp_in_SETOPTS;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in SetOptions",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  if (req_type != fcp_req_type_SET)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s is not allowed "
							"with RELEASE or QUERY",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  sop->timer_def = 1;
			  sop->timer = atoi (pairs->value);
			  if ((sop->timer < 0) || (sop->timer > 1000000))
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be 1 .. "
							"1000000 seconds",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_REFLEXIVE:
			  if ((in_where == fcp_in_SETOPTS)
				  || (in_where == fcp_in_PCKMODF))
				{
				  fcp_icmpmessage_allowed = 0;
				  fcp_packetmodifier_allowed = 0;
				  in_where = fcp_in_SETOPTS;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in SetOptions",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  sop->reflexive_def = 1;
			  if (!strcasecmp (pairs->value, "yes"))
				{
				  sop->reflexive = 1;
				}
			  else if (!strcasecmp (pairs->value, "no"))
				{
				  sop->reflexive = 0;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s may only be set "
							"to yes or no",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				};
			  break;

			case fcp_token_PRIORITYCLASS:
			  if ((in_where == fcp_in_SETOPTS)
				  || (in_where == fcp_in_PCKMODF))
				{
				  fcp_icmpmessage_allowed = 0;
				  fcp_packetmodifier_allowed = 0;
				  in_where = fcp_in_SETOPTS;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in SetOptions",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  sop->pri_class_def = 1;
			  sop->pri_class = atoi (pairs->value);
			  if ((sop->pri_class < 1)
				  || (sop->pri_class > FCP_MAX_PRIORITY_CLASSES))
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be in range"
							" 1 .. %u",
						   FCP_VERSION, seq, token_names[res],
						   FCP_MAX_PRIORITY_CLASSES);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_LOG:
			  if ((in_where == fcp_in_SETOPTS)
				  || (in_where == fcp_in_PCKMODF))
				{
				  fcp_icmpmessage_allowed = 0;
				  fcp_packetmodifier_allowed = 0;
				  in_where = fcp_in_SETOPTS;
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be "
							"specified in SetOptions",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  sop->log_def = 1;
			  sop->log = atoi (pairs->value);
			  if ((sop->log < 1) || (sop->log > FCP_MAX_LOG_CLASSES))
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must be in range"
							" from 1 to %i",
						   FCP_VERSION, seq, token_names[res],
						   FCP_MAX_LOG_CLASSES);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;

			case fcp_token_IP:
				sprintf (rep,
					   "FCP=%s SEQ=%i 400 Bad Request: %s is obsolete use %s instead",
					   FCP_VERSION, seq, token_names[res], token_names[11]);
				*rep_input = rep;
				FCP_FREE_MEM
				return 1;
			  break;

			case fcp_token_PORT:
				sprintf (rep,
								"FCP=%s SEQ=%i 400 Bad Request: %s is obsolete use %s instead",
								FCP_VERSION, seq, token_names[res], token_names[13]);
				*rep_input = rep;
				FCP_FREE_MEM
				return 1;
			  break;

			case fcp_token_UPPERPORT:
			  if (in_where == fcp_in_NATADDS)
				{
				  if (!parse_tcp_ports
					  (pairs->value, &(reserved->origin_uppt),
					   &(reserved->origin_uppt)))
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s is invalid",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM
					  return 1;
					}
				}
			  else
				{
				  if ((req_type != fcp_req_type_QUERYNAT) &&
					  (req_type != fcp_req_type_RELEASENAT))
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must only be"
								" specified in QUERYNAT or RELEASENAT statement",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM
					  return 1;
					}
				  else
					{
					  sprintf (rep,
							   "FCP=%s SEQ=%i 400 Bad Request: %s must follow"
								" PORT",
							   FCP_VERSION, seq, token_names[res]);
					  *rep_input = rep;
					  FCP_FREE_MEM
					  return 1;
					}

				}
			  break;

			case fcp_token_SEQ:
			  if (in_where != fcp_in_REQH)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s must follow FCP",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  if (seq_isdef != 0)
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: doublicate %s",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  seq_isdef = 1;
			  seq = atoi (pairs->value);
			  if (seq == -1)
				{
				  seq = 0;
				  sprintf (rep,
						   "FCP=%s SEQ=%i 400 Bad Request: %s value needs to "
							"be integer < 999999999",
						   FCP_VERSION, seq, token_names[res]);
				  *rep_input = rep;
				  FCP_FREE_MEM return 1;
				}
			  break;




			default:
			  /* this should _never_ happen ! */
			  sprintf (debug_msg_helper,
					   "Warning: INTERPRET: default for item \"%s\"",
					   token_names[res]);
			  fcp_log (LOG_CRIT, debug_msg_helper);
			  sprintf (rep,
					   "FCP=%s SEQ=%i 400 Bad Request: internal error near %s"
						" - unknown token",
					   FCP_VERSION, seq, token_names[res]);
			  *rep_input = rep;
			  FCP_FREE_MEM
			  return 1;

			  break;
			}

		  if (!req_type)		/* no SET, RELEASE,... at beginning */
			{
			  sprintf (rep,
					   "FCP=%s SEQ=%i 400 Bad Request: %s not allowed "
						"initially",
					   FCP_VERSION, seq, token_names[res]);
			  *rep_input = rep;
			  FCP_FREE_MEM
			  return 1;
			}
		}
	  else
		{
		  sprintf (debug_msg_helper, "INTERPRET: unknown token: \"%s\"",
				   pairs->name);
		  fcp_log (LOG_ERR, debug_msg_helper);

		  sprintf (rep, "FCP=%s SEQ=%i 400 Bad Request: unknown token \"%s\"",
				   FCP_VERSION, seq, pairs->name);

		  sprintf (debug_msg_helper, "INTERPRET: exiting");
		  fcp_log (LOG_DEBUG, debug_msg_helper);
		  *rep_input = rep;
		  FCP_FREE_MEM
		  return 1;
		}
	  pairs = pairs->next;
	}


  /* validity and priority class check */
  sprintf (debug_msg_helper, "INTERPRET: checking request for validity");
  fcp_log (LOG_DEBUG, debug_msg_helper);
  errstr = malloc (255);
  if (check_validity (state, errstr) == 1)
	{
	  sprintf (debug_msg_helper,
			   "INTERPRET: validity check failed - reason: %s", errstr);
	  fcp_log (LOG_ERR, debug_msg_helper);
	  sprintf (rep, "FCP=%s SEQ=%i %s", FCP_VERSION, seq, errstr);
	  *rep_input = rep;
	  FCP_FREE_MEM
	  free (errstr);
	  return 1;
	}
  free (errstr);

  /* direction detection and "NOT MY ROUTE" check */
  fcp_log (LOG_DEBUG, "INTERPRET: try to detect the direction");
  /* Only if both IPs are defined we can determine the direction */
  if (state->pme->src_ip_def && state->pme->dst_ip_def)
	{
	  /* First check if source or destination is one of the IPs of this host
	     or loopback. */
	  if (state->pme->src_ip == fcp_internal_IP ||
		  state->pme->src_ip == fcp_outer_IP ||
		  state->pme->src_ip == fcp_demilitary_IP ||
		  state->pme->src_ip == 0x7F000001)
		src_ip = 1;
	  if (state->pme->dst_ip == fcp_internal_IP ||
		  state->pme->dst_ip == fcp_outer_IP ||
		  state->pme->dst_ip == fcp_demilitary_IP ||
		  state->pme->dst_ip == 0x7F000001)
		dst_ip = 1;
	  /* If one of the IPs are not set to 1 search them in the list of
	     internal IPs */
	  if (!src_ip || !dst_ip)
		{
		  list = fcp_internal_ips.next;
		  while (list)
			{
			  if (ip_is_in_tuple
				  (list->address, list->netmask, state->pme->src_ip))
				src_ip = 2;
			  if (ip_is_in_tuple
				  (list->address, list->netmask, state->pme->dst_ip))
				dst_ip = 2;
			  list = list->next;
			}
		  /* If we have a list of IPs of the DMZ and one of the IPs is not
		     found until yet we search them in this list */
		  if (fcp_dmz_ips.next && (!src_ip || !dst_ip))
			{
			  list = fcp_dmz_ips.next;
			  while (list)
				{
				  if (ip_is_in_tuple
					  (list->address, list->netmask, state->pme->src_ip))
					src_ip = 3;
				  if (ip_is_in_tuple
					  (list->address, list->netmask, state->pme->dst_ip))
					dst_ip = 3;
				  list = list->next;
				}
			}
		}
	  /* If both IPs are in the same network the route won't go through our
	     host so we return that the request is Okay but we don't make an API
	     call. *FIXME* What should we do if both IPs are locale? This goes
	     through our host but why? */
	  if (src_ip == dst_ip)
		{
		  /* *FIXME* Should we insert this state in our lists? If we don't
		     do, we will end up in an error if the client try's to delete
		     this this rule. (Maybe he will try this because we returned an
		     2xx code which means Okay.) If we do, we should insert it in the
		     time list, so that the state won't stay forever in our server.
		     But then we have to handle this at an alarm extra because we
		     shouldn't make an API call for this state. */
		  sprintf (rep,
				   "FCP=%s SEQ=%i 203 Not My Route: source and destination IP"
					" are in the same network",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  return 0;
		}
	  /* The requested route will go through us, so determine it's direction */
	  else
		{
		  /* If we don't found the source in our lists so the route goes from
		     OUT to anywhere */
		  if (src_ip == 0)
			{
			  if (dst_ip == 1)
				state->direction = OUT_LOOP;
			  else if (dst_ip == 2)
				state->direction = OUT_IN;
			  else
				state->direction = OUT_DMZ;
			}
		  /* If the source is one of our IPs the route goes from LOOP to
		     anywhere */
		  else if (src_ip == 1)
			{
			  if (dst_ip == 0)
				state->direction = LOOP_OUT;
			  else if (dst_ip == 2)
				state->direction = LOOP_IN;
			  else
				state->direction = LOOP_DMZ;
			}
		  /* If the source is internal the route goes from IN to anywhere */
		  else if (src_ip == 2)
			{
			  if (dst_ip == 0)
				state->direction = IN_OUT;
			  else if (dst_ip == 1)
				state->direction = IN_LOOP;
			  else
				state->direction = IN_DMZ;
			}
		  /* Nothing left then the route goes from DMZ to anywhere */
		  else
			{
			  if (dst_ip == 0)
				state->direction = DMZ_OUT;
			  else if (dst_ip == 1)
				state->direction = DMZ_LOOP;
			  else
				state->direction = DMZ_IN;
			}
		}
	}
  /* We don't have both IPs so we set the direction to NOT_SET */
  else
	state->direction = NOT_SET;

  /* Everything should be interpreted here, now we execute what we got. */

  if (req_type == fcp_req_type_QUERYNAT)
	{
	  struct fcp_address_list *masq_list;
	  int found = 0;

	  errstr = malloc (255);
	  sprintf (debug_msg_helper, "INTERPRET: processing QUERYNAT command");
	  fcp_log (LOG_INFO, debug_msg_helper);

	  sprintf (debug_msg_helper,
			   "INTERPRET: QUERYNAT: IP: %i Port: %i Uppt: %i",
			   reserved->origin_ip, reserved->origin_port,
			   reserved->origin_uppt);
	  fcp_log (LOG_DEBUG, debug_msg_helper);

	  if (reserved->origin_ip == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: IP must be specified in QUERYNAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: IP must be specified in "
					"QUERYNAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}
	  if (reserved->origin_port == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: PORT must be specified in QUERYNAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: PORT must be specified in "
					"QUERYNAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}

	  if (reserved->proto == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: PROTO must be specified in QUERYNAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: PROTO must be specified in "
					"QUERYNAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}

	  reservations = reserved_list_base;

	  while (reservations->next != NULL)
		{
		  reservations = reservations->next;

		  if ((reservations->res->origin_ip == reserved->origin_ip)	/* already
														   reserved? */
			  && (reservations->res->origin_port == reserved->origin_port))
			{

			  sprintf (debug_msg_helper,
					   "INTERPRET: IP/PORT already reserved, returning "
						"reservation anyway");
			  fcp_log (LOG_INFO, debug_msg_helper);

			  doublestar = malloc (sizeof (char *));

			  ip2str (reserved->masq_ip, doublestar);

				if (reserved->origin_uppt == reserved->origin_port)
				{
				  sprintf (rep, "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i",
						   FCP_VERSION, seq, *doublestar,
						   reserved->masq_port);
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i-%i",
						   FCP_VERSION, seq, *doublestar, reserved->masq_port,
						   reserved->masq_uppt);
				}
			  free (*doublestar);
			  free (doublestar);
			  *rep_input = rep;
			  FCP_FREE_MEM free (errstr);
			  return 0;
			}
		}

	  /* Look in the list of networks which we have to masquerade if the IP
	     of this request have to be masqueraded. */
	  masq_list = fcp_masq_ips.next;
	  while (masq_list && !found)
		{
		  found =
			ip_is_in_tuple (masq_list->address, masq_list->netmask,
							reserved->origin_ip);
		  masq_list = masq_list->next;
		}

	  if (found)
		{
		  fcp_log (LOG_DEBUG,
				   "INTERPRET: IP in request have to be masqueraded");
		  /* API call */
		  if (!fcp_port_request (reserved, errstr))
			{
			  sprintf (debug_msg_helper,
					   "INTERPRET: fcp_port_request API call failed - "
						"Reason: %s",
					   errstr);
			  fcp_log (LOG_ERR, debug_msg_helper);
			  sprintf (rep, "FCP=%s SEQ=%i %s", FCP_VERSION, seq, errstr);
			  *rep_input = rep;
			  FCP_FREE_MEM free (errstr);
			  return 1;
			}
		  else
			{
			  sprintf (debug_msg_helper,
					   "INTERPRET: succesfully reserved IP=%i Port=%i-%i "
						"for origin IP=%i Port=%i-%i",
					   reserved->masq_ip, reserved->masq_port,
					   reserved->masq_uppt, reserved->origin_ip,
					   reserved->origin_port, reserved->origin_uppt);
			  fcp_log (LOG_ERR, debug_msg_helper);

			  doublestar = malloc (sizeof (char *));

			  ip2str (reserved->masq_ip, doublestar);

			  if (reserved->origin_uppt == reserved->origin_port)
				{
				  sprintf (rep, "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i",
						   FCP_VERSION, seq, *doublestar,
						   reserved->masq_port);
				}
			  else
				{
				  sprintf (rep,
						   "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i-%i",
						   FCP_VERSION, seq, *doublestar, reserved->masq_port,
						   reserved->masq_uppt);
				}
			  free (*doublestar);
			  free (doublestar);

			  /* insert rule into both lists */

			  reservations = reserved_list_base;

			  /* *FIXME* If it's really neccesary to insert it at the end of
			     the list? Why can't we insert it as the first element of the
			     list? */
			  while (reservations->next != NULL)	/* go to the end of the
													   list */
				{
				  reservations = reservations->next;
				}

			  reservations->next = malloc (sizeof (struct reserved_list));

			  reservations->next->res = reserved;	/* insert item as last in
													   the list */
			  reservations->next->next = NULL;
			  reservations->next->prev = reservations;
			  reservations->next->my_state = NULL;

			  states = malloc (sizeof (struct state_list));
			  states->res = reservations->next;
			  states->next = NULL;
			  states->prev = NULL;
			  states->state = NULL;

			  reservations->next->res_state = states;

			  alarm_rem = alarm (0);
			  sprintf (debug_msg_helper, "INTERPRET: %u left to next alarm",
					   alarm_rem);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  if (state_list_base->time_next)
				state_list_base->time_next->distance_ttl = alarm_rem;

			  time_list_insert (states, FCP_NATQUERY_TIMEOUT);

			  if (state_list_base->time_next != NULL)
				{
				  alarm (state_list_base->time_next->distance_ttl);
				  sprintf (debug_msg_helper, "INTERPRET: alarm set to %i",
						   state_list_base->time_next->distance_ttl);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				}

			  *rep_input = rep;
			  fcp_log (LOG_DEBUG, "INTERPRET: exiting");
			  free (pme);
			  free (sop);
			  free (state->owner_ip);
			  free (state);
			  free (errstr);
			  return 0;
			}					/* end fcp_port_request */
		}
	  else
		{
		  /* We don't have to masquerade so just return the IP and ports
		     which we get in the request. *FIXME* Should we insert a
		     reservation for this request? Only if we do this, we can find a
		     reservation for the according SET request... */
		  fcp_log (LOG_DEBUG,
				   "INTERPRET: IP in request don't have to be masqueraded");
		  doublestar = malloc (sizeof (char *));
		  ip2str (reserved->origin_ip, doublestar);
		  if (reserved->origin_uppt == 0)
			sprintf (rep, "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i", FCP_VERSION,
					 seq, *doublestar, reserved->origin_port);
		  else
			sprintf (rep, "FCP=%s SEQ=%i 200 OK\nIP=%s PORT=%i-%i",
					 FCP_VERSION, seq, *doublestar, reserved->origin_port,
					 reserved->origin_uppt);
		  free (*doublestar);
		  free (doublestar);
		  *rep_input = rep;
		  fcp_log (LOG_DEBUG, "INTERPRET: exiting");
		  return 0;
		}
	}							/* end QUERY_NAT */


  if (req_type == fcp_req_type_RELEASENAT)
	{
	  errstr = malloc (255);
	  sprintf (debug_msg_helper, "INTERPRET: processing RELEASENAT command");
	  fcp_log (LOG_INFO, debug_msg_helper);

	  sprintf (debug_msg_helper,
			   "INTERPRET: RELEASENAT: IP: %i Port: %i Uppt: %i",
			   reserved->origin_ip, reserved->origin_port,
			   reserved->origin_uppt);
	  fcp_log (LOG_DEBUG, debug_msg_helper);

	  if (reserved->origin_ip == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: IP must be specified in RELEASENAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: IP must be specified in "
					"RELEASENAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}
	  if (reserved->origin_port == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: PORT must be specified in RELEASENAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: PORT must be specified in "
					"RELEASENAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}

	  if (reserved->proto == 0)
		{
		  sprintf (debug_msg_helper,
				   "INTERPRET: PROTO must be specified in RELEASENAT");
		  fcp_log (LOG_ERR, debug_msg_helper);
		  sprintf (rep,
				   "FCP=%s SEQ=%i 400 Bad Request: PROTO must be specified in "
					"RELEASENAT statement",
				   FCP_VERSION, seq);
		  *rep_input = rep;
		  FCP_FREE_MEM free (errstr);
		  return 1;
		}

	  reservations = reserved_list_base;

	  while (reservations->next != NULL)
		{
		  reservations = reservations->next;

		  if ((reservations->res->origin_ip == reserved->origin_ip)	/* already
																	   reserved?
																	 */
			  && (reservations->res->origin_port == reserved->origin_port)
			  && (reservations->res->proto == reserved->proto))
			{

			  sprintf (debug_msg_helper,
					   "INTERPRET: found matching NAT reservation");
			  fcp_log (LOG_INFO, debug_msg_helper);

			  if (!fcp_port_release (reservations->res, errstr))
				{
				  sprintf (debug_msg_helper,
						   "INTERPRET: fcp_port_release API call failed - "
							"Reason: %s",
						   errstr);
				  fcp_log (LOG_ERR, debug_msg_helper);
				  sprintf (rep, "FCP=%s SEQ=%i %s", FCP_VERSION, seq, errstr);
				  *rep_input = rep;
				  FCP_FREE_MEM free (errstr);
				  return 1;
				}
			  else
				{
				  sprintf (debug_msg_helper,
						   "INTERPRET: succesfully released IP=%i Port=%i-"
							"%i for origin IP=%i Port=%i-%i",
						   reservations->res->masq_ip,
						   reservations->res->masq_port,
						   reservations->res->masq_uppt, reserved->origin_ip,
						   reserved->origin_port, reserved->origin_uppt);
				  fcp_log (LOG_ERR, debug_msg_helper);

				  /* remove reservation from both lists */

				  reservations->prev->next = reservations->next;
				  if (reservations->next != NULL)
					reservations->next->prev = reservations->prev;

				  states = state_list_base;
				  while (states->time_next != NULL)
					{
					  if (states->time_next->res == reservations)
						states_helper = states->time_next;
					  states = states->time_next;
					}

				  time_list_remove (states_helper);
				  free (states_helper);

				  free (reservations->res);
				  free (reservations);

				  alarm_rem = alarm (0);
				  sprintf (debug_msg_helper,
						   "INTERPRET: %u left to next alarm", alarm_rem);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  if (state_list_base->time_next)
					state_list_base->time_next->distance_ttl = alarm_rem;

				  if (state_list_base->time_next != NULL)
					{
					  alarm (state_list_base->time_next->distance_ttl);
					  sprintf (debug_msg_helper, "INTERPRET: alarm set to %i",
							   state_list_base->time_next->distance_ttl);
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					}

				  sprintf (rep, "FCP=%s SEQ=%i 200 OK", FCP_VERSION, seq);
				  *rep_input = rep;
				  fcp_log (LOG_DEBUG, "INTERPRET: exiting");
				  free (pme);
				  free (sop);
				  free (state->owner_ip);
				  free (state);
				  free (errstr);
				  free (reserved);
				  return ret;
				}
			}
		}
	  sprintf (debug_msg_helper, "INTERPRET: no matching reservation foung");
	  fcp_log (LOG_ERR, debug_msg_helper);
	  sprintf (rep, "FCP=%s SEQ=%i 400 Bad Request: No such NAT reservation",
			   FCP_VERSION, seq);
	  *rep_input = rep;
	  FCP_FREE_MEM free (errstr);
	  return 1;

	}

  if (req_type == fcp_req_type_QUERY)
	{

	  sprintf (debug_msg_helper, "INTERPRET: processing QUERY command");
	  fcp_log (LOG_INFO, debug_msg_helper);

	  /* might need more space for reply than 2000: */
	  // free (rep);
	  // rep = (char *) malloc (20000);
	  rep_hlp = malloc (255);

	  sprintf (rep, "FCP=%s SEQ=%i 200 OK\n", FCP_VERSION, seq);
	  is_first = 1;

	  states = state_list_base;
	  while (states->next != NULL)
		{
		  states = states->next;
		  if (compare_pme (pme, states->state->pme, 1))	/* hit! */
			{
			  sprintf (debug_msg_helper,
					   "INTERPRET: found matching rule -> QUERYRESPONSE");
			  fcp_log (LOG_INFO, debug_msg_helper);

			  if (!is_first)
				{
				  sprintf (rep_hlp, ";\n");
				  rep = strcat (rep, rep_hlp);
				}
			  else
				is_first = 0;

			  if (states->state->pme->proto_def)
				{
				  sprintf (rep_hlp, "PROTO=%i ", states->state->pme->proto);
				  rep = strcat (rep, rep_hlp);
				}
			  if (states->state->pme->src_ip_def)
				{
				  doublestar = malloc (sizeof (char *));

				  ip2str (states->state->pme->src_ip, doublestar);
				  sprintf (rep_hlp, "SRCIP=%s", *doublestar);
				  rep = strcat (rep, rep_hlp);
				  if (states->state->pme->src_netmask_def)
					{
					  ip2str (states->state->pme->src_netmask, doublestar);
					  sprintf (rep_hlp, "/%s ", *doublestar);
					}
				  else
					sprintf (rep_hlp, " ");
				  rep = strcat (rep, rep_hlp);
				  free (*doublestar);
				  free (doublestar);
				}
			  if (states->state->pme->dst_ip_def)
				{
				  doublestar = malloc (sizeof (char *));
				  ip2str (states->state->pme->dst_ip, doublestar);
				  sprintf (rep_hlp, "DSTIP=%s", *doublestar);
				  rep = strcat (rep, rep_hlp);
				  if (states->state->pme->dst_netmask_def)
					{
					  ip2str (states->state->pme->dst_netmask, doublestar);
					  sprintf (rep_hlp, "/%s ", *doublestar);
					}
				  else
					sprintf (rep_hlp, " ");
				  rep = strcat (rep, rep_hlp);
				  free (*doublestar);
				  free (doublestar);
				}
			  if (states->state->pme->src_pt_def)
				{
				  if (states->state->pme->src_uppt_def)
					{
					  sprintf (rep_hlp, "SRCPORT=%i-%i ",
							   states->state->pme->src_pt,
							   states->state->pme->src_uppt);
					  rep = strcat (rep, rep_hlp);
					}
				  else
					{
					  sprintf (rep_hlp, "SRCPORT=%i ",
							   states->state->pme->src_pt);
					  rep = strcat (rep, rep_hlp);
					}
				}

			  if (states->state->pme->dst_pt_def)
				{
				  if (states->state->pme->dst_uppt_def)
					{
					  sprintf (rep_hlp, "DSTPORT=%i-%i ",
							   states->state->pme->dst_pt,
							   states->state->pme->dst_uppt);
					  rep = strcat (rep, rep_hlp);
					}
				  else
					{
					  sprintf (rep_hlp, "DSTPORT=%i ",
							   states->state->pme->dst_pt);
					  rep = strcat (rep, rep_hlp);
					}
				}
			  if (states->state->pme->tos_fld_def)
				{
				  sprintf (rep_hlp, "TOSFLD=%i ",
						   states->state->pme->tos_fld);
				  rep = strcat (rep, rep_hlp);
				}
			  if (states->state->pme->syn_flg_def)
				{
				  rep_hlp2 = malloc (6);
				  switch (states->state->pme->syn_flg)
					{
					case 1:
					  sprintf (rep_hlp2, "YES");
					  break;
					case 0:
					  sprintf (rep_hlp2, "NO");
					  break;
					}
				  sprintf (rep_hlp, "TCPSYNALLOWED=%s ", rep_hlp2);
				  free (rep_hlp2);
				  rep = strcat (rep, rep_hlp);
				}
			  if (states->state->pme->icmp_type_def)
				{
				  sprintf (rep_hlp, "ICMPTYPE=%i ",
						   states->state->pme->icmp_type);
				  rep = strcat (rep, rep_hlp);
				}
			  if (states->state->sop->action_def)
				{
				  rep_hlp2 = malloc (10);
				  switch (states->state->sop->action)
					{
					case fcp_action_pass:
					  sprintf (rep_hlp2, "PASS");
					  break;
					case fcp_action_drop:
					  sprintf (rep_hlp2, "DROP");
					  break;
					case fcp_action_reject:
					  sprintf (rep_hlp2, "REJECT");
					  break;
					}
				  sprintf (rep_hlp, "ACTION=%s ", rep_hlp2);
				  free (rep_hlp2);
				  rep = strcat (rep, rep_hlp);
				}
			  if (states->state->sop->timer_def)
				{
				  sprintf (rep_hlp, "TIMER=%i ", states->state->sop->timer);
				  rep = strcat (rep, rep_hlp);
				}

			}
		}
	  sprintf (rep_hlp, "\n");
	  rep = strcat (rep, rep_hlp);

	  *rep_input = rep;
	  FCP_FREE_MEM free (rep_hlp);
	  return 0;
	}


  if (req_type == fcp_req_type_SET)
	{
	  /* If reflexive is requested first insert the normal rule, then make a
	     reflexive copy and insert this also. */
	  if (state->sop->reflexive == 1)
		{
			reflex_state = create_reflex (state);
		  ret = set_action (state, rep);
		  if (ret == 0)
			{
			  ret = set_action (reflex_state, rep);
			}
			else
			{
				free (reflex_state->pme);
				free (reflex_state->sop);
				free (reflex_state->owner_ip);
				free (reflex_state);
			}
		}
	  /* no reflexive so just a normal insert */
	  else
		{
		  ret = set_action (state, rep);
		}
	  free (reserved);
	}							/* SET */

  if (req_type == fcp_req_type_RELEASE)
	{
	  /* We have to make reflexive copy before removing, because removing is
	     so complete that the memory of the state is freeed. */
	  reflex_state = create_reflex (state);
	  res = 0;
	  ret = release_action (state, rep, owner, &res);
	  /* Because reflexive isn't element of the PME and so not included in a
	     release request the release_action function returns if their should
	     exist another reflexive rule which we should remove. */
	  if (res == 1)
		{
		  ret = release_action (reflex_state, rep, owner, &res);
		}
	  /* If not reflexive we only free the memory of the reflexive copy. */
	  else
		{
		  free (reflex_state->pme);
		  free (reflex_state->sop);
		  free (reflex_state->owner_ip);
		  free (reflex_state);
		}
	  free (reserved);
	}							/* RELEASE */

  *rep_input = rep;
  fcp_log (LOG_DEBUG, "INTERPRET: exiting");

  /* no errors, all tokens known and request ok */
  return ret;	
};
