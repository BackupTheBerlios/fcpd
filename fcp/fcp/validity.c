/***************************************************************************
                          validity.c
                             -------------------
    begin                : Sun Jan 21 2001
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

#include "validity.h"
#include "debug.h"

/* this function take a state which has been interpreted and checks for */
/* inconsistencies.  */
/* return value of 0 means validity - 1 means error */
/* in case of error: repl contains the reply with the error message */
int check_validity (struct fcp_state *st, char *repl)
{
  if (st->pme->icmp_type_def && (st->pme->proto == 6 || st->pme->proto == 17))
	{
	  sprintf (repl,
			   "400 Bad Request: ICMPTYPE only makes sence with PROTO=1");
	  return 1;
	}
  if (!st->pme->proto_def && (st->pme->src_pt_def || st->pme->dst_pt_def))
	{
	  sprintf (repl,
			   "400 Bad Request: SRCPORT or DSTPORT only makes sence with "
               "PROTO=6 or 17");
	  return 1;
	}
  if (st->pme->proto == 1 && (st->pme->src_pt_def || st->pme->dst_pt_def))
	{
	  sprintf (repl,
			   "400 Bad Request: SRCPORT or DSTPORT only makes sence with "
               "PROTO=6 or 17");
	  return 1;
	}
  if (st->pme->in_if_def && st->pme->out_if_def
	  && st->pme->in_if == st->pme->out_if)
	{
	  sprintf (repl,
			   "400 Bad Request: same in and out interface doesn't make"
               " sence");
	  return 1;
	}

  /* Priority Class check */
  if (st->sop->pri_class_def)
	{
	  /* Check for a correct number as priority class is made at the
	     interpreter above. */
	  fcp_log (LOG_DEBUG, "INTERPRET: priority class check");
	  if (rules_per_priority_class[st->sop->pri_class] == 0)
		{
		  priority_class_action[st->sop->pri_class] = st->sop->action;
		  sprintf (debug_msg_helper,
				   "INTERPRET: action of priority class %i set to %i",
				   st->sop->pri_class, st->sop->action);
		  fcp_log (LOG_DEBUG, debug_msg_helper);
		}
	  else
		{
		  if (priority_class_action[st->sop->pri_class] != st->sop->action)
			{
			  fcp_log (LOG_DEBUG, "INTERPRET: priority class conflict");
			  sprintf (repl,
					   "480 Priority Class Conflict: class %i have not this"
                       " action",
					   st->sop->pri_class);
			  return 1;
			}
		}
	}
  return 0;
}
