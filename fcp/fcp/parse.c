/***************************************************************************
                          parse.c
                             -------------------
    begin                : Mon Dec 11 2000
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

#include <stdlib.h>
#include <stdio.h>
#include "parse.h"
#include "debug.h"

/* this is the revision of the fcp-parser - it uses special syntax checks to
   ensure, that the new protocol is used correctly. This new implementation
   has one big goal: do everything here and the fuck leave the interpreter
   untouched...

   it's planned for a future release, that a good interpreter will be coded
   but for now it does it's work quite well, checking syntax and semantic in
   his own AI-style way - change it yourself, if you like :-) */

#define FCP_PARSER_CONTEXT_NOCONTEXT			0
#define FCP_PARSER_CONTEXT_SET						1
#define FCP_PARSER_CONTEXT_SET_STR				"SET\0"
#define FCP_PARSER_CONTEXT_RELEASE				2
#define FCP_PARSER_CONTEXT_RELEASE_STR  	"RELEASE\0"
#define FCP_PARSER_CONTEXT_QUERY					3
#define FCP_PARSER_CONTEXT_QUERY_STR			"QUERY\0"
#define FCP_PARSER_CONTEXT_QUERYNAT				4
#define FCP_PARSER_CONTEXT_QUERYNAT_STR		"QUERYNAT\0"
#define	FCP_PARSER_CONTEXT_RELEASENAT			5
#define	FCP_PARSER_CONTEXT_RELEASENAT_STR	"RELEASENAT\0"
#define	FCP_PARSER_CONTEXT_PME						6
#define	FCP_PARSER_CONTEXT_PME_STR				"PME\0"
#define	FCP_PARSER_CONTEXT_SETOPT					7
#define	FCP_PARSER_CONTEXT_SETOPT_STR			"SOPT\0"

/* input is in_buf buffer, containing the request to be parsed len length of
   the incoming buffer name_value linked list to be filled with tokens err
   will be filled with a potential error string */
int parse (char *in_buf, int len, struct name_value *ret, char *err)
{
  /* small help func to determine the context number if a token somwhat
     smells like a context-token */
  int check_for_context (char *checkme)
  {
	int return_me = 0;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_SET_STR)) ?
	  0 : FCP_PARSER_CONTEXT_SET;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_RELEASE_STR)) ?
	  0 : FCP_PARSER_CONTEXT_RELEASE;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_QUERY_STR)) ?
	  0 : FCP_PARSER_CONTEXT_QUERY;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_QUERYNAT_STR)) ?
	  0 : FCP_PARSER_CONTEXT_QUERYNAT;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_RELEASENAT_STR)) ?
	  0 : FCP_PARSER_CONTEXT_RELEASENAT;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_PME_STR)) ?
	  0 : FCP_PARSER_CONTEXT_PME;
	return_me += (strcasecmp (checkme, FCP_PARSER_CONTEXT_SETOPT_STR)) ?
	  0 : FCP_PARSER_CONTEXT_SETOPT;
	return return_me;
  }

  int i;						/* counter for the whole request */
  int context;					/* parser context */

  /* the internal buffer will never exceed the request's length */
  char *int_buf = malloc (len + 10);

  /* the current token */
  char *token;

  int errvalue = 0;

  int ctl;						/* current token length */
  int eol_found;				/* indicates that the current token was ended 
								   by endofline */

  /* define an internal token structure, which is a double linked list
     containing the value and it's according context */
  struct its
  {
	struct its *next, *prev;
	char *token;
	int context;
  };

  /* instantiate the base of the internal token struct struct list */
  /* we now have a token context list base... */
  struct its *tclb = malloc (sizeof (struct its));

  /* and a token context list to be inserted :) */
  struct its *tcltbi;

  /* and a token context list which represents the current position :-))) */
  struct its *tclwrtcp;

  /* and a token context list for scratch purposes */
  struct its *tclfsp;

  struct name_value *akt_struct = ret;

  sprintf (debug_msg_helper, "PARSER: starting up");
  fcp_log (LOG_DEBUG, debug_msg_helper);
  sprintf (debug_msg_helper, "PARSER: parsing \"%s\" with length %i", in_buf,
		   len);
  fcp_log (LOG_DEBUG, debug_msg_helper);

  // token[tokcount] = '\0';

  context = FCP_PARSER_CONTEXT_NOCONTEXT;
  ctl = 0;
  eol_found = 0;

  /* initialize the list so that prev and next are NULL for sure */
  memset (tclb, 0, sizeof (struct its));

  /* the current pos list is the base for now */
  tclwrtcp = tclb;

  for (i = 0; i <= len; i++)
	{
	  switch (in_buf[i])
		{
		case 13:
		  break;				/* ignore CR, it's optional, LF is required
								   anyways */
		case 0:				/* ignore end of request - this will be
								   treated like eol */
		case 10:				/* eol detected - remember that for later */
		  eol_found = 1;
		case '=':;
		case ';':;
		case ',':;				/* these are delimiters too now */
		case 32:;
		case 9:				/* we got a whitechar here */
		  if (ctl)				/* length not 0 -> this really was a token... 
								 */
			{
			  /* create a new token - length is current length + \0 */
			  token = malloc (ctl + 1);
			  /* terminate the current token */
			  int_buf[ctl] = '\0';
			  /* save the current token into the new one */
			  strcpy (token, int_buf);
			  /* now we got a new token, let everybody know :) */
			  sprintf (debug_msg_helper, "PARSER: found token \"%s\","
					   "context is %i", token, context);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* reset the current token length */
			  ctl = 0;
			  /* check if we got a new context token */
			  if (!context)		/* no context yet ... */
				{
				  /* try to fetch new context */
				  if (!(context = check_for_context (token)))
					{
					  /* we're in a mess now, no context yet and no context
					     token */
					  sprintf (err,
							   "400 Bad Request: misplaced token \"%s\"\n",
							   token);
					  errvalue = 1;
					  sprintf (debug_msg_helper,
							   "PARSER: token \"%s\" has no con"
							   "text and is none itself", token);
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					}
				  else
					{
					  sprintf (debug_msg_helper,
							   "PARSER: entering new context %i", context);
					  fcp_log (LOG_DEBUG, debug_msg_helper);
					  /* ******************************* */
					  /* interpreter preserver patch ON: */
					  if (context <= 5)	/* the token is one of
										   SET...RELEASENAT */
						{		/* so we must keep it for stupid interpreter */
						  /* insert the brandnew token into the list FIXME */
						  sprintf (debug_msg_helper,
								   "PARSER: inserting token %s", token);
						  fcp_log (LOG_DEBUG, debug_msg_helper);
						  /* create new node */
						  tcltbi = malloc (sizeof (struct its));
						  /* append to list */
						  tcltbi->prev = tclwrtcp;
						  tcltbi->next = NULL;
						  tclwrtcp->next = tcltbi;
						  /* set context */
						  tcltbi->context = context;
						  /* set token */
						  tcltbi->token = token;
						  /* set new current one */
						  tclwrtcp = tcltbi;
						  /* whuu ... great that you still do understand
						     what's up */
						}
					  /* interpreter preserver patch OFF */
					  /* ******************************* */
					  break;	/* the new context is now set, token is done */
					}
				}
			  else
				{
				  /* insert the brandnew token into the list FIXME */
				  sprintf (debug_msg_helper, "PARSER: inserting token %s",
						   token);
				  fcp_log (LOG_DEBUG, debug_msg_helper);
				  /* create new node */
				  tcltbi = malloc (sizeof (struct its));
				  /* append to list */
				  tcltbi->prev = tclwrtcp;
				  tcltbi->next = NULL;
				  tclwrtcp->next = tcltbi;
				  /* set context */
				  tcltbi->context = context;
				  /* set token */
				  tcltbi->token = token;
				  /* set new current one */
				  tclwrtcp = tcltbi;
				  /* whuu ... great that you still do understand what's up */
				}
			}
		  if (in_buf[i] == '=')
			{
			  token = "=\0";
			  sprintf (debug_msg_helper, "PARSER: inserting token %s", token);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* create new node */
			  tcltbi = malloc (sizeof (struct its));
			  /* append to list */
			  tcltbi->prev = tclwrtcp;
			  tcltbi->next = NULL;
			  tclwrtcp->next = tcltbi;
			  /* set context */
			  tcltbi->context = context;
			  /* set token */
			  tcltbi->token = token;
			  /* set new current one */
			  tclwrtcp = tcltbi;
			}
		  if (eol_found)
			{
			  sprintf (debug_msg_helper, "PARSER: leaving context %i",
					   context);
			  fcp_log (LOG_DEBUG, debug_msg_helper);
			  /* every context ends at newline, sorry 'bout that */
			  context = 0;
			  /* reset eol_found flag, that we can reuse it */
			  eol_found = 0;
			}
		  break;				/* that's it for whitespaces and newlines */

		default:
		  /* anything else but whitespace and newline */
		  /* safe char and incremente token length */
		  int_buf[ctl++] = in_buf[i];
		  /* thats it, ain't it easy? */
		  break;
		}						/* end of switch */
	}							/* end of for */

  /* <debug> !! tclwrtcp = tclb; while (tclwrtcp->next != NULL) { tclwrtcp =
     tclwrtcp->next; sprintf (debug_msg_helper,"DGB1: token: \"%s\", context
     %i,",tclwrtcp->token, tclwrtcp->context); fcp_log (LOG_DEBUG,
     debug_msg_helper); } </debug> !! */

  /* ******************************* */
  /* interpreter preserver patch ON: */


  /* first run, put tokens seperated by "-" and ":" together (portrange,
     icmp) */
  tclwrtcp = tclb;
  while (tclwrtcp->next)
	{
	  tclwrtcp = tclwrtcp->next;
	  /* 
	     sprintf (debug_msg_helper,"DGBx: processing token: \"%s\", context
	     %i,",tclwrtcp->token, tclwrtcp->context); fcp_log (LOG_DEBUG,
	     debug_msg_helper); */
	  if (!strcmp (tclwrtcp->token, "-"))	/* concatenate uvw - xyz to
											   uvw-xyz */
		{
		  if ((tclwrtcp->prev) && (tclwrtcp->next))
			{
			  tclwrtcp->prev->token = strcat (tclwrtcp->prev->token, "-\0");
			  tclwrtcp->prev->token =
				strcat (tclwrtcp->prev->token, tclwrtcp->next->token);
			  tclwrtcp->prev->next = tclwrtcp->next->next;
			  if (tclwrtcp->next->next)
				tclwrtcp->next->next->prev = tclwrtcp->prev;
			  tclfsp = tclwrtcp->prev;
			  free (tclwrtcp->next);
			  free (tclwrtcp);
			  tclwrtcp = tclfsp;
			}
		}
	  if (!strcmp (tclwrtcp->token, ":"))	/* concatenate uvw - xyz to
											   uvw-xyz */
		{
		  if ((tclwrtcp->prev) && (tclwrtcp->next))
			{
			  tclwrtcp->prev->token = strcat (tclwrtcp->prev->token, ":\0");
			  tclwrtcp->prev->token =
				strcat (tclwrtcp->prev->token, tclwrtcp->next->token);
			  tclwrtcp->prev->next = tclwrtcp->next->next;
			  if (tclwrtcp->next->next)
				tclwrtcp->next->next->prev = tclwrtcp->prev;
			  tclfsp = tclwrtcp->prev;
			  free (tclwrtcp->next);
			  free (tclwrtcp);
			  tclwrtcp = tclfsp;
			}
		}
	}

  /* <debug> !! tclwrtcp = tclb; while (tclwrtcp->next != NULL) { tclwrtcp =
     tclwrtcp->next; sprintf (debug_msg_helper,"DGB2: token: \"%s\", context
     %i,",tclwrtcp->token, tclwrtcp->context); fcp_log (LOG_DEBUG,
     debug_msg_helper); } </debug> !! */

  tclwrtcp = tclb;
  while (tclwrtcp->next)
	{
	  tclwrtcp = tclwrtcp->next;
	  if (!strcmp (tclwrtcp->token, "="))
		{
		  if (tclwrtcp->prev && tclwrtcp->prev->token &&
			  tclwrtcp->next && tclwrtcp->next->token)
			{
			  akt_struct->name = malloc (strlen (tclwrtcp->prev->token) + 2);
			  strcpy (akt_struct->name, tclwrtcp->prev->token);
			  akt_struct->value = malloc (strlen (tclwrtcp->next->token) + 2);
			  strcpy (akt_struct->value, tclwrtcp->next->token);
			  tclwrtcp = tclwrtcp->next;
			  akt_struct->next =
				(struct name_value *) malloc (sizeof (struct name_value));
			  akt_struct = akt_struct->next;
			  akt_struct->name = NULL;
			  akt_struct->next = NULL;
			  akt_struct->value = NULL;
			}
		  else
			{
			  sprintf (err, "400 Bad Request: misplaced \"=\"");
			  errvalue = 1;
			}
		}
	  else
		{
		  if (!
			  (tclwrtcp->next && tclwrtcp->next->token
			   && (!strcmp (tclwrtcp->next->token, "="))))
			{
			  akt_struct->name = malloc (strlen (tclwrtcp->token) + 2);
			  strcpy (akt_struct->name, tclwrtcp->token);
			  akt_struct->value = NULL;
			  akt_struct->next =
				(struct name_value *) malloc (sizeof (struct name_value));
			  akt_struct = akt_struct->next;
			  akt_struct->name = NULL;
			  akt_struct->next = NULL;
			  akt_struct->value = NULL;
			}
		}
	}

  /* interpreter preserver patch OFF */
  /* ******************************* */


  /* echoing and freeing the list */
  tclwrtcp = tclb;
  while (tclwrtcp->next != NULL)
	{
	  tclwrtcp = tclwrtcp->next;
	  free (tclwrtcp->prev);
	  sprintf (debug_msg_helper,
			   "PARSER: list contains: context %i token \"%s\" at addr %p",
			   tclwrtcp->context, tclwrtcp->token, tclwrtcp);
	  fcp_log (LOG_DEBUG, debug_msg_helper);
	}
  free (tclwrtcp);
  free (token);

  if (!errvalue)
	{
	  sprintf (debug_msg_helper, "PARSER: parsing succesful\n");
	  fcp_log (LOG_INFO, debug_msg_helper);
	}

  sprintf (debug_msg_helper, "PARSER: exiting\n");
  fcp_log (LOG_DEBUG, debug_msg_helper);
  free (int_buf);
  return errvalue;
}
