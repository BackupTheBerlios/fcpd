/***************************************************************************
                          network.c 
                             -------------------
    begin                : Sat Mar 31 2001
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

#include "network.h"
#include "main.h"
#include "debug.h"

/* initialize the network - creates a socket, binds to the port */
int init_network ()
{
  int yes = 1;					/* for setsockopt() SO_REUSEADDR, below */

  fcp_log (LOG_INFO, "NETWORK: starting networking");

  FD_ZERO (&master);			/* clear the master and temp sets */
  FD_ZERO (&read_fds);

  /* clear all request_counts */
  memset (&request_count, sizeof (request_count), 0);

  /* get the listener for TCP */
  if ((tcplistener = socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
	  fcp_log (LOG_CRIT,
			   "NETWORK: init_network: creation of tcp socket failed");
	  return (-2);
	}

  /* get the listener for UDP */
  if ((udplistener = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
	{
	  fcp_log (LOG_CRIT,
			   "NETWORK: init_network: creation of udp socket failed");
	  return (-2);
	}

  /* lose the pesky "address already in use" error message */
  if (setsockopt (tcplistener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int))
	  == -1)
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: setsockopt failed");
	  return (-2);
	}
  if (setsockopt (udplistener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int))
	  == -1)
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: setsockopt failed");
	  return (-2);
	}

  /* tcp bind */
  mytcpaddr.sin_family = AF_INET;
  mytcpaddr.sin_addr.s_addr = INADDR_ANY;
  mytcpaddr.sin_port = htons (fcp_port);
  memset (&(mytcpaddr.sin_zero), '\0', 8);
  if (bind (tcplistener, (struct sockaddr *) &mytcpaddr, sizeof (mytcpaddr))
	  == -1)
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: tcp bind failed");
	  return (-2);
	}

  /* udp bind */
  myudpaddr.sin_family = AF_INET;
  myudpaddr.sin_addr.s_addr = INADDR_ANY;
  myudpaddr.sin_port = htons (fcp_port);
  memset (&(myudpaddr.sin_zero), '\0', 8);
  if (bind (udplistener, (struct sockaddr *) &myudpaddr, sizeof (myudpaddr))
	  == -1)
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: udp bind failed");
	  return (-2);
	}

  /* tcp listen */
  if (listen (tcplistener, 10) == -1)	/* Backlog set to 10 */
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: tcp listen failed");
	  return (-2);
	}

  /* udp listen */
  if (listen (tcplistener, 10) == -1)	/* Backlog set to 10 */
	{
	  fcp_log (LOG_CRIT, "NETWORK: init_network: udp listen failed");
	  return (-2);
	}

  /* add the listeners to the master set */
  FD_SET (tcplistener, &master);
  FD_SET (udplistener, &master);

  /* keep track of the biggest file descriptor */
  fdmin = tcplistener;
  fdmax = udplistener;			/* so far, it's this one */
  return 0;
}

/* to change port while running, stop_network() and the init_network()
   closes all open connections and releases memory */
int stop_network ()				
{
  for (i = fdmin; i <= fdmax; i++)
	if (i)
	  {
		close (i);
		if (request[i] != NULL)
		  free (request[i]);
		if (ips[i] != NULL)
		  free (ips[i]);
	  }
  fcp_log (LOG_INFO, "NETWORK: stopped networking");
  return 0;
}

int sendall (int sofd, char *buff, int lenn)
{
  int total = 0;				/* how many bytes we've sent */
  int bytesleft = lenn;			/* how many we have left to send */
  int n;

  while (total < lenn)
	{
	  if (sofd == 0)			/* 0 is the dummy filedesc signaling udp */
		n = sendto (udplistener, buff + total, bytesleft, 0,
					(struct sockaddr *) &remoteudpaddr,
					sizeof (struct sockaddr));
	  else
		n = send (sofd, buff + total, bytesleft, 0);	/* normal tcp send */

	  if (n == -1)
		{
		  break;
		}
	  total += n;
	  bytesleft -= n;
	}
  return n == -1 ? -1 : 0;		/* return -1 on error, 0 on success */
}

/* handles all socket-fd's and returns if a complete request is received.
   returns the socket's fd and the request */
int get_full_request (int *filedesc, char *result, char *ip)
{
  char buffer[FCP_MAX_REQUEST_LENGTH];
  int len, eollen, overalllen;
  char eol1[5], eol2[3];		/* define end of line signatures */
  char *eolpos1, *eolpos2, *next_req;	/* saves request positions in buffer */
  char *quitpos;				/* the position of quit in buffer */

  eol1[0] = 13;
  eol1[1] = 10;
  eol1[2] = 13;
  eol1[3] = 10;
  eol1[4] = '\0';

  eol2[0] = 10;
  eol2[1] = 10;
  eol2[2] = '\0';

  /* main loop */
  for (;;)
	{
	  for (i = fdmin; i <= fdmax; i++)	/* check for requests states */
		{
		  if (request_count[i] == -1)
			{					/* socket must be closed, quit received */
			  send_response (i, "closing connection...\n");
			  close (i);
			  FD_CLR (i, &master);
			  free (request[i]);
			  free (ips[i]);
			  sprintf (debug_msg_helper,
					   "NETWORK: get_full_request: received"
					   " quit from socket %i - closed connection", i);
			  fcp_log (LOG_INFO, debug_msg_helper);
			  request_count[i] = 0;	/* reinit to normal state */
			  /* enable this to wait a second until the connection is closed,
			     this is needed if you want to view the results from a netcat
			     script, otherwise the connection is closed before netcat
			     fetches the results... took quite some time to figure out
			     :-) */
			  // sleep (1);

			  break;
			}
		  if (request_count[i] == 1)
			{	/* a complete request was found in buffer -
				 processing query */
			  /* search for double end of lines */
			  eollen = 4;
			  eolpos1 = strstr (request[i], eol1);
			  if (eolpos1 == NULL)
				{
				  eolpos1 = strstr (request[i], eol2);
				  eollen = 2;
				}

			  len = eolpos1 - request[i];
			  overalllen = strlen (request[i]);
			  /*
			     sprintf (debug_msg_helper, "NETWORK: get_full_request:
			     length is %i overall length is %i", len, overalllen);
			     fcp_log (LOG_INFO, debug_msg_helper); */
			  strncpy (result, request[i], len);	/* return the result */
			  result[len] = '\0';	/* and terminate the string */
			  strcpy (ip, ips[i]);	/* return the ip of the client */
			  *filedesc = i;	/* return the socket for the answer */
			  /*
			     sprintf (debug_msg_helper, "NETWORK: get_full_request:
			     received end of" " request from socket %i.", i); fcp_log
			     (LOG_INFO, debug_msg_helper); */
			  sprintf (debug_msg_helper,
					   "NETWORK: received full result from %s", ip);
			  fcp_log (LOG_INFO, debug_msg_helper);
			  sprintf (debug_msg_helper, "NETWORK: request is: %s", result);
			  fcp_log (LOG_INFO, debug_msg_helper);

			  /* saving the rest of the buffer */

			  buffer[0] = '\0';
			  next_req = request[i] + len + eollen;
			  strncpy (request[i], next_req, overalllen - len - eollen);

			  request[i][overalllen - len - eollen] = '\0';

			  sprintf (debug_msg_helper,
					   "NETWORK: get_full_request: rest is %s", request[i]);
			  fcp_log (LOG_INFO, debug_msg_helper);

			  /* now check if there is at least one more request
			     it will be handled next time get_full_request is called */
			  request_count[i] = 0;
			  eolpos1 = strstr (request[i], eol1);
			  quitpos = strstr (request[i], "quit");
			  if ((eolpos1 != NULL)
				  && ((eolpos1 < quitpos) || (quitpos == NULL)))
				request_count[i] = 1;
			  /* there's a full request in the buffer */

			  eolpos2 = strstr (request[i], eol2);
			  if ((eolpos2 != NULL)
				  && ((eolpos2 < quitpos) || (quitpos == NULL)))
				request_count[i] = 1;
			  /* there's a full request in the buffer */

			  if ((quitpos != NULL) && (((eolpos1 == NULL)
										 && (eolpos2 == NULL))
										|| ((eolpos1 != NULL)
											&& (quitpos < eolpos1))
										|| ((eolpos2 != NULL)
											&& (quitpos < eolpos2))))
				/* quit received - closing socket, in the next loop
				   indicated by request_count=-1 */
				request_count[i] = -1;
			  return 0;
			}
		}

	  /* there have been no unprocessed complete requests - run
	     select to get some input */

	  read_fds = master;		/* copy it */
	  if (select (fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
		{
		  /* exiting with error is normal in our case, since the alarm
		     signal, used for the timeout of rules, forces select to exit, no
		     problem, it will be respawned next time get_full_request is
		     called

		     fcp_log (LOG_DEBUG, "NETWORK: get_full_request: select ended
		     with error code"); */
		  return (-2);
		}

	  /* run through the existing connections looking for data to
	     read */
	  for (i = fdmin; i <= fdmax; i++)
		{
		  /* sprintf (debug_msg_helper, "NETWORK: get_full_request: trying:
		     %i", i); fcp_log (LOG_INFO, debug_msg_helper); */
		  if (FD_ISSET (i, &read_fds))
			{					/* we got one!! */
			  /*
			     sprintf (debug_msg_helper, "NETWORK: get_full_request: we
			     got one: %i", i); fcp_log (LOG_INFO, debug_msg_helper); */
			  if (i == tcplistener)	/* new tcp connection ? */
				{
				  /* handle new connections */
				  addrlen = sizeof (remotetcpaddr);
				  if ((newfd =
					   accept (tcplistener, (void *)&remotetcpaddr, &addrlen)) == -1)
					{
					  fcp_log (LOG_CRIT,
							   "NETWORK: get_full_request: getting new tcp "
								"connection failed");
					  return (-2);
					}
				  else
					{
					  if (newfd >= FCP_MAX_REQUESTS - 1)
						{
						  sprintf (debug_msg_helper,
								   "NETWORK: get_full_request: maximum "
									"connections exceeded");
						  fcp_log (LOG_INFO, debug_msg_helper);
						  close (newfd);
						}
					  else
						{
						  FD_SET (newfd, &master);	/* add to master set */
						  if (newfd > fdmax)
							{	/* keep track of the maximum */
							  fdmax = newfd;
							}
						  ips[newfd] = malloc (16);
						  strcpy (ips[newfd],
								  inet_ntoa (remotetcpaddr.sin_addr));
						  sprintf (debug_msg_helper,
								   "NETWORK: get_full_request: new tcp "
									"connection from %s on "
								   "socket %d\n", ips[newfd], newfd);
						  fcp_log (LOG_INFO, debug_msg_helper);
						  request[newfd] = malloc (FCP_MAX_REQUEST_LENGTH);
						  /* allocate request buffer for this socket/request */
						  request[newfd][0] = '\0';
						  /* terminate the new buffer */
						  request_count[newfd] = 0;
						  /* there's neither a full request nor a quit yet */
						  send_response (newfd, FCP_WELCOME_STRING);
						  /* hello world ;-) */
						}
					}
				}
			  else
				{
				  if (i == udplistener)	/* udp packet arrived */
					{
					  addrlen = sizeof (struct sockaddr);
					  nbytes = recvfrom (udplistener, buf, sizeof (buf), 0,	/* receive */
								 (struct sockaddr *) &remoteudpaddr,
								 &addrlen);	/* request */
					  strcpy (ip, inet_ntoa (remoteudpaddr.sin_addr)); /* return */
																/* ip */
																/* txt */
					  *filedesc = 0;	/* dummy filedescriptor meaning udp */
					  strncpy (result, buf, nbytes);	/* return result */
					  result[nbytes] = '\0';	/* terminate result string */

					  sprintf (debug_msg_helper,
							   "NETWORK: received udp request from %s, port %i",
							   ip, htons (remoteudpaddr.sin_port));
					  fcp_log (LOG_INFO, debug_msg_helper);
					  sprintf (debug_msg_helper,
							   "NETWORK: request is: %s", result);
					  fcp_log (LOG_INFO, debug_msg_helper);
					  return 0;	/* process query, send_reply to fd 0 forces
								   udp sendto() */
					}
				  else
					nbytes = recv (i, buf, sizeof (buf), 0);	/* handle tcp
															 data */
				  if (nbytes <= 0)
					{
					  /* got error or connection closed by client */
					  if (nbytes == 0)
						{
						  /* connection closed */
						  sprintf (debug_msg_helper,
								   "NETWORK: get_full_request: "
								   "connection/socket %d closed", i);
						  fcp_log (LOG_INFO, debug_msg_helper);
						}
					  else
						{
						  sprintf (debug_msg_helper,
								   "NETWORK: get_full_request: error receiving"
                                   " data");
						  fcp_log (LOG_INFO, debug_msg_helper);
						}
					  close (i);	/* bye! */
					  FD_CLR (i, &master);	/* remove from master set */
					  free (request[i]);	/* freeing memory for this request */
					  free (ips[i]);
					}
				  else
					{
					  /* we got some data from a client */
					  buf[nbytes] = '\0';	/* terminate the buffer */
					  strcat (request[i], buf);	/* concat buffer to request
												 buffer */
					  buffer[0] = '\0';	/* of this socket an terminate string */

					  eolpos1 = strstr (request[i], eol1);	/* find double
															end of line */
					  quitpos = strstr (request[i], "quit");	/* or quit */
					  if ((eolpos1 != NULL)
						  && ((eolpos1 < quitpos) || (quitpos == NULL)))
						request_count[i] = 1;
					  /* there's a full request in the buffer */

					  eolpos2 = strstr (request[i], eol2);	/* next possible
															double eol */
					  if ((eolpos2 != NULL)
						  && ((eolpos2 < quitpos) || (quitpos == NULL)))
						request_count[i] = 1;
					  /* there's a full request in the buffer */

					  /*
					     sprintf (debug_msg_helper, "we got: eolpos1 %p
					     eolpos2 %p quitpos %p, req_c=%i", eolpos1, eolpos2,
					     quitpos, request_count[i]); fcp_log (LOG_INFO,
					     debug_msg_helper); */

					  if ((quitpos != NULL) && (	/* is quit (before eol)
													 exisiting ? */
												 ((eolpos1 == NULL)
												  && (eolpos2 == NULL))
												 || ((eolpos1 != NULL)
													 && (quitpos < eolpos1))
												 || ((eolpos2 != NULL)
													 && (quitpos < eolpos2))))
						/* quit received - closing socket in next loop, */
						request_count[i] = -1;

					}
				}
			}
		}
	}
}

  /* sends the string as a reply to the specified socket */
int send_response (int sock, char *response)
{
  if (sendall (sock, response, strlen (response)) != 0)
	{
	  sprintf (debug_msg_helper,
			   "NETWORK: send_response: sendall failed on socket %i", i);
	  fcp_log (LOG_CRIT, debug_msg_helper);
	  return -1;
	}
  return 0;
}
