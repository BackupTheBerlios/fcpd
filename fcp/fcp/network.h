/***************************************************************************
                          network.h
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

#ifndef network_h
#define network_h 1


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main.h"

fd_set master;					// master file descriptor list
fd_set read_fds;				// temp file descriptor list for select()
struct sockaddr_in mytcpaddr;	// server tcp address
struct sockaddr_in remotetcpaddr;	// client tcp address
struct sockaddr_in myudpaddr;	// server udp address
struct sockaddr_in remoteudpaddr;	// client udp address
int fdmax, fdmin;				// minimum and maximum file descriptor number
int tcplistener;				// listening tcp socket descriptor
int udplistener;				// listening udp socket descriptor
int newfd;						// newly accept()ed socket descriptor
char buf[FCP_MAX_REQUEST_LENGTH];	// buffer for client data
int nbytes;
int addrlen;
int i, j;

  /* this stores data and ips, received so far for each connection */
char *request[FCP_MAX_REQUESTS];	// maximum parallel connections
char *ips[FCP_MAX_REQUESTS];	// stores ip-addresses of connections
int request_count[FCP_MAX_REQUESTS];
			// signalizes if there are any full requests left in the buffer
			// (1: yes)
			// (0: no) or that quit has been received (-1)

/* initialize the network - creates a socket, binds to the port */
int init_network ();

/* stops the network - freeing all open sockets end memory */
int stop_network ();

/* handles all socket-fd's and returns if a complete request is received.
   returns the socket's fd and the request */
int get_full_request (int *, char *, char *);

/* sends the string as a reply to the specified socket */
int send_response (int, char *);


#endif
