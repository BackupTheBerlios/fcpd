/***************************************************************************
                   validity.h  -  checks the valdity of a interpreted state
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

#ifndef validity_h
#define validity_h 1

#include "api.h"
#include "main.h"

/* this function take a state which has been interpreted and checks for
	 inconsistencies of a request
	 return value of 0 means validity - 1 means error
	 in case of error: repl contains the reply with the error message */
int check_validity (struct fcp_state *, char *reply);

#endif
