/***************************************************************************
                          interpret.h
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

#include "parse.h"

#ifndef interpret_h
#define interpret_h 1

/* interpret takes a parsed name-value-pairs list, and checks for known
   tokens, checking validity of values, then manipulates states lists and
   actually does something by running api-calls to insert and remove rules
   in/from the firewall. */
int interpret (struct name_value *, char **, char *);

#endif
