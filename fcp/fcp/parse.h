/***************************************************************************
                          parse.h  -  parses a request and inserts name
									  value pairs into the struct
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

#ifndef parse_h
#define parse_h 1

#include <string.h>

/* this structure contains the parsed name-value-pairs */
/* it is realized as a linked list */
struct name_value
{
  struct name_value *next;
  char *name;					/* according to protocol definitions */
  char *value;
};


/* parses the given string according to protocol syntax */
/* non zero return value means parse error(s) occurred.  */
/* return_struct is filled with values or error if failed */
int parse (char *buf, int buf_len, struct name_value *return_struct,
		   char *error);


#endif
