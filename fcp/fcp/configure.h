/***************************************************************************
                          configure.h
                             -------------------
    begin                : Sun Dec 24 2000
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
#ifndef configure_h
#define configure_h 1

/* how much characters per line are read. make it bigger if needed */
#define FCP_CONFIGURE_LINE_LENGTH 140

/* reads the FCP_CONFIG_FILE, interprets it, and sets the variables in main.h */
int configure ();

#endif
