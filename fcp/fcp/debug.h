/***************************************************************************
                          debug.h
                             -------------------
    begin                : Tue Nov 28 2000
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

#ifndef debug_h
#define debug_h 1

#include <syslog.h>

#include "api.h"
#include "parse.h"

/* Uncomment the following to disable debugging at compile time for faster
   code */
/* #define FCP_NO_DEBUG */

/* buffer to store debug messages */
char debug_msg_helper[256];

/* open the syslog functionality */
void fcp_openlog (char *logname, int pid, int logclass);

/* close the syslog functionality */
void fcp_closelog ();

/* if loglevel higher than fcp_loglevel passes logmessage to syslog */
void fcp_log (int loglevel, char *logmessage);

/* internal use only */
void fcp_log_fcp_state (struct fcp_state *state);

/* Internal use only */
void fcp_log_name_value (struct name_value *name);

#endif
