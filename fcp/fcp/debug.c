/***************************************************************************
                          debug.c
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

#include "debug.h"
#include "main.h"

/* Following LogLevels may be used: (from syslog.h):

   LOG_EMERG 0 system is unusable
   LOG_ALERT 1 action must be taken immediately
   LOG_CRIT 2 critical conditions
   LOG_ERR 3 error conditions
   LOG_WARNING 4 warning conditions
   LOG_NOTICE 5 normal but significant condition
   LOG_INFO 6 informational
   LOG_DEBUG 7 debug-level messages
 */

void fcp_openlog (char *logname, int pid, int logclass)
{
#ifndef FCP_NO_DEBUG			/* no debug code will be compiled */

  openlog (logname, pid, logclass);

#endif
}

void fcp_closelog ()
{
#ifndef FCP_NO_DEBUG			/* no debug code will be compiled */

  closelog ();

#endif
}

void fcp_log (int loglevel, char *logmessage)
{
#ifndef FCP_NO_DEBUG			/* no debug code will be compiled */

  void now_log (int ll, char *msg)
  {
	syslog (ll, msg);
  }

  if (loglevel <= fcp_loglevel)
	now_log (loglevel, logmessage);

#endif
}

/* This helper function logs parts of the fcp_state with syslog fcp_sop and
   the tcp flags will not be loged */
void fcp_log_fcp_state (struct fcp_state *state)
{
  struct fcp_state dbg = *state;

  syslog (LOG_DEBUG, "DEBUG: masq_ip: %u masq_port: %u owner_ip: %s",
		  dbg.masq_ip, dbg.masq_port, dbg.owner_ip);
  syslog (LOG_DEBUG, "DEBUG: proto: %i proto_def: %i", dbg.pme->proto,
		  dbg.pme->proto_def);
  syslog (LOG_DEBUG, "DEBUG: src_ip: %u src_ip_def: %i", dbg.pme->src_ip,
		  dbg.pme->src_ip_def);
  syslog (LOG_DEBUG, "DEBUG: src_netmask: %u src_netmask_def: %i",
		  dbg.pme->src_netmask, dbg.pme->src_netmask_def);
  syslog (LOG_DEBUG, "DEBUG: src_pt: %u src_pt_def: %i", dbg.pme->src_pt,
		  dbg.pme->src_pt_def);
  syslog (LOG_DEBUG, "DEBUG: src_uppt: %u src_uppt_def: %i",
		  dbg.pme->src_uppt, dbg.pme->src_uppt_def);
  syslog (LOG_DEBUG, "DEBUG: dst_ip: %u dst_ip_def: %i", dbg.pme->dst_ip,
		  dbg.pme->dst_ip_def);
  syslog (LOG_DEBUG, "DEBUG: dst_netmask: %u dst_netmaks_def: %i",
		  dbg.pme->dst_netmask, dbg.pme->dst_netmask_def);
  syslog (LOG_DEBUG, "DEBUG: dst_pt: %u dst_pt_def: %i", dbg.pme->dst_pt,
		  dbg.pme->dst_pt_def);
  syslog (LOG_DEBUG, "DEBUG: dst_uppt: %u dst_uppt_def: %i",
		  dbg.pme->dst_uppt, dbg.pme->dst_uppt_def);
  syslog (LOG_DEBUG, "DEBUG: tos_fld: %i tos_fld_def: %i", dbg.pme->tos_fld,
		  dbg.pme->tos_fld_def);
  syslog (LOG_DEBUG, "DEBUG: icmp_type: %i icmp_type_def: %i",
		  dbg.pme->icmp_type, dbg.pme->icmp_type_def);
  syslog (LOG_DEBUG, "DEBUG: in_if: %i in_if_def: %i", dbg.pme->in_if,
		  dbg.pme->in_if_def);
  syslog (LOG_DEBUG, "DEBUG: out_if: %i out_if_def: %i", dbg.pme->out_if,
		  dbg.pme->out_if_def);
};

/* This helper function logs every name and value of name_value list */
void fcp_log_name_value (struct name_value *name)
{
  struct name_value *this;

  this = name;
  while (this)
	{
	  syslog (LOG_DEBUG, "DEBUG: name: %s value: %s", this->name,
			  this->value);
	  syslog (LOG_DEBUG, "DEBUG: next: %u", (unsigned int)this->next);
	  this = this->next;
	}
}
