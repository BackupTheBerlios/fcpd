/***************************************************************************
                          api.h
                             -------------------
    begin                : Sun Nov 26 2000
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

#ifndef api_h
#define api_h 1

#define FCP_INTERFACE_IN 				1
#define FCP_INTERFACE_OUT				2
#define FCP_INTERFACE_DMZ				3
#define FCP_INTERFACE_LOOPBACK	4

#define fcp_action_pass			1
#define fcp_action_drop			2
#define fcp_action_reject		3

/* this structure stores a complete PacketMatchingExpression */
struct fcp_pme
{
  /* _def indicates that this value was specified in the request */
  int proto, proto_def;
  /* warning: proto will be used in querynat-statement too, although there's
     no PME !!! same thing with SRCIP and SRCPRT, which are used by QUERYNAT
     as IP and PORT !!!!!! UPPERPORT will be saved in DSTPORT - very ugly...
     will be changed in *future* -> struct reserved */
  unsigned int src_ip;
  int src_ip_def;
  unsigned int src_netmask;
  int src_netmask_def;
  unsigned int src_pt;
  int src_pt_def;
  unsigned int src_uppt;
  int src_uppt_def;
  unsigned int dst_ip;
  int dst_ip_def;
  unsigned int dst_netmask;
  int dst_netmask_def;
  unsigned int dst_pt;
  int dst_pt_def;
  unsigned int dst_uppt;
  int dst_uppt_def;
  int tos_fld, tos_fld_def;
  int syn_flg, syn_flg_def;
  int icmp_type, icmp_type_def;
  int in_if, in_if_def;
  int out_if, out_if_def;
};

/* this structure stores SetOptions */
struct fcp_sop
{
  int action, action_def;
  // struct fcp_pme *packet_modf;
  struct
  {
	// int proto, proto_def;
	// unsigned int src_ip, dst_ip;
	// int src_ip_def, dst_ip_def;
	// unsigned int src_netmask, dst_netmask;
	// int src_pt, src_pt_def;
	// int src_uppt;
	// int dst_pt, dst_pt_def;
	// int dst_uppt;
	int tos_fld, tos_fld_def;
  }
  packet_modf;
  int icmp_msg, icmp_msg_def;
  int timer, timer_def;
  int reflexive, reflexive_def;
  unsigned int pri_class, pri_class_def;
  int log, log_def;
};

enum directions
{
  NOT_SET,
  IN_OUT,
  IN_DMZ,
  IN_LOOP,
  OUT_IN,
  OUT_DMZ,
  OUT_LOOP,
  DMZ_IN,
  DMZ_OUT,
  DMZ_LOOP,
  LOOP_IN,
  LOOP_OUT,
  LOOP_DMZ
};

/* this structure stores a complete state. in *future* masq_ will be used for 
   NAT */
struct fcp_state
{
  struct fcp_pme *pme;
  struct fcp_sop *sop;
  unsigned int masq_ip;
  unsigned int masq_port;
  unsigned int masq_uppt;
  char *owner_ip;
  enum directions direction;
};

/* Is the base structure for a list, which includes the reserved ports on the
   firewall. */
struct fcp_reserved				/* *nils* API change: added uppt's!! */
{
  unsigned int masq_ip;
  int masq_port;
  int masq_uppt;
  unsigned int origin_ip;
  int origin_port;
  int origin_uppt;
  int proto;					/* *nils* API change: added uppt's!! */
};

/* This structure will be returned/filled by fcp_query API call */
struct fcp_query_answer
{
  struct fcp_pme *pme;
  struct fcp_sop *sop;
  struct fcp_query_answer *next;
};

/* This struct contains one IP, the belonging netmask and a pointer to next
   element of the list. If it's a single IP the netmask should be set to
   0xFFFFFFFF. */
struct fcp_address_list
{
  unsigned int address;
  unsigned int netmask;
  struct fcp_address_list *next;
};

/* This list contain the IPs which are known as the internal IPs of the
   firewall. */
struct fcp_address_list fcp_internal_ips;

/* This list contains the IPs which have to be masquareded. */
struct fcp_address_list fcp_masq_ips;

/* This list contains the IPs which are in the DMZ */
struct fcp_address_list fcp_dmz_ips;

/* This struct contains a pointer to the name of an interface. For future
   extension is the pointer to the next interface. Until yet only one
   interface is supported.  */
struct fcp_interface_list
{
  char *name;
  struct fcp_interface_list *next;
};

/* These three structs contains the names of the interfaces as/if specified
   in the configuration file. */
struct fcp_interface_list fcp_in_interface, fcp_out_interface,
  fcp_dmz_interface;

/* These are the IPs of the three interfaces of the server. */
unsigned int fcp_internal_IP, fcp_outer_IP, fcp_demilitary_IP;

/* These ints contain the packets per time which should be logged. */
int fcp_log_per_sec, fcp_log_per_min, fcp_log_per_hou, fcp_log_per_day;

/* This function is called from main at startup of the server. So here can
   all nessecary things be initalised or checked. */
void fcp_api_init ();

/* inserts a rule according to state. returns: 1: ok ; 0: insert failed */
int fcp_rule_insert (struct fcp_state *state, char *errstr);

/* deletes a rule according to state. returns: 1: ok ; 0: delete failed */
int fcp_rule_delete (struct fcp_state *state, char *errstr);

/* a call to this function changes the masq_port attrribute to the port
   number, which this function reserves. The masq_ip must be set to the ip,
   on which the masq port should be reserved (important for multiple ip's on
   the firewall) returns: 1: ok ; 0: failed; -1: no ports avaiable; -2...:
   reserved for *future* use */
int fcp_port_request (struct fcp_reserved *res, char *errstr);

/* Releases the port masq_port on the ip masq_ip. returns: 1: ok ; 0: failed;
   -1: port not reserved; -2...: reserved for *future* use */
int fcp_port_release (struct fcp_reserved *res, char *errstr);

/* returns the complete state of rule number rule_number. returns: 1: ok ; 0: 
   query failed; -1...: reserved for later use */
int fcp_query (struct fcp_query_answer *rules, unsigned int *rule_numbers,
			   char *errstr);

#endif
