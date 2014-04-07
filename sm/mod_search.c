/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file sm/mod_search.c
  * @brief user directory search
  * @author Sylvain "Gugli" Guglielmi
  * $Date: 2014/04/05 15:19:28 $
  * $Revision: 1.0 $
  */

#include "sm.h"

#define uri_SEARCH    "jabber:iq:search"

typedef struct _mod_search_st {
    int namespace;
} *mod_search_t;

static mod_ret_t _search_pkt_sm(mod_instance_t mi, pkt_t pkt) {
	//mod_search_t mod = (mod_search_t)mi->mod->private;
    os_t os;
	int isactive, iqelem, queryelem, elem, ns;
	char const * argname;
	char const * argvalue;
	int arglength, argvaluelength;
	jid_t jid;
	
    if( pkt->type != pkt_IQ )
        return mod_PASS;
	
	iqelem = nad_find_elem(pkt->nad, 0, -1, "iq", 1);
	if(iqelem < 0) {           
        return mod_PASS;
	}
	
    ns = nad_find_scoped_namespace(pkt->nad, uri_SEARCH, NULL);
	if(ns < 0) {           
        return mod_PASS;
	}
	
	queryelem = nad_find_elem(pkt->nad, 1, ns, "query", 1);
	if(queryelem < 0) {           
        return mod_PASS;
	}
	
	
	// That's a packet for us 
	elem = nad_find_elem(pkt->nad, queryelem, ns, 0, 1);
	if(elem < 0) {
		// That's not a search : that'a request for available fields
		pkt_tofrom(pkt);
        nad_set_attr(pkt->nad, iqelem, -1, "type", "result", 6);
		nad_insert_elem(pkt->nad, queryelem, ns, "instructions", "Fill in one or more fields to search for any matching active users.");
		nad_insert_elem(pkt->nad, queryelem, ns, "jid", 0);		
		pkt_router(pkt);
		return mod_HANDLED;	
	}
	else
	{
		// That a search, let's browse search arguments
		jid = 0;
		do{
			argname = NAD_ENAME(pkt->nad, elem);
			arglength = NAD_ENAME_L(pkt->nad, elem);
			argvalue = NAD_CDATA(pkt->nad, elem);
			argvaluelength = NAD_CDATA_L(pkt->nad, elem);
			
			if( strncmp(argname,"jid", arglength) == 0)
			{
				jid = jid_new(argvalue, argvaluelength);
				break;
			}
			
			elem = nad_find_elem(pkt->nad, elem, ns, 0, 0);		
		}while(elem >= 0);
		
		
		/* get their active status */	
		if(jid && storage_get(mi->sm->st, "active", jid_user(jid), NULL, &os) == st_SUCCESS ) {
			os_free(os);
			isactive = 1;
		} else {
			isactive = 0;
		}
			

		
		pkt_tofrom(pkt);
        nad_set_attr(pkt->nad, iqelem, -1, "type", "result", 6);
		
		// drop all the fields
		do{
			elem = nad_find_elem(pkt->nad, queryelem, ns, 0, 1);
			if(elem<0) break;
			nad_drop_elem(pkt->nad, elem);
		} while(1);
		
		if(isactive) {
			elem = nad_insert_elem(pkt->nad, queryelem, ns, "item", 0);
			nad_set_attr(pkt->nad, elem, ns, "jid", jid_user(jid), strlen(jid_user(jid)));
		}
		
		pkt_router(pkt);
		
		
		if(jid)
			jid_free(jid);
		
		return mod_HANDLED;	
	}
	
}

static void _search_free(module_t mod) {
    sm_unregister_ns(mod->mm->sm, uri_SEARCH);
    feature_unregister(mod->mm->sm, uri_SEARCH);
    free(mod->private);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
	mod_search_t search;

    if(mod->init) return 0;
	
    mod->pkt_sm = _search_pkt_sm;
	mod->free = _search_free;
	
    search = (mod_search_t) calloc(1, sizeof(struct _mod_search_st));	
	search->namespace = sm_register_ns(mod->mm->sm, uri_SEARCH);
    feature_register(mod->mm->sm, uri_SEARCH);
	
	mod->private = search;
	
    return 0;
}
