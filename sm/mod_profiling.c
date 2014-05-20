/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
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

#include "sm.h"

#ifdef GPERFTOOLS_ENABLED
#include <gperftools/profiler.h>
#endif

#define uri_Profiling "debug:profiling"


static void _profiling_start(const char* filename)
{
    fprintf(stderr,"profiling : start in %s\n",filename);
	
#ifdef GPERFTOOLS_ENABLED
	ProfilerStart(filename);
#endif
}

static void _profiling_stop()
{
    fprintf(stderr,"profiling : stop\n");
	
#ifdef GPERFTOOLS_ENABLED
			ProfilerStop();
#endif
}

static void _profiling_flush()
{
    fprintf(stderr,"profiling : flush\n");
	
#ifdef GPERFTOOLS_ENABLED
			ProfilerFlush();
#endif
}

/** our main handler for router packets */
static mod_ret_t _profiling_in_router ( mod_instance_t mi, pkt_t pkt )
{
	int ns, queryelem, attr;
	const char* value;
	int valuelength;
	
    /* check for the special update packet*/
    if ( !(pkt->type & pkt_IQ_SET) ) {      
		return mod_PASS;
	}
		
	ns = nad_find_namespace ( pkt->nad, 2, uri_Profiling, NULL );		
	if(ns < 0) {           
		return mod_PASS;
	}
	
	queryelem = nad_find_elem(pkt->nad, 1, ns, "query", 1);
	if(queryelem < 0) {           
		return mod_PASS;
	}

	attr = nad_find_attr(pkt->nad, queryelem, -1, "operation", NULL);
	if(attr < 0) {           
		return mod_PASS;
	}
	
	value = NAD_AVAL(pkt->nad, attr);
	valuelength = NAD_AVAL_L(pkt->nad, attr);

	if( strncmp(value, "start" ,valuelength) == 0)
	{
		attr = nad_find_attr(pkt->nad, queryelem, -1, "filename", NULL);
		value = NAD_AVAL(pkt->nad, attr);
		valuelength = NAD_AVAL_L(pkt->nad, attr);
		if(valuelength < 1024)
		{
			char filename[1024];
			sprintf ( filename, "%.*s", valuelength, value );
		
			_profiling_start(filename);
		}
	} else if ( strncmp(value, "stop" ,valuelength) == 0 ) {
		_profiling_stop();
		
	} else if ( strncmp(value, "flush" ,valuelength) == 0 ) {
		_profiling_flush();
	}
	
	pkt_free ( pkt );

	return mod_HANDLED;	
}
DLLEXPORT int module_init ( mod_instance_t mi, const char *arg )
{
    module_t mod = mi->mod;

    if ( mod->init ) {
        return 0;
    }
	
    mod->in_router = _profiling_in_router;

    feature_register ( mod->mm->sm, uri_Profiling );
	
    return 0;
}
