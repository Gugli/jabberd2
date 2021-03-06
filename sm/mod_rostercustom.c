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
#include <mysql.h>

#ifndef ROSTERCUSTOM_DEBUG
#define ROSTERCUSTOM_DEBUG 0
#endif

#define rostercustom_debug if(ROSTERCUSTOM_DEBUG) _rostercustom_debug

static void _rostercustom_debug(const char* file, int line, const char *msgfmt, ...)
{
	//log_write(sm->log, LOG_NOTICE, "connection to router closed");
    va_list ap;
    va_start(ap,msgfmt);
    fprintf(stderr,"rostercustom.c#%d: ",line);
    vfprintf(stderr,msgfmt,ap);
    va_end(ap);
    fprintf(stderr,"\n");
	fflush(stderr);
}

/** @file sm/mod_roster.c
  * @brief highly customisable roster managment & subscriptions
  * @author Robert Norris & Sylvain "Gugli" Guglielmi
  * $Date: 2013/05/20 05:34:13 $
  * $Revision: 1.00 $
  */

#define rostercutsom_params_maxcount			(9)	/* Max number of param values : must be equal to the max of MaxParamCount column in mod_rostercustom_statements.h */
#define rostercutsom_params_maxoccurencescount		(12)	/* Max Number of question marks in statements */

#define rostercutsom_results_maxcount			(10)
#define rostercutsom_results_buffersize			(1024)

#define rostercutsom_maxsubstatementcount		(4)

#define uri_ROSTERCUSTOM_APPLYDBCHANGES     "jabber:iq:rostercustom:applydbchanges"


#define MRostercustomStatement(__CodeName, __TextName, __ParamCount, __Results) ERostercustom_Statement_##__CodeName,
typedef enum {
#include "mod_rostercustom_statements.h"
    ERostercustom_Statement_Count
} rostercustom_statement_t;
#undef MRostercustomStatement

// The following names are used to identify actions in the config file

#define MRostercustomStatement(__CodeName, __TextName, __ParamCount, __Results) __TextName,
static const char * _rostercustom_preparedstatements_names[ERostercustom_Statement_Count] = {
#include "mod_rostercustom_statements.h"
};
#undef MRostercustomStatement

// Number of params
#define MRostercustomStatement(__CodeName, __TextName, __ParamCount, __Results) __ParamCount,
static const unsigned char _rostercustom_preparedstatements_maxparamcount[ERostercustom_Statement_Count] = {
#include "mod_rostercustom_statements.h"
};
#undef MRostercustomStatement


// Number of result fields
#define MRostercustomStatement(__CodeName, __TextName, __ParamCount, __Results) __Results
#define MRostercustomNoResult() 0,
#define MRostercustom1Result(__R1) 1,
#define MRostercustom3Results(__R1, __R2, __R3) 3,
#define MRostercustom7Results(__R1, __R2, __R3, __R4, __R5, __R6, __R7) 7,
#define MRostercustom10Results(__R1, __R2, __R3, __R4, __R5, __R6, __R7, __R8, __R9, __R10) 10,
static const unsigned char _rostercustom_preparedstatements_resultcount[ERostercustom_Statement_Count] = {
#include "mod_rostercustom_statements.h"
};
#undef MRostercustom10Results
#undef MRostercustom7Results
#undef MRostercustom3Results
#undef MRostercustom1Result
#undef MRostercustomNoResult
#undef MRostercustomStatement

// Types of params fields
enum rostercustom_paramtype {
    ERostercustom_StatementParam_String,
    ERostercustom_StatementParam_Integer
};

// Types of result fields
enum rostercustom_resulttype {
    ERostercustom_StatementResult_String,
    ERostercustom_StatementResult_Integer
};

#define MRostercustomStatement(__CodeName, __TextName, __ParamCount, __Results) __Results
#define MRostercustomTypeToEnum(__Type) ERostercustom_StatementResult_##__Type
#define MRostercustomNoResult() {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
#define MRostercustom1Result(__R1) {MRostercustomTypeToEnum(__R1), -1, -1, -1, -1, -1,-1,-1,-1,-1},
#define MRostercustom3Results(__R1, __R2, __R3) {MRostercustomTypeToEnum(__R1), MRostercustomTypeToEnum(__R2), MRostercustomTypeToEnum(__R3), -1, -1, -1, -1,-1, -1,-1},
#define MRostercustom7Results(__R1, __R2, __R3, __R4, __R5, __R6, __R7) {MRostercustomTypeToEnum(__R1), MRostercustomTypeToEnum(__R2), MRostercustomTypeToEnum(__R3), MRostercustomTypeToEnum(__R4), MRostercustomTypeToEnum(__R5), MRostercustomTypeToEnum(__R6), MRostercustomTypeToEnum(__R7),-1, -1,-1},
#define MRostercustom10Results(__R1, __R2, __R3, __R4, __R5, __R6, __R7, __R8, __R9, __R10) {MRostercustomTypeToEnum(__R1), MRostercustomTypeToEnum(__R2), MRostercustomTypeToEnum(__R3), MRostercustomTypeToEnum(__R4), MRostercustomTypeToEnum(__R5), MRostercustomTypeToEnum(__R6), MRostercustomTypeToEnum(__R7), MRostercustomTypeToEnum(__R8), MRostercustomTypeToEnum(__R9), MRostercustomTypeToEnum(__R10)},
static const enum rostercustom_resulttype _rostercustom_preparedstatements_resulttypes[ERostercustom_Statement_Count][rostercutsom_results_maxcount] = {
#include "mod_rostercustom_statements.h"
};
#undef MRostercustom10Results
#undef MRostercustom7Results
#undef MRostercustom3Results
#undef MRostercustom1Result
#undef MRostercustomNoResult
#undef MRostercustomTypeToEnum
#undef MRostercustomStatement


typedef struct _mod_rostercustom_st {
    const char * 	host;
    unsigned short	port;
    const char * 	user;
    const char * 	password;
    const char * 	dbname;

    int			symmetrical; // symmetrical mode : no one-way relationships

    const char *	preparedstatementstext[ERostercustom_Statement_Count];
    unsigned int	preparedstatements_substatementscount[ERostercustom_Statement_Count];
    MYSQL_STMT *	preparedstatements_substatements[ERostercustom_Statement_Count][rostercutsom_maxsubstatementcount];

    unsigned char	preparedstatements_occurencescount[ERostercustom_Statement_Count][rostercutsom_maxsubstatementcount][rostercutsom_params_maxcount];
    unsigned char	preparedstatements_indexreorder[ERostercustom_Statement_Count][rostercutsom_maxsubstatementcount][rostercutsom_params_maxcount][rostercutsom_params_maxoccurencescount]; // matrix of params order

    MYSQL *		conn;

    // temp params and results
    unsigned char	currentpreparedstatement;
    unsigned char 	currentsubstatementindex;

    MYSQL_BIND			occurences[rostercutsom_params_maxoccurencescount];
    enum rostercustom_paramtype	params_type[rostercutsom_params_maxcount];
    const char*			params_strings[rostercutsom_params_maxcount];
    unsigned int 		params_stringslength[rostercutsom_params_maxcount];
    int				params_integers[rostercutsom_params_maxcount];
    unsigned char		params_currentindex;

    MYSQL_BIND		results[rostercutsom_results_maxcount];
    const char	 	results_buffers[rostercutsom_results_maxcount][rostercutsom_results_buffersize];
    unsigned long	results_length[rostercutsom_results_maxcount];
    my_bool	 	results_isnull[rostercutsom_results_maxcount];
    my_bool	 	results_error[rostercutsom_results_maxcount];

	log_t connectionlog;
} *mod_rostercustom_t;

typedef struct _rostercustom_walker_st {
    pkt_t  pkt;
    int    req_ver;
    int    ver;
    sess_t sess;
} *rostercustom_walker_t;

static unsigned int _rostercustom_mysql_aretypesmatching ( enum rostercustom_resulttype resulttype, enum enum_field_types mysqltype )
{
    switch ( resulttype ) {
    case ERostercustom_StatementResult_String:
        return mysqltype == MYSQL_TYPE_VAR_STRING || mysqltype == MYSQL_TYPE_BLOB;
    case ERostercustom_StatementResult_Integer:
        return mysqltype == MYSQL_TYPE_TINY || mysqltype == MYSQL_TYPE_SHORT || mysqltype == MYSQL_TYPE_LONG ||mysqltype == MYSQL_TYPE_LONGLONG;
    }
    return 0;
}


static enum enum_field_types _rostercustom_getmysqltype ( enum rostercustom_resulttype resulttype )
{
    switch ( resulttype ) {
    case ERostercustom_StatementResult_String:
        return MYSQL_TYPE_VAR_STRING;
    case ERostercustom_StatementResult_Integer:
        return MYSQL_TYPE_LONGLONG;
    }
    return 0;
}

static long _rostercustom_mysql_getintegerval ( const char* buffer, unsigned long length )
{
    switch ( length ) {
    case 1:
        return *buffer;
    case 2:
        return * ( ( const short int* ) buffer );
    case 4:
        return * ( ( const int* ) buffer );
    case 8:
        return * ( ( const long long int* ) buffer );
    }
    return -1;
}


static int _rostercustom_statementcall_ispossible ( mod_rostercustom_t mod, unsigned int index )
{
    return mod->preparedstatements_substatementscount[index] != 0;
}

/** prepare a call to a statement */
static void _rostercustom_statementcall_begin ( mod_rostercustom_t mod, unsigned int index )
{
    mod->params_currentindex = 0;
    mod->currentpreparedstatement = index;

    rostercustom_debug ( ZONE, "Begin database request %s : %s", _rostercustom_preparedstatements_names[index], mod->preparedstatementstext[index] );
}

static void _rostercustom_statementcall_addparamstring ( mod_rostercustom_t mod, const char* str, unsigned int strlen )
{
    const unsigned char paramindex = mod->params_currentindex;
    mod->params_strings[paramindex] = str;
    mod->params_stringslength[paramindex] = strlen;
	mod->params_type[paramindex] = ERostercustom_StatementParam_String;
    mod->params_currentindex++;

    rostercustom_debug ( ZONE, "\tParam %d : \"%s\"", mod->params_currentindex, str );
}

static void _rostercustom_statementcall_addparamint ( mod_rostercustom_t mod, const int intval )
{
    const unsigned char paramindex = mod->params_currentindex;
    mod->params_integers[paramindex] = intval;
	mod->params_type[paramindex] = ERostercustom_StatementParam_Integer;

    mod->params_currentindex++;

    rostercustom_debug ( ZONE, "\tParam %d : \"%d\"", mod->params_currentindex, intval );
}

/** call the statement */
static unsigned int _rostercustom_statementcall_execute_try ( mod_rostercustom_t mod )
{
    const unsigned char statementindex = mod->currentpreparedstatement;
    const unsigned char substatementcount = mod->preparedstatements_substatementscount[statementindex];

    const unsigned char paramcount = _rostercustom_preparedstatements_maxparamcount[statementindex];
    for ( ; mod->currentsubstatementindex<substatementcount; mod->currentsubstatementindex++ ) {
        MYSQL_STMT * stmt = mod->preparedstatements_substatements[statementindex][mod->currentsubstatementindex];
 
		rostercustom_debug ( ZONE, "\tDatabase request %s executing substatement %d/%d...", _rostercustom_preparedstatements_names[statementindex], mod->currentsubstatementindex+1, substatementcount );

        // bind params

        if ( mod->params_currentindex != paramcount ) {
            rostercustom_debug ( ZONE, "unexpected number of params %s : %d given where %d were expected", _rostercustom_preparedstatements_names[statementindex], paramcount, mod->params_currentindex );
            return 1;
        }

        if ( paramcount ) {			
            unsigned char occurencestotalcount = 0;
            unsigned char paramindex;
            for ( paramindex = 0; paramindex < paramcount; paramindex++ ) {

                const unsigned char occurencecount = mod->preparedstatements_occurencescount[statementindex][mod->currentsubstatementindex][paramindex];

                occurencestotalcount += occurencecount;

                unsigned char occurenceindex;
                for ( occurenceindex = 0; occurenceindex < occurencecount; occurenceindex++ ) {

                    const unsigned char reorderindex = mod->preparedstatements_indexreorder[statementindex][mod->currentsubstatementindex][paramindex][occurenceindex];

                    memset ( &mod->occurences[reorderindex], 0, sizeof ( mod->occurences[reorderindex] ) );

                    if ( mod->params_type[paramindex] == ERostercustom_StatementParam_String ) {
                        mod->occurences[reorderindex].buffer_type	= MYSQL_TYPE_STRING;
                        mod->occurences[reorderindex].buffer	= ( void* ) mod->params_strings[paramindex];
                        mod->occurences[reorderindex].buffer_length	= mod->params_stringslength[paramindex];
                        mod->occurences[reorderindex].length_value	= mod->params_stringslength[paramindex];
                    } else if ( mod->params_type[paramindex] == ERostercustom_StatementParam_Integer ) {
                        mod->occurences[reorderindex].buffer_type	= MYSQL_TYPE_LONG;
                        mod->occurences[reorderindex].buffer	= ( void* ) & mod->params_integers[paramindex];
                        mod->occurences[reorderindex].buffer_length	= sizeof ( int );
                        mod->occurences[reorderindex].length_value	= sizeof ( int );
                    }
                }
            }
            
#if ROSTERCUSTOM_DEBUG
			{
				rostercustom_debug ( ZONE, "\tOccurrences :");
				unsigned int i;
				for(i=0; i<occurencestotalcount; i++)
				{
					if(mod->occurences[i].buffer_type == MYSQL_TYPE_STRING) {
						rostercustom_debug ( ZONE, "\t\tStr : %s", (const char*)(mod->occurences[i].buffer) );
					} else if (mod->occurences[i].buffer_type == MYSQL_TYPE_LONG) {
						rostercustom_debug ( ZONE, "\t\tInt : %d", *((const int*)(mod->occurences[i].buffer)) );
					} else {
						rostercustom_debug ( ZONE, "\t\t????" );
					}
				}
			}
#endif
			
			if ( mysql_stmt_bind_param ( stmt, mod->occurences ) != 0 ) {
				rostercustom_debug ( ZONE, "mysql_stmt_bind_param failed for %s", _rostercustom_preparedstatements_names[statementindex] );
				return 1;
			}
        }

        // last substatement : prepare results
        if ( mod->currentsubstatementindex+1 == substatementcount ) {
            unsigned int numfields = mysql_stmt_field_count ( stmt );
            if ( numfields > 0 ) {
                unsigned int i;
                memset ( mod->results, 0, sizeof ( mod->results[0] ) *numfields );
                for ( i = 0; i<numfields; i++ ) {
                    mod->results[i].buffer_type = _rostercustom_getmysqltype(_rostercustom_preparedstatements_resulttypes[statementindex][i]);
                    mod->results[i].buffer = & mod->results_buffers[i];
                    mod->results[i].length = & mod->results_length[i];
                    mod->results[i].error = & mod->results_isnull[i];
                    mod->results[i].is_null = & mod->results_error[i];
                    mod->results[i].buffer_length = rostercutsom_results_buffersize;
#if ROSTERCUSTOM_DEBUG
                    memset ( (void*)mod->results_buffers[i], -1, rostercutsom_results_buffersize ); // will help detect bugs
#endif
                }
				
                if ( mysql_stmt_bind_result ( stmt, mod->results ) ) {
                    rostercustom_debug ( ZONE, "mysql_stmt_bind_result failed for %s", _rostercustom_preparedstatements_names[statementindex] );
                    return 1;
                }
            }
        }

      
        if ( mysql_stmt_execute ( stmt ) ) {
            rostercustom_debug ( ZONE, "mysql_stmt_execute failed for %s : %s", _rostercustom_preparedstatements_names[statementindex], mysql_stmt_error ( stmt ) );
			return 1;
        }

        // last substatement : do not free results
        if ( mod->currentsubstatementindex+1 != substatementcount ) {
            mysql_stmt_free_result ( stmt );
        }
    }
    return 0;
}

/** fetch a row */
static int _rostercustom_statementcall_getnextrow ( mod_rostercustom_t mod )
{
    unsigned char statementindex = mod->currentpreparedstatement;
    const unsigned char substatementcount = mod->preparedstatements_substatementscount[statementindex];
    MYSQL_STMT * stmt = mod->preparedstatements_substatements[mod->currentpreparedstatement][substatementcount-1];
    return mysql_stmt_fetch ( stmt );
}


static void _rostercustom_statementcall_end ( mod_rostercustom_t mod )
{
    const unsigned char statementindex = mod->currentpreparedstatement;
    const unsigned char substatementcount = mod->preparedstatements_substatementscount[statementindex];
    MYSQL_STMT * stmt = mod->preparedstatements_substatements[mod->currentpreparedstatement][substatementcount-1];
    mysql_stmt_free_result ( stmt );
    mod->currentpreparedstatement = -1;
}

/** connects to sql server */
static int _rostercustom_connect( mod_rostercustom_t mrostercustom)
{
	unsigned int option_timeout;
	my_bool option_reconnect;
    MYSQL *conn;
    MYSQL_STMT *stmt;
    unsigned int i;
    unsigned int j;
    const char* statementtext;
    unsigned int statementtextlength;

    const char* currentchar;
    char* currentparsedchar;
    char* statementparsedtext;
    unsigned int previouscharisquestionmark;
    unsigned int occurenceindex;
    unsigned int paramindex;
	
    conn = mysql_init ( NULL ); // Initialise the instance

    if ( conn == NULL ) {
        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] unable to allocate mysql database connection state" );
        return 1;
    }

    mysql_options ( conn, MYSQL_READ_DEFAULT_GROUP, "jabberd" );
    mysql_options ( conn, MYSQL_SET_CHARSET_NAME, "utf8" );
	option_timeout = 60;
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &option_timeout);
	option_reconnect = 0;
    mysql_options ( conn, MYSQL_OPT_RECONNECT, &option_reconnect ); // Disable autoreconnect : we need to reprepare prepared-statements and not just reconnect

    /* connect with CLIENT_INTERACTIVE to get a (possibly) higher timeout value than default */
    if ( mysql_real_connect (
                conn,
                mrostercustom->host,
                mrostercustom->user,
                mrostercustom->password,
                mrostercustom->dbname,
                mrostercustom->port, NULL, CLIENT_INTERACTIVE ) == NULL ) {
        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] connection to mysql database failed: %s", mysql_error ( conn ) );
        return 1;
    }

    mysql_query ( conn, "SET NAMES 'utf8'" );


    mrostercustom->conn = conn;

    for ( i = 0; i < ERostercustom_Statement_Count; i++ ) {
        statementtext = mrostercustom->preparedstatementstext[i];
        if ( !statementtext ) {
            continue;
        }

        statementtextlength = strlen ( statementtext );
        if ( statementtextlength == 0 ) {
            continue;
        }

        mrostercustom->preparedstatements_substatementscount[i] = 0;

        const char* currentbegining = statementtext;
        const char* currentend;
        unsigned int substatementindex = 0;
        int islastsubstatement = 0;
        while ( !islastsubstatement ) {
            currentend = strchr ( currentbegining, ';' );
            if ( !currentend ) {
                islastsubstatement = 1;
                currentend = statementtext + statementtextlength;
            }

            statementparsedtext = malloc ( currentend-currentbegining+1 );

            memset ( mrostercustom->preparedstatements_occurencescount[i][substatementindex], 0, sizeof ( mrostercustom->preparedstatements_occurencescount[i][substatementindex] ) );
            memset ( mrostercustom->preparedstatements_indexreorder[i][substatementindex], 0xFF, sizeof ( mrostercustom->preparedstatements_indexreorder[i][substatementindex] ) );

            currentchar = currentbegining;
            currentparsedchar = statementparsedtext;
            previouscharisquestionmark = 0;
            occurenceindex = 0;

            while ( currentchar != currentend ) {
                if ( !previouscharisquestionmark && *currentchar == '?' ) {
                    previouscharisquestionmark=1;
                } else if ( !previouscharisquestionmark && *currentchar != '?' ) {
                    *currentparsedchar = *currentchar;
                    currentparsedchar++;
                } else if ( previouscharisquestionmark && *currentchar != '?' ) {
                    if ( '1' > *currentchar || *currentchar > '9' ) {
                        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] wrong statement syntax in %s. ? can only be followed by another ? or by one non-zero digit", _rostercustom_preparedstatements_names[i] );
                        return 1;
                    }
                    paramindex = *currentchar - '1';
                    if ( paramindex >= _rostercustom_preparedstatements_maxparamcount[i] ) {
                        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] wrong statement syntax in %s. Param index $%d is too high", _rostercustom_preparedstatements_names[i], paramindex+1 );
                        return 1;
                    }

                    mrostercustom->preparedstatements_indexreorder[i][substatementindex][paramindex][ mrostercustom->preparedstatements_occurencescount[i][substatementindex][paramindex] ] = occurenceindex;
                    mrostercustom->preparedstatements_occurencescount[i][substatementindex][paramindex] ++;

                    occurenceindex++;
                    *currentparsedchar = '?';
                    currentparsedchar++;
                    previouscharisquestionmark = 0;
                } else if ( previouscharisquestionmark && *currentchar == '?' ) {
                    *currentparsedchar = '?';
                    currentparsedchar++;
                    previouscharisquestionmark = 0;
                }

                currentchar++;
            }
            *currentparsedchar = 0; // Null terminated string

            stmt = mysql_stmt_init ( conn );
            if ( !stmt ) {
                log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] unable to allocate mysql database statement" );
                return 1;
            }

            if ( mysql_stmt_prepare ( stmt, statementparsedtext, strlen ( statementparsedtext ) ) ) {
                log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] unable to prepare %s statement: %s", _rostercustom_preparedstatements_names[i], mysql_stmt_error ( stmt ) );
                free ( ( void* ) statementparsedtext );
                return 1;
            }
            free ( ( void* ) statementparsedtext );

            if ( islastsubstatement ) {
                // Check the result count
                if ( mysql_stmt_field_count ( stmt ) != _rostercustom_preparedstatements_resultcount[i] ) {
                    log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] wrong number of result fields for %s : %d provided where %d were expected", _rostercustom_preparedstatements_names[i], mysql_stmt_field_count ( stmt ), _rostercustom_preparedstatements_resultcount[i] );
                    return 1;
                }

                // Check the result types
                if ( _rostercustom_preparedstatements_resultcount[i] > 0 ) {
                    MYSQL_RES * metadata = mysql_stmt_result_metadata ( stmt );
                    if ( metadata == NULL ) {
                        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] unable to get statement result metadata for %s", _rostercustom_preparedstatements_names[i] );
                        return 1;
                    }
                    MYSQL_FIELD *fields = mysql_fetch_fields ( metadata ) ;
                    if ( fields == NULL ) {
                        log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] unable to get statement result field types for %s", _rostercustom_preparedstatements_names[i] );
                        mysql_free_result ( metadata );
                        return 1;
                    }
                    for ( j = 0; j < _rostercustom_preparedstatements_resultcount[i]; j++ ) {
                        if ( !_rostercustom_mysql_aretypesmatching ( _rostercustom_preparedstatements_resulttypes[i][j], fields[j].type ) ) {
                            log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] type mismatch in result field types for %s arg %s", _rostercustom_preparedstatements_names[i], fields[j].name );
                            mysql_free_result ( metadata );
                            return 1;
                        }
                    }
                    mysql_free_result ( metadata );
                }
            }

            mrostercustom->preparedstatements_substatements[i][substatementindex] = stmt;

            mrostercustom->preparedstatements_substatementscount[i] ++;
            substatementindex++;

            currentbegining = currentend + 1;
        }
    }
    
    return 0;
}

static int _rostercustom_reconnect ( mod_rostercustom_t mrostercustom)
{
    unsigned int i;
    unsigned int j;
    unsigned int substatementcount;
	int result;
	
    if ( mrostercustom->conn ) {	
		rostercustom_debug ( ZONE, "Closing previous connection");
		for ( i = 0; i < ERostercustom_Statement_Count; i++ ) {
			substatementcount = mrostercustom->preparedstatements_substatementscount[i];
			for ( j = 0; j < substatementcount; j++ ) {
				mysql_stmt_close ( mrostercustom->preparedstatements_substatements[i][j] );
			}
		}
        mysql_close ( mrostercustom->conn );
		mrostercustom->conn = 0;
    }

	rostercustom_debug ( ZONE, "Reconnecting...");

	result = _rostercustom_connect(mrostercustom);
	if(result)
	{
		rostercustom_debug ( ZONE, "Reconnect failed");
	}
	
	return result;	
}


static void _rostercustom_statementcall_execute ( mod_rostercustom_t mrostercustom)
{   
	mrostercustom->currentsubstatementindex = 0;

	unsigned int result = _rostercustom_statementcall_execute_try ( mrostercustom );
	
	if(!result) return;
	
	const char* mysqlerror = mysql_error(mrostercustom->conn);
	const unsigned int mysqlerrorno = mysql_errno(mrostercustom->conn);
	
	if(mysqlerrorno)
	{
		log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] mysql error : [%d]%s", mysqlerrorno, mysqlerror );
	}
	
	if(mysqlerrorno == 2006 || mysqlerrorno ==  2013 /* CR_SERVER_GONE_ERROR || CR_SERVER_LOST */)
	{
		if ( _rostercustom_reconnect(mrostercustom) ) {
			log_write ( mrostercustom->connectionlog, LOG_ERR, "[rostercustom] Unable to reconnect after loosing connection to MySQL. ");
		} else {
			_rostercustom_statementcall_execute_try ( mrostercustom );
		}
	}
	else
	{
		return;
	}
	
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

/** free a single roster item */
static void _rostercustom_freeuser_walker ( const char *key, int keylen, void *val, void *arg )
{
    item_t item = ( item_t ) val;
    int i;

    jid_free ( item->jid );

    if ( item->name != NULL ) {
        free ( ( void* ) item->name );
    }

    for ( i = 0; i < item->ngroups; i++ ) {
        free ( ( void* ) item->groups[i] );
    }
    free ( item->groups );

    free ( item );
}

/** free the roster */
static void _rostercustom_freeuser ( user_t user )
{
    if ( user->roster == NULL ) {
        return;
    }

    rostercustom_debug ( ZONE, "freeing rostercustom for %s", jid_user ( user->jid ) );

    xhash_walk ( user->roster, _rostercustom_freeuser_walker, NULL );

    xhash_free ( user->roster );
    user->roster = NULL;
}

/** insert a roster item into this pkt, starting at elem */
static void _rostercustom_insert_item ( pkt_t pkt, item_t item, int elem )
{
    int ns, i;
    char *sub;

    ns = nad_add_namespace ( pkt->nad, uri_CLIENT, NULL );
    elem = nad_insert_elem ( pkt->nad, elem, ns, "item", NULL );
    nad_set_attr ( pkt->nad, elem, -1, "jid", jid_full ( item->jid ), 0 );

    if ( item->to && item->from ) {
        sub = "both";
    } else if ( item->to ) {
        sub = "to";
    } else if ( item->from ) {
        sub = "from";
    } else {
        sub = "none";
    }

    nad_set_attr ( pkt->nad, elem, -1, "subscription", sub, 0 );

    if ( item->ask == 1 ) {
        nad_set_attr ( pkt->nad, elem, -1, "ask", "subscribe", 9 );
    } else if ( item->ask == 2 ) { /* XXX there is no ask='unsubscribe' in RFC bis anymore */
        nad_set_attr ( pkt->nad, elem, -1, "ask", "unsubscribe", 11 );
    }

    if ( item->name != NULL ) {
        nad_set_attr ( pkt->nad, elem, -1, "name", item->name, 0 );
    }

    for ( i = 0; i < item->ngroups; i++ ) {
        nad_insert_elem ( pkt->nad, elem, NAD_ENS ( pkt->nad, elem ), "group", item->groups[i] );
    }
}

/** push this packet to all sessions except the given one */
static int _rostercustom_push ( user_t user, pkt_t pkt, int mod_index )
{
    sess_t scan;
    pkt_t push;
    int pushes = 0;

    /* do the push */
    for ( scan = user->sessions; scan != NULL; scan = scan->next ) {
        /* don't push to us or to anyone who hasn't loaded the roster */
        if ( scan->module_data[mod_index] == NULL ) {
            continue;
        }

        push = pkt_dup ( pkt, jid_full ( scan->jid ), NULL );
        pkt_sess ( push, scan );
        pushes++;
    }

    /* return the pushed packets count */
    return pushes;
}

static void _rostercustom_save_item ( mod_rostercustom_t mrostercustom, user_t user, item_t item )
{	
#if ROSTERCUSTOM_DEBUG
	if(	mrostercustom->symmetrical && item->to != item->from)
	{
		rostercustom_debug ( ZONE, "Error, symmetrical mode, but to=%d and from=%d", item->to, item->from );
	}
	
	if(item->name != NULL) {
		rostercustom_debug ( ZONE, "[roster of %s] save contact: %s (name=%s, to=%d, from=%d, ask=%d)", user->jid->node, item->jid->node, item->name, item->to, item->from, item->ask );
	} else {
		rostercustom_debug ( ZONE, "[roster of %s] save contact: %s (to=%d, from=%d, ask=%d)", user->jid->node, item->jid->node, item->to, item->from, item->ask );
	}
#endif

    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_SET ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_SET );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	user->jid->node,	strlen ( user->jid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	user->jid->domain,	strlen ( user->jid->domain ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom, 	item->jid->node,	strlen ( item->jid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	item->jid->domain,	strlen ( item->jid->domain ) );
        if ( item->name != NULL ) {
            _rostercustom_statementcall_addparamstring ( mrostercustom,	item->name,		strlen ( item->name ) );
        } else {
            _rostercustom_statementcall_addparamstring ( mrostercustom,	"",			0 );
        }
        _rostercustom_statementcall_addparamint ( mrostercustom, 	item->to );
        _rostercustom_statementcall_addparamint ( mrostercustom,	item->from );
        _rostercustom_statementcall_addparamint ( mrostercustom,	item->ask );
        _rostercustom_statementcall_addparamint ( mrostercustom,	item->ver );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }
}

static mod_ret_t _rostercustom_in_sess_s10n ( mod_instance_t mi, sess_t sess, pkt_t pkt )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    module_t mod = mi->mod;
    item_t item;
    pkt_t push;
    int ns, elem;

    rostercustom_debug ( ZONE, "got s10n packet" );

    /* s10ns have to go to someone */
    if ( pkt->to == NULL ) {
        return -stanza_err_BAD_REQUEST;
    }

    /* add a proper from address (no resource) */
    if ( pkt->from != NULL ) {
        jid_free ( pkt->from );
    }

    pkt->from = jid_new ( jid_user ( sess->jid ), -1 );
    nad_set_attr ( pkt->nad, 1, -1, "from", jid_full ( pkt->from ), 0 );

    /* see if they're already on the roster */
    item = xhash_get ( sess->user->roster, jid_full ( pkt->to ) );
    if ( item == NULL ) {
        /* if they're not on the roster, there's no subscription,
         * so quietly pass it on */
        if ( pkt->type == pkt_S10N_UN || pkt->type == pkt_S10N_UNED ) {
            return mod_PASS;
        }

        /* check if user exceedes maximum roster items */
        if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_GET_CANADD ) ) {
            _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_GET_CANADD );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->node, strlen ( sess->user->jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->domain, strlen ( sess->user->jid->domain ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, pkt->to->node, strlen ( pkt->to->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, pkt->to->domain, strlen ( pkt->to->domain ) );
            _rostercustom_statementcall_execute ( mrostercustom );
            if ( _rostercustom_statementcall_getnextrow ( mrostercustom ) != 0 ||
                    * ( ( unsigned char* ) mrostercustom->results[0].buffer ) == 0 ) {
                _rostercustom_statementcall_end ( mrostercustom );
                return -stanza_err_NOT_ACCEPTABLE;
            }
            _rostercustom_statementcall_end ( mrostercustom );
        }


        /* make a new one */
        item = ( item_t ) calloc ( 1, sizeof ( struct item_st ) );

        item->jid = jid_dup ( pkt->to );

        /* remember it */
        xhash_put ( sess->user->roster, jid_full ( item->jid ), ( void * ) item );
		
        /* add item to database */
        if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_ADD ) ) {
            _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_ADD );
            _rostercustom_statementcall_addparamstring ( mrostercustom,	sess->user->jid->node,		strlen ( sess->user->jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom,	sess->user->jid->domain,	strlen ( sess->user->jid->domain ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom,	item->jid->node,		strlen ( item->jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom,	item->jid->domain,		strlen ( item->jid->domain ) );
            _rostercustom_statementcall_execute ( mrostercustom );
            _rostercustom_statementcall_end ( mrostercustom );
        }

        rostercustom_debug ( ZONE, "made new empty roster item for %s", jid_full ( item->jid ) );
    }

    /* a request */
    if ( pkt->type == pkt_S10N && ! item->to ) {
        item->ask = 1;
    } else if ( pkt->type == pkt_S10N_UN && item->to ) {
        item->ask = 2;
    }

    /* changing states */
    else if ( pkt->type == pkt_S10N_ED ) {
        /* they're allowed to see us, send them presence */
        item->from = 1;
        if ( mrostercustom->symmetrical ) {
            item->to = 1;
            item->ask = 0;
        }
        pres_roster ( sess, item );
    } else if ( pkt->type == pkt_S10N_UNED ) {
        /* they're not allowed to see us anymore */
        item->from = 0;
        if ( mrostercustom->symmetrical ) {
            item->to = 0;
            item->ask = 0;
        }
        pres_roster ( sess, item );
    }

    /* save changes */
    _rostercustom_save_item ( mrostercustom, sess->user, item );

    /* build a new packet to push out to everyone */
    push = pkt_create ( sess->user->sm, "iq", "set", NULL, NULL );
    pkt_id_new ( push );
    ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );
    elem = nad_append_elem ( push->nad, ns, "query", 3 );

    _rostercustom_insert_item ( push, item, elem );

    /* tell everyone */
    _rostercustom_push ( sess->user, push, mod->index );

    /* everyone knows */
    pkt_free ( push );

    /* pass it on */
    return mod_PASS;
}

/** build the iq:roster packet from the hash */
static void _rostercustom_get_walker ( const char *id, int idlen, void *val, void *arg )
{
    item_t item = ( item_t ) val;
    rostercustom_walker_t rw = ( rostercustom_walker_t ) arg;

    _rostercustom_insert_item ( rw->pkt, item, 2 );

    /* remember largest item version */
    if ( item->ver > rw->ver ) {
        rw->ver = item->ver;
    }
}

/** push roster XEP-0237 updates to client */
static void _rostercustom_update_walker ( const char *id, int idlen, void *val, void *arg )
{
    pkt_t push;
    char *buf;
    int elem, ns;
    item_t item = ( item_t ) val;
    rostercustom_walker_t rw = ( rostercustom_walker_t ) arg;

    /* skip unneded roster items */
    if ( item->ver <= rw->req_ver ) {
        return;
    }

    /* build a interim roster push packet */
    push = pkt_create ( rw->sess->user->sm, "iq", "set", NULL, NULL );
    pkt_id_new ( push );
    ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );
    elem = nad_append_elem ( push->nad, ns, "query", 3 );

    buf = ( char * ) malloc ( sizeof ( char ) * 128 );
    sprintf ( buf, "%d", item->ver );
    nad_set_attr ( push->nad, elem, -1, "ver", buf, 0 );
    free ( buf );

    _rostercustom_insert_item ( push, item, elem );

    pkt_sess ( push, rw->sess );
}

static void _rostercustom_group_set ( mod_rostercustom_t mrostercustom, jid_t userjid, jid_t itemjid, const char* group )
{    
    // add group to DB
    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_GROUPS_SET ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_GROUPS_SET );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	userjid->node,		strlen ( userjid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	userjid->domain,	strlen ( userjid->domain ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	itemjid->node,		strlen ( itemjid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	itemjid->domain,	strlen ( itemjid->domain ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	group,			strlen ( group ) );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }
}

static void _rostercustom_group_remove ( mod_rostercustom_t mrostercustom, jid_t userjid, jid_t itemjid, const char* group )
{    
    // remove group from DB
    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_GROUPS_REMOVE ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_GROUPS_REMOVE );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	userjid->node,		strlen ( userjid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	userjid->domain,	strlen ( userjid->domain ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	itemjid->node,		strlen ( itemjid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	itemjid->domain,	strlen ( itemjid->domain ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom,	group,			strlen ( group ) );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }
}

static int _rostercustom_set_item ( pkt_t pkt, int elem, sess_t sess, mod_instance_t mi )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    module_t mod = mi->mod;
    int attr, ns, i;
    jid_t jid;
    item_t item;
    pkt_t push;
    char filter[4096];
    int elemindex;
    const char* tempswapstr;

    /* extract the jid */
    attr = nad_find_attr ( pkt->nad, elem, -1, "jid", NULL );
    jid = jid_new ( NAD_AVAL ( pkt->nad, attr ), NAD_AVAL_L ( pkt->nad, attr ) );
    if ( jid == NULL ) {
        rostercustom_debug ( ZONE, "jid failed prep check, skipping" );
        return 1;
    }
    
    /* check for removals */
    if ( nad_find_attr ( pkt->nad, elem, -1, "subscription", "remove" ) >= 0 ) {
        /* trash the item */
        item = xhash_get ( sess->user->roster, jid_full ( jid ) );
        if ( item != NULL ) {
            /* tell them they're unsubscribed */
            if ( item->from ) {
                rostercustom_debug ( ZONE, "telling %s that they're unsubscribed", jid_user ( item->jid ) );
                pkt_router ( pkt_create ( sess->user->sm, "presence", "unsubscribed", jid_user ( item->jid ), jid_user ( sess->jid ) ) );
            }
            item->from = 0;

            /* tell them to unsubscribe us */
            if ( item->to ) {
                rostercustom_debug ( ZONE, "unsubscribing from %s", jid_user ( item->jid ) );
                pkt_router ( pkt_create ( sess->user->sm, "presence", "unsubscribe", jid_user ( item->jid ), jid_user ( sess->jid ) ) );
            }
            item->to = 0;

            /* send unavailable */
            pres_roster ( sess, item );

            /* kill it */
            xhash_zap ( sess->user->roster, jid_full ( jid ) );
            _rostercustom_freeuser_walker ( ( const char * ) jid_full ( jid ), strlen ( jid_full ( jid ) ), ( void * ) item, NULL );

            snprintf ( filter, 4096, "(jid=%zu:%s)", strlen ( jid_full ( jid ) ), jid_full ( jid ) );

            /* remove */
            if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_REMOVE ) ) {
                _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_REMOVE );
                _rostercustom_statementcall_addparamstring ( mrostercustom,	sess->user->jid->node,		strlen ( sess->user->jid->node ) );
                _rostercustom_statementcall_addparamstring ( mrostercustom,	sess->user->jid->domain,	strlen ( sess->user->jid->domain ) );
                _rostercustom_statementcall_addparamstring ( mrostercustom,	jid->node,			strlen ( jid->node ) );
                _rostercustom_statementcall_addparamstring ( mrostercustom,	jid->domain,			strlen ( jid->domain ) );
                _rostercustom_statementcall_execute ( mrostercustom );
                _rostercustom_statementcall_end ( mrostercustom );
            }
        }

        rostercustom_debug ( ZONE, "removed %s from roster", jid_full ( jid ) );

        /* build a new packet to push out to everyone */
        push = pkt_create ( sess->user->sm, "iq", "set", NULL, NULL );
        pkt_id_new ( push );
        ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );

        nad_append_elem ( push->nad, ns, "query", 3 );
        elem = nad_append_elem ( push->nad, ns, "item", 4 );
        nad_set_attr ( push->nad, elem, -1, "jid", jid_full ( jid ), 0 );
        nad_set_attr ( push->nad, elem, -1, "subscription", "remove", 6 );

        /* tell everyone */
        _rostercustom_push ( sess->user, push, mod->index );

        /* we're done */
        pkt_free ( push );

        jid_free ( jid );

        return 0;
    }

    /* find a pre-existing one */
    item = xhash_get ( sess->user->roster, jid_full ( jid ) );
    if ( item == NULL ) {
        /* check if user exceedes maximum roster items */
        if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_GET_CANADD ) ) {
            _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_GET_CANADD );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->node, strlen ( sess->user->jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->domain, strlen ( sess->user->jid->domain ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, jid->node, strlen ( jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, jid->domain, strlen ( jid->domain ) );
            _rostercustom_statementcall_execute ( mrostercustom );
            if ( _rostercustom_statementcall_getnextrow ( mrostercustom ) != 0 || * ( ( unsigned char* ) mrostercustom->results[0].buffer ) == 0 ) {
                /* if the limit is reached, skip it */
                _rostercustom_statementcall_end ( mrostercustom );
                return 1;
            }
            _rostercustom_statementcall_end ( mrostercustom );
        }

        /* make a new one */
        item = ( item_t ) calloc ( 1, sizeof ( struct item_st ) );

        /* add the jid */
        item->jid = jid;

        /* add it to the roster */
        xhash_put ( sess->user->roster, jid_full ( item->jid ), ( void * ) item );

        /* add item to database */
        if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_CONTACT_ADD ) ) {
            _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_CONTACT_ADD );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->node,	strlen ( sess->user->jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, sess->user->jid->domain,	strlen ( sess->user->jid->domain ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, jid->node,		strlen ( jid->node ) );
            _rostercustom_statementcall_addparamstring ( mrostercustom, jid->domain,		strlen ( jid->domain ) );
            _rostercustom_statementcall_execute ( mrostercustom );
            _rostercustom_statementcall_end ( mrostercustom );
        }

        rostercustom_debug ( ZONE, "created new roster item %s", jid_full ( item->jid ) );
    }

    else {
        jid_free ( jid );
    }

    /* extract the name */
    attr = nad_find_attr ( pkt->nad, elem, -1, "name", NULL );
    if ( attr >= 0 ) {
        /* free the old name */
        if ( item->name != NULL ) {
            free ( ( void* ) item->name );
            item->name = NULL;
        }

        if ( NAD_AVAL_L ( pkt->nad, attr ) > 0 ) {
            item->name = ( const char * ) malloc ( sizeof ( char ) * ( NAD_AVAL_L ( pkt->nad, attr ) + 1 ) );
            sprintf ( ( char * ) item->name, "%.*s", NAD_AVAL_L ( pkt->nad, attr ), NAD_AVAL ( pkt->nad, attr ) );
        }
    }

    elem = nad_find_elem ( pkt->nad, elem, NAD_ENS ( pkt->nad, elem ), "group", 1 );
    elemindex = 0;
    while ( elem >= 0 ) {
        /* empty group tags get skipped */
        if ( NAD_CDATA_L ( pkt->nad, elem ) >= 0 ) {
            if ( item->groups && item->ngroups > elemindex ) {
                // enough room in the array

                // check if the group is already here
                for ( i = elemindex; i < item->ngroups; i++ ) {
                    if ( strlen ( item->groups[i] ) != NAD_CDATA_L ( pkt->nad, elem ) || strncmp ( NAD_CDATA ( pkt->nad, elem ), item->groups[i], NAD_CDATA_L ( pkt->nad, elem ) ) == 0 ) {
                        break;
                    }
                }

                if ( i < item->ngroups ) {
                    // the group exist in the array, we swap and do nothing more
                    tempswapstr = item->groups[i];
                    item->groups[i] = item->groups[elemindex];
                    item->groups[elemindex] = tempswapstr;
                } else {
                    _rostercustom_group_remove ( mrostercustom, sess->user->jid, item->jid, item->groups[elemindex] );

                    item->groups[elemindex] = ( const char * ) realloc ( ( void* ) item->groups[elemindex], sizeof ( char ) * ( NAD_CDATA_L ( pkt->nad, elem ) + 1 ) );
                    sprintf ( ( char * ) ( item->groups[elemindex] ), "%.*s", NAD_CDATA_L ( pkt->nad, elem ), NAD_CDATA ( pkt->nad, elem ) );

                    _rostercustom_group_set ( mrostercustom, sess->user->jid, item->jid, item->groups[elemindex] );

                }
            } else {
                // makes room
                item->groups = ( const char ** ) realloc ( item->groups, sizeof ( char * ) * ( item->ngroups + 1 ) );
                item->ngroups++;
                // copy the group name
                item->groups[elemindex] = ( const char * ) malloc ( sizeof ( char ) * ( NAD_CDATA_L ( pkt->nad, elem ) + 1 ) );
                sprintf ( ( char * ) ( item->groups[elemindex] ), "%.*s", NAD_CDATA_L ( pkt->nad, elem ), NAD_CDATA ( pkt->nad, elem ) );

                _rostercustom_group_set ( mrostercustom, sess->user->jid, item->jid, item->groups[elemindex] );
            }
            elemindex++;
        }
        elem = nad_find_elem ( pkt->nad, elem, NAD_ENS ( pkt->nad, elem ), "group", 0 );
    }

    /* free the old groups */
    if ( item->ngroups > elemindex ) {
        for ( i = elemindex; i < item->ngroups; i++ ) {

            _rostercustom_group_remove ( mrostercustom, sess->user->jid, item->jid, item->groups[i] );

            free ( ( void* ) item->groups[i] );
        }

        if ( elemindex == 0 ) {
            free ( item->groups );
            item->groups = 0;
        } else {
            item->groups = ( const char ** ) realloc ( item->groups, sizeof ( char * ) * elemindex );
        }
    }
    item->ngroups = elemindex;

    rostercustom_debug ( ZONE, "updated roster item %s (to %d from %d ask %d name %s ngroups %d)", jid_full ( item->jid ), item->to, item->from, item->ask, ( item->name != NULL ) ? item->name : "", item->ngroups );

    /* save changes */
    _rostercustom_save_item ( mrostercustom, sess->user, item );

    /* build a new packet to push out to everyone */
    push = pkt_create ( sess->user->sm, "iq", "set", NULL, NULL );
    pkt_id_new ( push );
    ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );
    elem = nad_append_elem ( push->nad, ns, "query", 3 );

    _rostercustom_insert_item ( push, item, elem );

    /* tell everyone */
    _rostercustom_push ( sess->user, push, mod->index );

    /* we're done */
    pkt_free ( push );
	
	return 0;
}

static jid_t _rostercustom_newjid ( const char* node, int nodelen, const char*domain, int domainlen )
{
    jid_t jid;
    if ( !nodelen || !domainlen ) {
        return NULL;
    }

    jid = malloc ( sizeof ( struct jid_st ) );
    memset ( jid, 0, sizeof ( struct jid_st ) );

    jid->jid_data_len = nodelen + 1 + domainlen + 1;
    jid->jid_data = malloc ( jid->jid_data_len );

    memcpy ( jid->jid_data, node, nodelen );
    jid->jid_data[nodelen] = '\0';
    memcpy ( &jid->jid_data[nodelen+1], domain, domainlen );
    jid->jid_data[nodelen+1+domainlen] = '\0';

    jid->node = jid->jid_data;
    jid->domain = jid->jid_data + nodelen + 1;
    jid->resource = "";
    jid->dirty = 1;

    return jid;
}

static void _rostercustom_apply_db_changes ( mod_instance_t mi )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    item_t item;
    user_t user;
    jid_t jiduser, jidcontact;
    int itemhaschanged;
    int strlength;
    int ns, elem;
    const char *str;
    char *newstr;
    long int newfrom, newto, newask, newver, deleting;
    pkt_t push;
	
    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_ISSYNCREQUIRED ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_ISSYNCREQUIRED );
        _rostercustom_statementcall_execute ( mrostercustom );
        if ( _rostercustom_statementcall_getnextrow ( mrostercustom ) != 0 ||
                * ( ( unsigned char* ) mrostercustom->results[0].buffer ) == 0 ) {
            _rostercustom_statementcall_end ( mrostercustom );
            return;
        }
        _rostercustom_statementcall_end ( mrostercustom );
    }

    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_PRESYNC ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_PRESYNC );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }

    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_SYNC ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_SYNC );
        _rostercustom_statementcall_execute ( mrostercustom );
        while ( _rostercustom_statementcall_getnextrow ( mrostercustom ) == 0 ) {

            if ( !mrostercustom->results_length[0] || !mrostercustom->results_length[1] ) {
                rostercustom_debug ( ZONE, "invalid user jid skipping item" );
                continue;
            }

            if ( !mrostercustom->results_length[2] || !mrostercustom->results_length[3] ) {
                rostercustom_debug ( ZONE, "invalid contact jid skipping item" );
                continue;
            }


            jiduser = _rostercustom_newjid ( mrostercustom->results_buffers[0], mrostercustom->results_length[0], mrostercustom->results_buffers[1], mrostercustom->results_length[1] );

            /* get the user _without_ doing a load */
            user = xhash_get ( mi->sm->users, jid_user ( jiduser ) );

            jid_free ( jiduser );

            /* no user = nothing to do */
            if ( user == NULL ) {
                continue;
            }

            jidcontact = _rostercustom_newjid ( mrostercustom->results_buffers[2], mrostercustom->results_length[2], mrostercustom->results_buffers[3], mrostercustom->results_length[3] );

            deleting = _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[9], mrostercustom->results_length[9] );


            /* get the contact */
            item = xhash_get ( user->roster, jid_full ( jidcontact ) );

            if ( deleting ) {
                if ( item ) {
                    xhash_zap ( user->roster, jid_full ( jidcontact ) );
                    _rostercustom_freeuser_walker ( jid_full ( jidcontact ), strlen ( jid_full ( jidcontact ) ), ( void * ) item, NULL );

                    /* build a new packet to push out to everyone */
                    push = pkt_create ( user->sm, "iq", "set", NULL, NULL );
                    pkt_id_new ( push );
                    ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );

                    nad_append_elem ( push->nad, ns, "query", 3 );
                    elem = nad_append_elem ( push->nad, ns, "item", 4 );
                    nad_set_attr ( push->nad, elem, -1, "jid", jid_full ( jidcontact ), 0 );
                    nad_set_attr ( push->nad, elem, -1, "subscription", "remove", 6 );

                    /* tell everyone */
                    _rostercustom_push ( user, push, mi->mod->index );

                    /* we're done */
                    pkt_free ( push );
                }

                jid_free ( jidcontact );
            } else {
                itemhaschanged = 0;
                if ( !item ) {
                    /* new one */
                    item = ( item_t ) calloc ( 1, sizeof ( struct item_st ) );
                    item->jid = jidcontact;

                    xhash_put ( user->roster, jid_full ( jidcontact ), ( void * ) item );
                } else {
                    jid_free ( jidcontact );
                }


                strlength = mrostercustom->results_length[4];
                str = mrostercustom->results_buffers[4];
                if ( !item->name || strlength != strlen ( item->name ) || strncmp ( item->name, str, strlength ) != 0 ) {
                    free ( ( void* ) item->name );
                    itemhaschanged = 1;
                    newstr = malloc ( strlength + 1 );
                    memcpy ( newstr, str, strlength );
                    newstr[strlength] = '\0';
                    item->name = newstr;
                }

                newto = _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[5], mrostercustom->results_length[5] );
                newfrom = _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[6], mrostercustom->results_length[6] );
                newask = _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[7], mrostercustom->results_length[7] );
                newver = _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[8], mrostercustom->results_length[8] );
                if ( item->to != newto || item->from != newfrom || item->ask != newask || item->ver != newver ) {
                    itemhaschanged = 1;
                    item->to = newto;
                    item->from = newfrom;
                    item->ask = newask;
                    item->ver = newver;
                }

                if ( itemhaschanged ) {

                    /* build a new packet to push out to everyone */
                    push = pkt_create ( user->sm, "iq", "set", NULL, NULL );
                    pkt_id_new ( push );
                    ns = nad_add_namespace ( push->nad, uri_ROSTER, NULL );
                    elem = nad_append_elem ( push->nad, ns, "query", 3 );

                    _rostercustom_insert_item ( push, item, elem );

                    /* tell everyone */
                    _rostercustom_push ( user, push, mi->mod->index );

                    /* we're done */
                    pkt_free ( push );
                }
            }
        }
        _rostercustom_statementcall_end ( mrostercustom );
    }

    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_POSTSYNC ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_POSTSYNC );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }


}

/** our main handler for router packets */
static mod_ret_t _rostercustom_in_router ( mod_instance_t mi, pkt_t pkt )
{
    /* check for the special update packet*/
    if ( ( pkt->type & pkt_IQ ) &&
            ( nad_find_namespace ( pkt->nad, 2, uri_ROSTERCUSTOM_APPLYDBCHANGES, NULL ) >= 0 ) ) {

        _rostercustom_apply_db_changes ( mi );

        pkt_free ( pkt );

        return mod_HANDLED;
    } else {

        return mod_PASS;
    }
}

/** our main handler for packets arriving from a session */
static mod_ret_t _rostercustom_in_sess ( mod_instance_t mi, sess_t sess, pkt_t pkt )
{
    module_t mod = mi->mod;
    int elem, attr, ver = 0;
    pkt_t result;
    char *buf;
    rostercustom_walker_t rw;

    /* handle s10ns in a different function */
    if ( pkt->type & pkt_S10N ) {
        return _rostercustom_in_sess_s10n ( mi, sess, pkt );
    }

    /* we only want to play with iq:roster packets */
    if ( pkt->ns != ns_ROSTER ) {
        return mod_PASS;
    }

    /* quietly drop results, its probably them responding to a push */
    if ( pkt->type == pkt_IQ_RESULT ) {
        pkt_free ( pkt );
        return mod_HANDLED;
    }

    /* need gets or sets */
    if ( pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET ) {
        return mod_PASS;
    }

    /* get */
    if ( pkt->type == pkt_IQ ) {
        /* check for "XEP-0237: Roster Versioning request" */
        if ( ( elem = nad_find_elem ( pkt->nad, 1, -1, "query", 1 ) ) >= 0
                && ( attr = nad_find_attr ( pkt->nad, elem, -1, "ver", NULL ) ) >= 0 ) {
            if ( NAD_AVAL_L ( pkt->nad, attr ) > 0 ) {
                buf = ( char * ) malloc ( sizeof ( char ) * ( NAD_AVAL_L ( pkt->nad, attr ) + 1 ) );
                sprintf ( buf, "%.*s", NAD_AVAL_L ( pkt->nad, attr ), NAD_AVAL ( pkt->nad, attr ) );
                ver = j_atoi ( buf, 0 );
                free ( buf );
            }
        }

        /* build the packet */
        rw = ( rostercustom_walker_t ) calloc ( 1, sizeof ( struct _rostercustom_walker_st ) );
        rw->pkt = pkt;
        rw->req_ver = ver;
        rw->sess = sess;

        nad_set_attr ( pkt->nad, 1, -1, "type", "result", 6 );

        if ( ver > 0 ) {
            /* send XEP-0237 empty result */
            nad_drop_elem ( pkt->nad, elem );
            pkt_sess ( pkt_tofrom ( pkt ), sess );
            xhash_walk ( sess->user->roster, _rostercustom_update_walker, ( void * ) rw );
        } else {
            xhash_walk ( sess->user->roster, _rostercustom_get_walker, ( void * ) rw );
            if ( elem >= 0 && attr >= 0 ) {
                buf = ( char * ) malloc ( sizeof ( char ) * 128 );
                sprintf ( buf, "%d", rw->ver );
                nad_set_attr ( pkt->nad, elem, -1, "ver", buf, 0 );
                free ( buf );
            }
            pkt_sess ( pkt_tofrom ( pkt ), sess );
        }

        free ( rw );

        /* remember that they loaded it, so we know to push updates to them */
        sess->module_data[mod->index] = ( void * ) 1;

        return mod_HANDLED;
    }

    /* set, find the item */
    elem = nad_find_elem ( pkt->nad, 2, NAD_ENS ( pkt->nad, 2 ), "item", 1 );
    if ( elem < 0 )
        /* no item, abort */
    {
        return -stanza_err_BAD_REQUEST;
    }

    /* loop over items and stick them in */
    while ( elem >= 0 ) {
        /* extract the jid */
        attr = nad_find_attr ( pkt->nad, elem, -1, "jid", NULL );
        if ( attr < 0 || NAD_AVAL_L ( pkt->nad, attr ) == 0 ) {
            rostercustom_debug ( ZONE, "no jid on this item, aborting" );

            /* no jid, abort */
            return -stanza_err_BAD_REQUEST;
        }

        /* utility */
        if( _rostercustom_set_item ( pkt, elem, sess, mi ) )
		{
            /* not enough room */
            return -stanza_err_NOT_ACCEPTABLE;
		}

        /* next one */
        elem = nad_find_elem ( pkt->nad, elem, NAD_ENS ( pkt->nad, elem ), "item", 0 );
    }

    /* send the result */
    result = pkt_create ( sess->user->sm, "iq", "result", NULL, NULL );

    pkt_id ( pkt, result );

    /* tell them */
    pkt_sess ( result, sess );

    /* free the request */
    pkt_free ( pkt );

    return mod_HANDLED;
}

/** handle incoming s10ns */
static mod_ret_t _rostercustom_pkt_user ( mod_instance_t mi, user_t user, pkt_t pkt )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    module_t mod = mi->mod;
    item_t item;
    int ns, elem;


    /* only want s10ns */
    if ( ! ( pkt->type & pkt_S10N ) ) {
        return mod_PASS;
    }

    /* drop route errors */
    if ( pkt->rtype & route_ERROR ) {
        pkt_free ( pkt );
        return mod_HANDLED;
    }

    /* get the roster item */
    item = ( item_t ) xhash_get ( user->roster, jid_full ( pkt->from ) );
    if ( item == NULL ) {
        /* subs are handled by the client */
        if ( pkt->type == pkt_S10N ) {
            /* if the user is online broadcast it like roster push */
            if ( user->top != NULL && _rostercustom_push ( user, pkt, mod->index ) > 0 ) {
                /* pushed, thus handled */
                pkt_free ( pkt );
                return mod_HANDLED;
            } else {
                /* not pushed to any online resource - pass it on (to mod_offline) */
                return mod_PASS;
            }
        }

        /* other S10Ns: we didn't ask for this, so we don't care */
        pkt_free ( pkt );
        return mod_HANDLED;
    }

    /* ignore bogus answers */
    if ( ( pkt->type == pkt_S10N_ED && ( item->ask != 1 || item->to ) )
            || ( pkt->type == pkt_S10N_UNED && ! item->to ) ) {
        /* remove pending ask */
        if ( ( pkt->type == pkt_S10N_ED && item->ask == 1 )
                || ( pkt->type == pkt_S10N_UNED && item->ask == 2 ) ) {
            if ( item->ask ) {
                item->ask = 0;
                /* save changes */
                _rostercustom_save_item ( mrostercustom, user, item );
            }
        }

        pkt_free ( pkt );
        return mod_HANDLED;
    }

    /* trying to subscribe */
    if ( pkt->type == pkt_S10N ) {
        if ( item->from ) {
            /* already subscribed, tell them */
            nad_set_attr ( pkt->nad, 1, -1, "type", "subscribed", 10 );
            pkt_router ( pkt_tofrom ( pkt ) );

            /* update their presence from the leading session */
            if ( user->top != NULL ) {
                pres_roster ( user->top, item );
            }

            return mod_HANDLED;
        }

        return mod_PASS;
    }

    /* handle unsubscribe */
    else if ( pkt->type == pkt_S10N_UN ) {
        if ( !item->from ) {
            /* already unsubscribed, tell them */
            nad_set_attr ( pkt->nad, 1, -1, "type", "unsubscribed", 12 );
            pkt_router ( pkt_tofrom ( pkt ) );

            return mod_HANDLED;
        }

        /* change state */
        item->from = 0;

        if ( mrostercustom->symmetrical ) {
            item->to = 0;
        }

        /* confirm unsubscription */
        pkt_router ( pkt_create ( user->sm, "presence", "unsubscribed", jid_user ( pkt->from ), jid_user ( user->jid ) ) );

        /* update their presence from the leading session */
        if ( user->top != NULL ) {
            pres_roster ( user->top, item );
        }
    }

    /* update our s10n */
    else if ( pkt->type == pkt_S10N_ED ) {
        item->to = 1;

        if ( mrostercustom->symmetrical ) {
            item->from = 1;
        }

        if ( item->ask == 1 ) {
            item->ask = 0;
        }
    }
    if ( pkt->type == pkt_S10N_UNED ) {
        item->to = 0;

        if ( mrostercustom->symmetrical ) {
            item->from = 0;
        }

        if ( item->ask == 2 ) {
            item->ask = 0;
        }
    }

    /* save changes */
    _rostercustom_save_item ( mrostercustom, user, item );

    /* if there's no sessions, then we're done */
    if ( user->sessions == NULL ) {
        return mod_PASS;
    }

    /* build a new packet to push out to everyone */
    pkt = pkt_create ( user->sm, "iq", "set", NULL, NULL );
    pkt_id_new ( pkt );
    ns = nad_add_namespace ( pkt->nad, uri_ROSTER, NULL );
    elem = nad_append_elem ( pkt->nad, ns, "query", 3 );

    _rostercustom_insert_item ( pkt, item, elem );

    /* tell everyone */
    _rostercustom_push ( user, pkt, mod->index );

    /* everyone knows */
    pkt_free ( pkt );

    return mod_PASS;
}

/** load the roster from the database */
static int _rostercustom_user_load ( mod_instance_t mi, user_t user )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    char *str;
    unsigned int strlength;
    item_t item, olditem;
    char staticstr[MAXLEN_JID];

    rostercustom_debug ( ZONE, "loading roster for %s", jid_user ( user->jid ) );

    user->roster = xhash_new ( 101 );
    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_USER_LOAD_ITEMS ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_USER_LOAD_ITEMS );
        _rostercustom_statementcall_addparamstring ( mrostercustom, user->jid->node, strlen ( user->jid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom, user->jid->domain, strlen ( user->jid->domain ) );
        _rostercustom_statementcall_execute ( mrostercustom );
        while ( _rostercustom_statementcall_getnextrow ( mrostercustom ) == 0 ) {
            /* new one */

            if ( !mrostercustom->results_length[0] || !mrostercustom->results_length[1] ) {
                rostercustom_debug ( ZONE, "invalid jid. skipping it" );
                continue;
            }

            item = ( item_t ) calloc ( 1, sizeof ( struct item_st ) );

            item->jid = _rostercustom_newjid ( mrostercustom->results_buffers[0], mrostercustom->results_length[0], mrostercustom->results_buffers[1], mrostercustom->results_length[1] );

            if ( !item->jid ) {
                rostercustom_debug ( ZONE, "invalid jid. skipping it" );
                free ( item );
                continue;
            }

            strlength = mrostercustom->results_length[2];
            if ( strlength > 0 ) {
                str = malloc ( strlength + 1 );
                memcpy ( str, mrostercustom->results_buffers[2], strlength );
                str[strlength] = '\0';
                item->name = str;
            }

            item->to	= _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[3], mrostercustom->results_length[3] );
            item->from	= _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[4], mrostercustom->results_length[4] );
            item->ask	= _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[5], mrostercustom->results_length[5] );
            item->ver	= _rostercustom_mysql_getintegerval ( mrostercustom->results_buffers[6], mrostercustom->results_length[6] );

            olditem = xhash_get ( user->roster, jid_full ( item->jid ) );
            if ( olditem ) {
                rostercustom_debug ( ZONE, "removing old %s roster entry", jid_full ( item->jid ) );
                xhash_zap ( user->roster, jid_full ( item->jid ) );
                _rostercustom_freeuser_walker ( jid_full ( item->jid ), strlen ( jid_full ( item->jid ) ), ( void * ) olditem, NULL );
            }

            /* its good */
            xhash_put ( user->roster, jid_full ( item->jid ), ( void * ) item );

            rostercustom_debug ( ZONE, "added %s to roster (to %d from %d ask %d ver %d name %s)",
                        jid_full ( item->jid ), item->to, item->from, item->ask, item->ver, ( item->name != NULL ) ? item->name : "" );

        }
        _rostercustom_statementcall_end ( mrostercustom );
    }


    /* pull the groups and match them up */
    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_USER_LOAD_GROUPS ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_USER_LOAD_GROUPS );
        _rostercustom_statementcall_addparamstring ( mrostercustom, user->jid->node, strlen ( user->jid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom, user->jid->domain, strlen ( user->jid->domain ) );
        _rostercustom_statementcall_execute ( mrostercustom );
        while ( _rostercustom_statementcall_getnextrow ( mrostercustom ) == 0 ) {

            memcpy ( staticstr, mrostercustom->results_buffers[0], mrostercustom->results_length[0] );
            staticstr[mrostercustom->results_length[0]] = '@';
            memcpy ( staticstr+mrostercustom->results_length[0]+1, mrostercustom->results_buffers[1], mrostercustom->results_length[1] );
            staticstr[mrostercustom->results_length[0] + 1 + mrostercustom->results_length[1] ] = '\0';

            item = xhash_getx ( user->roster, staticstr, mrostercustom->results_length[0] + 1 + mrostercustom->results_length[1] );

            strlength = mrostercustom->results_length[2];
            if ( item != NULL && strlength > 0 ) {
                item->groups = realloc ( item->groups, sizeof ( char * ) * ( item->ngroups + 1 ) );
                str = malloc ( strlength + 1 );
                memcpy ( str, mrostercustom->results_buffers[2], strlength );
                str[strlength] = '\0';
                item->groups[item->ngroups] = str;

                item->ngroups++;

                rostercustom_debug ( ZONE, "added group %s to item %s", str, jid_full ( item->jid ) );
            }
        }
        _rostercustom_statementcall_end ( mrostercustom );
    }

    pool_cleanup ( user->p, ( void ( * ) ) ( void * ) _rostercustom_freeuser, user );

    return 0;
}

static void _rostercustom_user_delete ( mod_instance_t mi, jid_t jid )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mi->mod->private;
    rostercustom_debug ( ZONE, "deleting roster data for %s", jid_user ( jid ) );

    if ( _rostercustom_statementcall_ispossible ( mrostercustom, ERostercustom_Statement_USER_DELETE ) ) {
        _rostercustom_statementcall_begin ( mrostercustom, ERostercustom_Statement_USER_DELETE );
        _rostercustom_statementcall_addparamstring ( mrostercustom, jid->node, strlen ( jid->node ) );
        _rostercustom_statementcall_addparamstring ( mrostercustom, jid->domain, strlen ( jid->domain ) );
        _rostercustom_statementcall_execute ( mrostercustom );
        _rostercustom_statementcall_end ( mrostercustom );
    }
}

static void _rostercustom_free ( module_t mod )
{
    mod_rostercustom_t mrostercustom = ( mod_rostercustom_t ) mod->private;
    unsigned int substatementcount;
    unsigned int i;
    unsigned int j;

    rostercustom_debug(ZONE, "module freeing" );
	
	if(mrostercustom->conn)
	{
		for ( i = 0; i < ERostercustom_Statement_Count; i++ ) {
			substatementcount = mrostercustom->preparedstatements_substatementscount[i];
			for ( j = 0; j < substatementcount; j++ ) {
				mysql_stmt_close ( mrostercustom->preparedstatements_substatements[i][j] );
			}
		}
		mysql_close ( mrostercustom->conn );
		mrostercustom->conn = 0;
	}
    free ( mrostercustom );
}

DLLEXPORT int module_init ( mod_instance_t mi, const char *arg )
{
    char configitem[256];
    module_t mod = mi->mod;
    mod_rostercustom_t mrostercustom;

    if ( mod->init ) {
        return 0;
    }

    rostercustom_debug(ZONE, "module init" );
	
    mrostercustom = ( mod_rostercustom_t ) calloc ( 1, sizeof ( struct _mod_rostercustom_st ) );

    mrostercustom->host		= config_get_one ( mod->mm->sm->config, "rostercustom.host", 0 );
    mrostercustom->port		= j_atoi ( config_get_one ( mod->mm->sm->config, "rostercustom.port", 0 ), 0 );
    mrostercustom->user		= config_get_one ( mod->mm->sm->config, "rostercustom.user", 0 );
    mrostercustom->password	= config_get_one ( mod->mm->sm->config, "rostercustom.pass", 0 );
    mrostercustom->dbname		= config_get_one ( mod->mm->sm->config, "rostercustom.dbname", 0 );
    mrostercustom->symmetrical	= j_atoi ( config_get_one ( mod->mm->sm->config, "rostercustom.symmetrical", 0 ), 0 );
	mrostercustom->connectionlog = mi->sm->log;

    unsigned int i;
    for ( i = 0; i < ERostercustom_Statement_Count; i++ ) {
        snprintf ( configitem, 256, "rostercustom.%s", _rostercustom_preparedstatements_names[i] );
        mrostercustom->preparedstatementstext[i] = config_get_one ( mod->mm->sm->config, configitem, 0 );
    }

    mrostercustom->conn = NULL;

    mod->private = mrostercustom;

	if( _rostercustom_connect(mrostercustom) ) {
		return 1;
	}
	
    mod->in_sess = _rostercustom_in_sess;
    mod->in_router = _rostercustom_in_router;
    mod->pkt_user = _rostercustom_pkt_user;
    mod->user_load = _rostercustom_user_load;
    mod->user_delete = _rostercustom_user_delete;
    mod->free = _rostercustom_free;

    feature_register ( mod->mm->sm, uri_ROSTER );


    return 0;
}
