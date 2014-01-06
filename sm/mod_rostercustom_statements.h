//				CodeName		TextName			MaxParamCount		Results		  

MRostercustomStatement(		USER_LOAD_ITEMS,	"user_loaditems",		2, 			MRostercustom6Results(String, String, Integer, Integer, Integer, Integer) )
MRostercustomStatement(		USER_LOAD_GROUPS,	"user_loadgroups",		2, 			MRostercustom2Results(String, String) )
MRostercustomStatement(		USER_DELETE,		"user_delete",			2, 			MRostercustomNoResult() )

MRostercustomStatement(		CONTACT_ADD,		"contact_add",			3, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_SET,		"contact_set",			8, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_REMOVE,		"contact_remove",		3, 			MRostercustomNoResult() )

MRostercustomStatement(		CONTACT_GET_CANADD,	"contact_get_canadd",		2,			MRostercustom1Result(Integer) )

MRostercustomStatement(		CONTACT_GROUPS_SET,	"contact_groups_set",		4, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_GROUPS_REMOVE,	"contact_groups_remove",	4, 			MRostercustomNoResult() )


MRostercustomStatement(		PRESYNC,		"presync",			2, 			MRostercustomNoResult() )
MRostercustomStatement(		SYNC,			"sync",				2, 			MRostercustom7Results(String, String, Integer, Integer, Integer, Integer, Integer) )
MRostercustomStatement(		POSTSYNC,		"postsync",			2, 			MRostercustomNoResult() )


