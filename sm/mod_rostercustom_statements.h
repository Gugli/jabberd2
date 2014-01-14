//				CodeName		TextName			MaxParamCount		Results		  

MRostercustomStatement(		USER_LOAD_ITEMS,	"user_loaditems",		2, 			MRostercustom7Results(String, String, String, Integer, Integer, Integer, Integer) )
MRostercustomStatement(		USER_LOAD_GROUPS,	"user_loadgroups",		2, 			MRostercustom3Results(String, String, String) )
MRostercustomStatement(		USER_DELETE,		"user_delete",			2, 			MRostercustomNoResult() )

MRostercustomStatement(		CONTACT_ADD,		"contact_add",			4, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_SET,		"contact_set",			9, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_REMOVE,		"contact_remove",		4, 			MRostercustomNoResult() )

MRostercustomStatement(		CONTACT_GET_CANADD,	"contact_get_canadd",		4,			MRostercustom1Result(Integer) )

MRostercustomStatement(		CONTACT_GROUPS_SET,	"contact_groups_set",		5, 			MRostercustomNoResult() )
MRostercustomStatement(		CONTACT_GROUPS_REMOVE,	"contact_groups_remove",	5, 			MRostercustomNoResult() )


MRostercustomStatement(		ISSYNCREQUIRED,		"issyncrequired",		0, 			MRostercustom1Result(Integer) )
MRostercustomStatement(		PRESYNC,		"presync",			0, 			MRostercustomNoResult() )
MRostercustomStatement(		SYNC,			"sync",				0, 			MRostercustom10Results(String, String, String, String, String, Integer, Integer, Integer, Integer, Integer) )
MRostercustomStatement(		POSTSYNC,		"postsync",			0, 			MRostercustomNoResult() )


