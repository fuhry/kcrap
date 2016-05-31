/* Excerpted from MIT KerberosV 1.4.4 & 1.6.3 */

/*
 * include/krb5/kdb.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * KDC Database interface definitions.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "../config.h"

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL	0
#define KRB5_KDB_SALTTYPE_V4		1
#define KRB5_KDB_SALTTYPE_NOREALM	2
#define KRB5_KDB_SALTTYPE_ONLYREALM	3
#define KRB5_KDB_SALTTYPE_SPECIAL	4
#define KRB5_KDB_SALTTYPE_AFS3		5

#define KRB5_KDB_M_NAME		"K/M"	/* Kerberos/Master */

#define KRB5_KDB_OPEN_RW                0
#define KRB5_KDB_OPEN_RO                1

#ifndef KRB5_KDB_SRV_TYPE_KDC
#define KRB5_KDB_SRV_TYPE_KDC           0x0100        
#endif

#ifndef KRB5_KDB_SRV_TYPE_ADMIN
#define KRB5_KDB_SRV_TYPE_ADMIN         0x0200  
#endif

#ifndef KRB5_KDB_SRV_TYPE_PASSWD
#define KRB5_KDB_SRV_TYPE_PASSWD        0x0300
#endif

#ifndef KRB5_KDB_SRV_TYPE_OTHER
#define KRB5_KDB_SRV_TYPE_OTHER         0x0400  
#endif



#ifdef HAVE_KRB5_DB_OPEN
/* 1.6.3 */

typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;		/* NOT saved */
    krb5_int16 		  tl_data_type;		
    krb5_ui_2		  tl_data_length;	
    krb5_octet 	        * tl_data_contents;	
} krb5_tl_data;

typedef struct _krb5_key_data {
    krb5_int16 		  key_data_ver;		/* Version */
    krb5_int16		  key_data_kvno;	/* Key Version */
    krb5_int16		  key_data_type[2];	/* Array of types */
    krb5_ui_2		  key_data_length[2];	/* Array of lengths */
    krb5_octet 	        * key_data_contents[2];	/* Array of pointers */
} krb5_key_data;

typedef struct _krb5_keysalt {
    krb5_int16		  type;	
    krb5_data		  data;			/* Length, data */
} krb5_keysalt;

typedef struct _krb5_db_entry_new {
    krb5_magic 		  magic;		/* NOT saved */
    krb5_ui_2		  len;			
    krb5_ui_4             mask;                 /* members currently changed/set */	
    krb5_flags 		  attributes;
    krb5_deltat		  max_life;
    krb5_deltat		  max_renewable_life;
    krb5_timestamp 	  expiration;	  	/* When the client expires */
    krb5_timestamp 	  pw_expiration;  	/* When its passwd expires */
    krb5_timestamp 	  last_success;		/* Last successful passwd */
    krb5_timestamp 	  last_failed;		/* Last failed passwd attempt */
    krb5_kvno 	 	  fail_auth_count; 	/* # of failed passwd attempt */
    krb5_int16 		  n_tl_data;
    krb5_int16 		  n_key_data;
    krb5_ui_2		  e_length;		/* Length of extra data */
    krb5_octet		* e_data;		/* Extra data to be saved */

    krb5_principal 	  princ;		/* Length, data */	
    krb5_tl_data	* tl_data;		/* Linked list */
    krb5_key_data       * key_data;		/* Array */
} krb5_db_entry;

krb5_error_code krb5_db_open( krb5_context kcontext, char **db_args, int mode );
krb5_error_code krb5_db_init  ( krb5_context kcontext );
krb5_error_code krb5_db_fini ( krb5_context kcontext );
krb5_error_code krb5_db_get_principal ( krb5_context kcontext,
					krb5_const_principal search_for,
					krb5_db_entry *entries,
					int *nentries,
					krb5_boolean *more );
krb5_error_code krb5_db_free_principal ( krb5_context kcontext,
					 krb5_db_entry *entry,
					 int count );
krb5_error_code krb5_db_fetch_mkey  ( krb5_context   context,
				      krb5_principal mname,
				      krb5_enctype   etype,
				      krb5_boolean   fromkeyboard,
				      krb5_boolean   twice,
				      char          *db_args,
				      krb5_data     *salt,
				      krb5_keyblock *key);
krb5_error_code krb5_db_verify_master_key ( krb5_context kcontext,
					    krb5_principal mprinc,
					    krb5_keyblock *mkey );
krb5_error_code
krb5_dbe_find_enctype( krb5_context	kcontext,
		       krb5_db_entry	*dbentp,
		       krb5_int32		ktype,
		       krb5_int32		stype,
		       krb5_int32		kvno,
		       krb5_key_data	**kdatap);
krb5_error_code
krb5_dbekd_decrypt_key_data( krb5_context 	  context,
			     const krb5_keyblock	* mkey,
			     const krb5_key_data	* key_data,
			     krb5_keyblock 	* dbkey,
			     krb5_keysalt 	* keysalt);
krb5_error_code
krb5_db_setup_mkey_name ( krb5_context context,
			  const char *keyname,
			  const char *realm,
			  char **fullname,
			  krb5_principal *principal);

#elif defined(HAVE_KRB5_DB_SET_NAME)
/* 1.4.4 */

typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;		/* NOT saved */
    krb5_int16 		  tl_data_type;		
    krb5_ui_2		  tl_data_length;	
    krb5_octet 	        * tl_data_contents;	
} krb5_tl_data;

typedef struct _krb5_key_data {
    krb5_int16 		  key_data_ver;		/* Version */
    krb5_int16		  key_data_kvno;	/* Key Version */
    krb5_int16		  key_data_type[2];	/* Array of types */
    krb5_ui_2		  key_data_length[2];	/* Array of lengths */
    krb5_octet 	        * key_data_contents[2];	/* Array of pointers */
} krb5_key_data;

typedef struct _krb5_keysalt {
    krb5_int16		  type;	
    krb5_data		  data;			/* Length, data */
} krb5_keysalt;

typedef struct _krb5_db_entry_new {
    krb5_magic 		  magic;		/* NOT saved */
    krb5_ui_2		  len;			
    krb5_flags 		  attributes;
    krb5_deltat		  max_life;
    krb5_deltat		  max_renewable_life;
    krb5_timestamp 	  expiration;	  	/* When the client expires */
    krb5_timestamp 	  pw_expiration;  	/* When its passwd expires */
    krb5_timestamp 	  last_success;		/* Last successful passwd */
    krb5_timestamp 	  last_failed;		/* Last failed passwd attempt */
    krb5_kvno 	 	  fail_auth_count; 	/* # of failed passwd attempt */
    krb5_int16 		  n_tl_data;
    krb5_int16 		  n_key_data;
    krb5_ui_2		  e_length;		/* Length of extra data */
    krb5_octet		* e_data;		/* Extra data to be saved */

    krb5_principal 	  princ;		/* Length, data */	
    krb5_tl_data	* tl_data;		/* Linked list */
    krb5_key_data       * key_data;		/* Array */
} krb5_db_entry;

krb5_error_code krb5_db_set_name (krb5_context, char * );
krb5_error_code krb5_db_init (krb5_context);
krb5_error_code krb5_db_fini ( krb5_context kcontext );
krb5_error_code krb5_db_get_principal (krb5_context, krb5_const_principal ,
				       krb5_db_entry *, int *,
				       krb5_boolean * );
void krb5_db_free_principal (krb5_context, krb5_db_entry *, int  );
krb5_error_code	krb5_db_fetch_mkey (krb5_context, krb5_principal, krb5_enctype,
				    krb5_boolean, krb5_boolean, char *,
				    krb5_data *, 
				    krb5_keyblock * );
krb5_error_code krb5_db_verify_master_key (krb5_context, krb5_principal, 
					   krb5_keyblock *);
krb5_error_code krb5_dbe_find_enctype (krb5_context, krb5_db_entry *,
				       krb5_int32,
				       krb5_int32,
				       krb5_int32,
				       krb5_key_data **);
krb5_error_code krb5_dbekd_decrypt_key_data (krb5_context,
					     const krb5_keyblock *,
					     const krb5_key_data *,
					     krb5_keyblock *,
					     krb5_keysalt *);
krb5_error_code krb5_db_setup_mkey_name (krb5_context, const char *, 
					 const char *, char **,
					 krb5_principal *);

#endif
