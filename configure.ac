#
# GNU autoconfigure script to tune options
#

AC_INIT
AC_CONFIG_SRCDIR([configure])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_TARGET


AC_PROG_CC

AC_MSG_CHECKING(whether to compile with debug flags)
AC_ARG_ENABLE(debug,
[  --enable-debug          compile with -g and no optimization],
[ case "$enableval" in
    no)
	if test "${GCC}" = "yes"; then
	  CFLAGS="$CFLAGS -O2 -s"
	fi
	LDFLAGS="$LDFLAGS -s"
	AC_MSG_RESULT(optimize)
	;;
    *)
	CFLAGS="$CFLAGS -g"
	LDFLAGS="$LDFLAGS -g"
	if test "${GCC}" = "yes"; then
	  CFLAGS="$CFLAGS -O0 -Wall -Wno-long-long -Wpointer-arith -Wcast-align -Waggregate-return -Wmissing-declarations -Wredundant-decls -Wnested-externs -DDEBUG"
	fi
	AC_MSG_RESULT(yes)
	;;
  esac
],
[ AC_MSG_RESULT(no)
])


AC_PROG_GCC_TRADITIONAL
AC_C_CONST
AC_PROG_INSTALL


LDSH="$CC"
LDSHFLAGS="-shared"
PICFLAG=
SOEXT=so
SOEXTVER=so.0
LIBINC=
MKSO=

AC_MSG_CHECKING(how to make shared libraries)
done=0
if [[ "$GCC" = yes ]]; then
  PICFLAG=-fPIC
  done=1
  AC_MSG_RESULT(GCC)
fi

if [[ "$done" = 0 ]]; then
  case "`$CC -V 2>&1`" in
    *"WorkShop Compilers"*|*"Sun C"*)
      LDSHFLAGS=-G
      PICFLAG=-KPIC
      done=1
      AC_MSG_RESULT(Sun)
      ;;
  esac
fi

if [[ "$done" = 0 ]]; then
  case "`$CC -v 2>&1`" in
    *MIPSpro*)
      PICFLAG=-KPIC
      done=1
      AC_MSG_RESULT(MIPSpro)
      ;;
    *"gcc version"*)
      PICFLAG=-fPIC
      done=1
      AC_MSG_RESULT(GCC)
      ;;
  esac
fi

if [[ "$done" = 0 ]]; then
  case "`$CC -qversion 2>&1`" in
    *"IBM XL C"*)
      PICFLAG=-qpic
      LDSHFLAGS=-G
      LIBINC=libkcrap.${SOEXTVER}
      done=1
      AC_MSG_RESULT(IBM xlc)
      ;;
  esac
fi

if [[ "$done" = 0 ]]; then
  AC_MSG_RESULT(UNKNOWN COMPILER SUITE -- SHARED LIBRARIES WILL NOT BE BUILT)
  LDSHFLAGS=
  SOEXT=
  SOEXTVER=
  MKSO="#"
fi



AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(connect, socket)
AC_SEARCH_LIBS(herror, resolv)


AC_ARG_WITH(mit-krb5,
[  --with-mit-krb5=PATH   Installed location of MIT kerberos ],
[ CFLAGS="$CFLAGS -I${withval}/include"
  CPPFLAGS="$CPPFLAGS -I${withval}/include"
  LDFLAGS="$LDFLAGS -L${withval}/lib -R${withval}/lib"
])

unset ac_cv_header_profile_h
AC_CHECK_HEADER(profile.h, [], [
  CFLAGS="$CFLAGS -I/usr/local/include"
  CPPFLAGS="$CPPFLAGS -I/usr/local/include"
  LDFLAGS="$CPPFLAGS -L/usr/local/lib"
  unset ac_cv_header_profile_h
  AC_CHECK_HEADER(profile.h, [], [AC_MSG_ERROR(profile.h not found)])
])
AC_CHECK_HEADER(krb5.h, [], [AC_MSG_ERROR(krb5.h not found)])

found=
AC_ARG_WITH(mit-krb5-src,
[  --with-mit-krb5-src=PATH Location kdb.h (required for server build) ],
[ AC_MSG_CHECKING(location of MIT KerberosV source (kdb.h))
  for d in "" /krb5 /include/krb5 /src/include/krb5; do
    if [[ -d "${withval}${d}" -a -r "${withval}${d}/kdb.h" ]]; then
	found="${withval}${d}"
	break;
    fi
  done
  if [[ "$found" = "" -a -f "${withval}" -a -r "`dirname ${withval}`/kdb.h" ]]; then
    found="`dirname ${withval}`"
  fi
  if [[ "$found" = "" ]]; then
    AC_MSG_ERROR(NOT FOUND)
  else
    CFLAGS="$CFLAGS -I${found}"
    CPPFLAGS="$CPPFLAGS -I${found}"
    AC_MSG_RESULT(${found})
  fi
],
[ AC_CHECK_HEADER(kdb.h, [
    found=system
    AC_MSG_CHECKING(location of MIT KerberosV source (kdb.h))
    AC_MSG_RESULT(found)
  ], [
    AC_MSG_CHECKING(location of MIT KerberosV source (kdb.h))
    AC_MSG_RESULT(NOT FOUND)
  ])
])

build_server=0
AC_ARG_WITH(server,
[  --with-server           build KCRAP server (default detect) ],
[ AC_MSG_CHECKING(whether to build KCRAP server)
  case "$withval" in
    no)
	AC_MSG_RESULT(no)
	;;
    *)
	build_server=1
	AC_MSG_RESULT(yes)
	if [[ "$found" = "" ]]; then
	  AC_DEFINE(USE_KDB_H_STUB, [], [Use stub kdb.h])
	fi
	;;
  esac
],
[ AC_CHECK_HEADER(kdb.h, [
    build_server=1
    AC_MSG_CHECKING(whether to build KCRAP server)
    AC_MSG_RESULT(yes)
  ], [
    AC_MSG_CHECKING(whether to build KCRAP server)
    AC_MSG_RESULT(no)
  ])
])


build_library=0
AC_MSG_CHECKING(whether to build KCRAP library)
AC_ARG_WITH(library,
[  --with-library          build KCRAP library (default yes) ],
[ case "$withval" in
    no)
	AC_MSG_RESULT(no)
	;;
    *)
	build_library=1
	AC_MSG_RESULT(yes)
	;;
  esac
],
[ build_library=1
  AC_MSG_RESULT(yes)
])


build_client=0
AC_MSG_CHECKING(whether to build KCRAP client)
AC_ARG_WITH(client,
[  --with-client          build KCRAP client (default yes) ],
[ case "$withval" in
    no)
       AC_MSG_RESULT(no)
       ;;
    *)
       build_client=1
       AC_MSG_RESULT(yes)
       ;;
  esac
],
[ build_client=1
  AC_MSG_RESULT(yes)
])



build_tests=0
AC_MSG_CHECKING(whether to build KCRAP tests)
AC_ARG_WITH(tests,
[  --with-tests            build KCRAP tests (default=yes)],
[ case "$withval" in
    no)
	AC_MSG_RESULT(no)
	;;
    *)
	build_tests=1
	AC_MSG_RESULT(yes)
	;;
  esac
],
[ build_tests=1
  AC_MSG_RESULT(yes)
])


if [[ "$build_server" = 1 ]]; then
  save_LIBS="$LIBS"
  AC_SEARCH_LIBS(krb5_db_open, kdb5, [
    AC_DEFINE(HAVE_KRB5_DB_OPEN, [], [Have krb5_db_open (mit krb5 1.6)])
  ], [
    AC_SEARCH_LIBS(krb5_db_set_name, kdb5, [
      AC_DEFINE(HAVE_KRB5_DB_SET_NAME, [], [Have krb5_db_set_name (mit krb5 1.4)])
    ], [
      AC_MSG_ERROR(neither krb5_db_open nor krb5_db_set_name found in libkdb)
    ])
  ])

  AC_MSG_CHECKING(8-argument krb5_db_fetch_mkey() with KVNO)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <unistd.h>
#include <krb5.h>
#include <profile.h>
#include <com_err.h>
#include <kdb.h>]], [[krb5_db_fetch_mkey(NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL)]])],[
    AC_MSG_RESULT(8-argument)
    AC_DEFINE(HAVE_KRB5_DB_FETCH_MKEY_KVNO, [], [Have 8-argument krb5_db_fetch_mkey() function with kvno])
  ],[
    AC_MSG_RESULT(not 8-argument)
  ])

  AC_MSG_CHECKING(more argument to krb5_db_get_principal)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <unistd.h>
#include <krb5.h>
#include <profile.h>
#include <com_err.h>
#include <kdb.h>]], [[krb5_db_get_principal(NULL, NULL, 0, NULL, NULL)]])],[
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_KRB5_DB_GET_PRINCIPAL_MORE, [], [Use more arg to krb5_db_get_princip])
  ],[
    AC_MSG_RESULT(no)
  ])

  AC_MSG_CHECKING(nentries argument to krb5_db_free_principal)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <unistd.h>
#include <krb5.h>
#include <profile.h>
#include <com_err.h>
#include <kdb.h>]], [[krb5_db_free_principal(NULL, NULL, 0)]])],[
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_KRB5_DB_FREE_PRINCIPAL_NENTRIES, [], [Use nentries arg to krb5_db_free_princip])
  ],[
    AC_MSG_RESULT(no)
  ])

  LIBS="$save_LIBS"
fi


echo ""
echo "------------------"
echo "Build options:"

if [[ "$build_library" = "1" ]]; then
  echo "  KCRAP library: YES"
  SUBDIR="${SUBDIR}${SUBDIR:+ }lib"
else
  echo "  KCRAP library: NO"
fi

if [[ "$build_server" = "1" ]]; then
  echo "  KCRAP server: YES"
  SUBDIR="${SUBDIR}${SUBDIR:+ }server"
else
  echo "  KCRAP server: NO"
fi

if [[ "$build_tests" = "1" ]]; then
  echo "  KCRAP tests: YES"
  SUBDIR="${SUBDIR}${SUBDIR:+ }test"
else
  echo "  KCRAP tests: NO"
fi

if [[ "$build_client" = "1" ]]; then
  echo "  KCRAP client: YES"
  SUBDIR="${SUBDIR}${SUBDIR:+ }client"
else
  echo "  KCRAP client: NO"
fi

if [[ "$MKSO" = "#" ]]; then
  echo "  WARNING: not building shared libraries"
fi
if [[ "$build_server" = 1 -a "$found" = "" ]]; then
  echo "  WARNING: Compiling KCRAP server with stub kdb.h"
  echo "  WARNING: Server may not work if krb5 headers have changed"
  echo "  WARNING: Rerun configure with --with-mit-krb5-src=PATH"
  echo ""
  sleep 5
fi


AC_SUBST(SUBDIR)
AC_SUBST(LDSH)
AC_SUBST(LDSHFLAGS)
AC_SUBST(PICFLAG)
AC_SUBST(SOEXT)
AC_SUBST(SOEXTVER)
AC_SUBST(LIBINC)
AC_SUBST(MKSO)

MF=""
for entry in ${SUBDIR}; do
	MF="$MF ${entry}/Makefile"
done

AC_CONFIG_FILES([$MF Makefile])
AC_OUTPUT

