
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.4.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 1 "read_config_yy.y"

/*
 * (C) 2006-2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: configuration file abstract grammar
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include "conntrackd.h"
#include "bitops.h"
#include "cidr.h"
#include <syslog.h>
#include <sched.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

extern char *yytext;
extern int   yylineno;

struct ct_conf conf;

enum {
	CTD_CFG_ERROR = 0,
	CTD_CFG_WARN,
};

static void print_err(int err, const char *msg, ...);

static void __kernel_filter_start(void);
static void __kernel_filter_add_state(int value);
static void __max_dedicated_links_reached(void);


/* Line 189 of yacc.c  */
#line 126 "read_config_yy.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     T_IPV4_ADDR = 258,
     T_IPV4_IFACE = 259,
     T_PORT = 260,
     T_HASHSIZE = 261,
     T_HASHLIMIT = 262,
     T_MULTICAST = 263,
     T_PATH = 264,
     T_UNIX = 265,
     T_REFRESH = 266,
     T_IPV6_ADDR = 267,
     T_IPV6_IFACE = 268,
     T_IGNORE_UDP = 269,
     T_IGNORE_ICMP = 270,
     T_IGNORE_TRAFFIC = 271,
     T_BACKLOG = 272,
     T_GROUP = 273,
     T_LOG = 274,
     T_UDP = 275,
     T_ICMP = 276,
     T_IGMP = 277,
     T_VRRP = 278,
     T_TCP = 279,
     T_IGNORE_PROTOCOL = 280,
     T_LOCK = 281,
     T_STRIP_NAT = 282,
     T_BUFFER_SIZE_MAX_GROWN = 283,
     T_EXPIRE = 284,
     T_TIMEOUT = 285,
     T_GENERAL = 286,
     T_SYNC = 287,
     T_STATS = 288,
     T_RELAX_TRANSITIONS = 289,
     T_BUFFER_SIZE = 290,
     T_DELAY = 291,
     T_SYNC_MODE = 292,
     T_LISTEN_TO = 293,
     T_FAMILY = 294,
     T_RESEND_BUFFER_SIZE = 295,
     T_ALARM = 296,
     T_FTFW = 297,
     T_CHECKSUM = 298,
     T_WINDOWSIZE = 299,
     T_ON = 300,
     T_OFF = 301,
     T_REPLICATE = 302,
     T_FOR = 303,
     T_IFACE = 304,
     T_PURGE = 305,
     T_RESEND_QUEUE_SIZE = 306,
     T_ESTABLISHED = 307,
     T_SYN_SENT = 308,
     T_SYN_RECV = 309,
     T_FIN_WAIT = 310,
     T_CLOSE_WAIT = 311,
     T_LAST_ACK = 312,
     T_TIME_WAIT = 313,
     T_CLOSE = 314,
     T_LISTEN = 315,
     T_SYSLOG = 316,
     T_WRITE_THROUGH = 317,
     T_STAT_BUFFER_SIZE = 318,
     T_DESTROY_TIMEOUT = 319,
     T_RCVBUFF = 320,
     T_SNDBUFF = 321,
     T_NOTRACK = 322,
     T_POLL_SECS = 323,
     T_FILTER = 324,
     T_ADDRESS = 325,
     T_PROTOCOL = 326,
     T_STATE = 327,
     T_ACCEPT = 328,
     T_IGNORE = 329,
     T_FROM = 330,
     T_USERSPACE = 331,
     T_KERNELSPACE = 332,
     T_EVENT_ITER_LIMIT = 333,
     T_DEFAULT = 334,
     T_NETLINK_OVERRUN_RESYNC = 335,
     T_NICE = 336,
     T_IPV4_DEST_ADDR = 337,
     T_IPV6_DEST_ADDR = 338,
     T_SCHEDULER = 339,
     T_TYPE = 340,
     T_PRIO = 341,
     T_NETLINK_EVENTS_RELIABLE = 342,
     T_DISABLE_INTERNAL_CACHE = 343,
     T_DISABLE_EXTERNAL_CACHE = 344,
     T_ERROR_QUEUE_LENGTH = 345,
     T_IP = 346,
     T_PATH_VAL = 347,
     T_NUMBER = 348,
     T_SIGNED_NUMBER = 349,
     T_STRING = 350
   };
#endif
/* Tokens.  */
#define T_IPV4_ADDR 258
#define T_IPV4_IFACE 259
#define T_PORT 260
#define T_HASHSIZE 261
#define T_HASHLIMIT 262
#define T_MULTICAST 263
#define T_PATH 264
#define T_UNIX 265
#define T_REFRESH 266
#define T_IPV6_ADDR 267
#define T_IPV6_IFACE 268
#define T_IGNORE_UDP 269
#define T_IGNORE_ICMP 270
#define T_IGNORE_TRAFFIC 271
#define T_BACKLOG 272
#define T_GROUP 273
#define T_LOG 274
#define T_UDP 275
#define T_ICMP 276
#define T_IGMP 277
#define T_VRRP 278
#define T_TCP 279
#define T_IGNORE_PROTOCOL 280
#define T_LOCK 281
#define T_STRIP_NAT 282
#define T_BUFFER_SIZE_MAX_GROWN 283
#define T_EXPIRE 284
#define T_TIMEOUT 285
#define T_GENERAL 286
#define T_SYNC 287
#define T_STATS 288
#define T_RELAX_TRANSITIONS 289
#define T_BUFFER_SIZE 290
#define T_DELAY 291
#define T_SYNC_MODE 292
#define T_LISTEN_TO 293
#define T_FAMILY 294
#define T_RESEND_BUFFER_SIZE 295
#define T_ALARM 296
#define T_FTFW 297
#define T_CHECKSUM 298
#define T_WINDOWSIZE 299
#define T_ON 300
#define T_OFF 301
#define T_REPLICATE 302
#define T_FOR 303
#define T_IFACE 304
#define T_PURGE 305
#define T_RESEND_QUEUE_SIZE 306
#define T_ESTABLISHED 307
#define T_SYN_SENT 308
#define T_SYN_RECV 309
#define T_FIN_WAIT 310
#define T_CLOSE_WAIT 311
#define T_LAST_ACK 312
#define T_TIME_WAIT 313
#define T_CLOSE 314
#define T_LISTEN 315
#define T_SYSLOG 316
#define T_WRITE_THROUGH 317
#define T_STAT_BUFFER_SIZE 318
#define T_DESTROY_TIMEOUT 319
#define T_RCVBUFF 320
#define T_SNDBUFF 321
#define T_NOTRACK 322
#define T_POLL_SECS 323
#define T_FILTER 324
#define T_ADDRESS 325
#define T_PROTOCOL 326
#define T_STATE 327
#define T_ACCEPT 328
#define T_IGNORE 329
#define T_FROM 330
#define T_USERSPACE 331
#define T_KERNELSPACE 332
#define T_EVENT_ITER_LIMIT 333
#define T_DEFAULT 334
#define T_NETLINK_OVERRUN_RESYNC 335
#define T_NICE 336
#define T_IPV4_DEST_ADDR 337
#define T_IPV6_DEST_ADDR 338
#define T_SCHEDULER 339
#define T_TYPE 340
#define T_PRIO 341
#define T_NETLINK_EVENTS_RELIABLE 342
#define T_DISABLE_INTERNAL_CACHE 343
#define T_DISABLE_EXTERNAL_CACHE 344
#define T_ERROR_QUEUE_LENGTH 345
#define T_IP 346
#define T_PATH_VAL 347
#define T_NUMBER 348
#define T_SIGNED_NUMBER 349
#define T_STRING 350




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 53 "read_config_yy.y"

	int		val;
	char		*string;



/* Line 214 of yacc.c  */
#line 359 "read_config_yy.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 264 of yacc.c  */
#line 371 "read_config_yy.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  21
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   332

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  98
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  94
/* YYNRULES -- Number of rules.  */
#define YYNRULES  234
/* YYNRULES -- Number of states.  */
#define YYNSTATES  367

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   350

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    96,     2,    97,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     6,     8,    11,    13,    15,    17,
      19,    21,    23,    26,    29,    32,    35,    38,    41,    44,
      46,    49,    52,    55,    58,    61,    64,    69,    70,    73,
      76,    79,    84,    90,    91,    94,    97,   100,   103,   106,
     109,   112,   115,   118,   121,   124,   127,   132,   138,   139,
     142,   145,   148,   151,   154,   157,   160,   163,   166,   169,
     172,   177,   183,   184,   187,   190,   193,   196,   199,   202,
     205,   208,   211,   214,   217,   220,   223,   226,   231,   232,
     235,   238,   241,   246,   247,   250,   252,   254,   259,   260,
     263,   265,   267,   269,   271,   273,   275,   277,   279,   281,
     283,   285,   287,   289,   291,   293,   295,   297,   303,   309,
     315,   316,   319,   321,   323,   325,   327,   329,   331,   332,
     335,   337,   339,   341,   343,   345,   347,   348,   351,   353,
     355,   357,   359,   362,   365,   368,   371,   374,   377,   380,
     383,   385,   387,   390,   395,   396,   399,   401,   403,   404,
     407,   409,   411,   413,   415,   417,   419,   421,   423,   425,
     428,   431,   436,   437,   440,   442,   444,   446,   448,   450,
     452,   454,   456,   458,   460,   462,   464,   466,   468,   470,
     472,   474,   476,   479,   482,   485,   488,   491,   494,   497,
     500,   505,   506,   509,   512,   515,   518,   521,   524,   529,
     536,   543,   544,   547,   553,   559,   560,   563,   565,   567,
     573,   579,   580,   583,   586,   589,   595,   601,   602,   605,
     609,   614,   615,   618,   620,   622,   624,   626,   628,   631,
     634,   637,   640,   643,   646
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
      99,     0,    -1,    -1,   100,    -1,   101,    -1,   100,   101,
      -1,   130,    -1,   113,    -1,   107,    -1,   161,    -1,   133,
      -1,   184,    -1,    19,    45,    -1,    19,    46,    -1,    19,
      92,    -1,    61,    45,    -1,    61,    46,    -1,    61,    95,
      -1,    26,    92,    -1,    27,    -1,    11,    93,    -1,    29,
      93,    -1,    30,    93,    -1,    50,    93,    -1,    43,    45,
      -1,    43,    46,    -1,    16,    96,   114,    97,    -1,    -1,
     114,   115,    -1,     3,    91,    -1,    12,    91,    -1,     8,
      96,   117,    97,    -1,     8,    79,    96,   117,    97,    -1,
      -1,   117,   118,    -1,     3,    91,    -1,    12,    91,    -1,
       4,    91,    -1,    13,    91,    -1,    49,    95,    -1,    17,
      93,    -1,    18,    93,    -1,    66,    93,    -1,    65,    93,
      -1,    43,    45,    -1,    43,    46,    -1,    20,    96,   120,
      97,    -1,    20,    79,    96,   120,    97,    -1,    -1,   120,
     121,    -1,     3,    91,    -1,    12,    91,    -1,    82,    91,
      -1,    83,    91,    -1,    49,    95,    -1,     5,    93,    -1,
      66,    93,    -1,    65,    93,    -1,    43,    45,    -1,    43,
      46,    -1,    24,    96,   123,    97,    -1,    24,    79,    96,
     123,    97,    -1,    -1,   123,   124,    -1,     3,    91,    -1,
      12,    91,    -1,    82,    91,    -1,    83,    91,    -1,    49,
      95,    -1,     5,    93,    -1,    66,    93,    -1,    65,    93,
      -1,    43,    45,    -1,    43,    46,    -1,    90,    93,    -1,
       6,    93,    -1,     7,    93,    -1,    10,    96,   128,    97,
      -1,    -1,   128,   129,    -1,     9,    92,    -1,    17,    93,
      -1,    25,    96,   131,    97,    -1,    -1,   131,   132,    -1,
      93,    -1,    95,    -1,    32,    96,   134,    97,    -1,    -1,
     134,   135,    -1,   108,    -1,   109,    -1,   110,    -1,   111,
      -1,   112,    -1,   116,    -1,   119,    -1,   122,    -1,   151,
      -1,   152,    -1,   136,    -1,   137,    -1,   138,    -1,   153,
      -1,   154,    -1,   160,    -1,   150,    -1,    37,    41,    96,
     139,    97,    -1,    37,    42,    96,   141,    97,    -1,    37,
      67,    96,   143,    97,    -1,    -1,   139,   140,    -1,   108,
      -1,   109,    -1,   110,    -1,   111,    -1,   151,    -1,   152,
      -1,    -1,   141,   142,    -1,   148,    -1,   147,    -1,   110,
      -1,   111,    -1,   149,    -1,   146,    -1,    -1,   143,   144,
      -1,   110,    -1,   111,    -1,   145,    -1,   146,    -1,    88,
      45,    -1,    88,    46,    -1,    89,    45,    -1,    89,    46,
      -1,    40,    93,    -1,    51,    93,    -1,    44,    93,    -1,
      64,    93,    -1,    34,    -1,    36,    -1,    38,    91,    -1,
      47,   155,    48,   156,    -1,    -1,   155,   157,    -1,    95,
      -1,   159,    -1,    -1,   158,   159,    -1,    53,    -1,    54,
      -1,    52,    -1,    55,    -1,    56,    -1,    57,    -1,    58,
      -1,    59,    -1,    60,    -1,    62,    45,    -1,    62,    46,
      -1,    31,    96,   162,    97,    -1,    -1,   162,   163,    -1,
     125,    -1,   126,    -1,   102,    -1,   103,    -1,   105,    -1,
     104,    -1,   106,    -1,   127,    -1,   164,    -1,   165,    -1,
     172,    -1,   173,    -1,   174,    -1,   175,    -1,   166,    -1,
     167,    -1,   168,    -1,   169,    -1,    35,    93,    -1,    28,
      93,    -1,    80,    45,    -1,    80,    46,    -1,    80,    93,
      -1,    87,    45,    -1,    87,    46,    -1,    81,    94,    -1,
      84,    96,   170,    97,    -1,    -1,   170,   171,    -1,    85,
      95,    -1,    86,    93,    -1,    39,    95,    -1,    78,    93,
      -1,    68,    93,    -1,    69,    96,   176,    97,    -1,    69,
      75,    76,    96,   176,    97,    -1,    69,    75,    77,    96,
     176,    97,    -1,    -1,   176,   177,    -1,    71,    73,    96,
     178,    97,    -1,    71,    74,    96,   178,    97,    -1,    -1,
     178,   179,    -1,    95,    -1,    24,    -1,    70,    73,    96,
     180,    97,    -1,    70,    74,    96,   180,    97,    -1,    -1,
     180,   181,    -1,     3,    91,    -1,    12,    91,    -1,    72,
      73,    96,   182,    97,    -1,    72,    74,    96,   182,    97,
      -1,    -1,   182,   183,    -1,   158,    48,    24,    -1,    33,
      96,   185,    97,    -1,    -1,   185,   186,    -1,   187,    -1,
     188,    -1,   189,    -1,   190,    -1,   191,    -1,    19,    45,
      -1,    19,    46,    -1,    19,    92,    -1,    61,    45,    -1,
      61,    46,    -1,    61,    95,    -1,    63,    93,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,    84,    84,    85,    88,    89,    92,    93,    94,    95,
      96,    97,   100,   105,   109,   114,   119,   124,   156,   161,
     166,   171,   176,   181,   186,   197,   208,   218,   219,   221,
     243,   269,   283,   299,   300,   302,   321,   361,   380,   385,
     405,   412,   418,   424,   430,   436,   442,   456,   472,   473,
     475,   486,   503,   514,   531,   546,   552,   558,   564,   570,
     576,   592,   610,   611,   613,   624,   641,   652,   669,   684,
     690,   696,   702,   708,   714,   720,   725,   730,   732,   733,
     736,   741,   746,   756,   757,   760,   768,   781,   791,   792,
     794,   795,   796,   797,   798,   799,   800,   801,   802,   803,
     804,   805,   806,   807,   808,   809,   810,   813,   818,   823,
     828,   829,   831,   832,   833,   834,   835,   836,   839,   840,
     842,   843,   844,   845,   846,   847,   850,   851,   853,   854,
     855,   856,   859,   864,   869,   874,   879,   885,   890,   895,
     900,   906,   912,   917,   927,   928,   930,   937,   939,   940,
     942,   950,   958,   966,   974,   982,   990,   998,  1006,  1015,
    1021,  1027,  1029,  1030,  1033,  1034,  1035,  1036,  1037,  1038,
    1039,  1040,  1041,  1042,  1043,  1044,  1045,  1046,  1047,  1048,
    1049,  1050,  1053,  1058,  1063,  1068,  1073,  1078,  1083,  1088,
    1093,  1095,  1096,  1099,  1111,  1120,  1128,  1133,  1143,  1148,
    1153,  1158,  1159,  1161,  1170,  1183,  1184,  1186,  1205,  1224,
    1233,  1255,  1256,  1258,  1317,  1377,  1386,  1400,  1401,  1403,
    1405,  1415,  1416,  1419,  1420,  1421,  1422,  1423,  1426,  1431,
    1435,  1440,  1445,  1450,  1482
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "T_IPV4_ADDR", "T_IPV4_IFACE", "T_PORT",
  "T_HASHSIZE", "T_HASHLIMIT", "T_MULTICAST", "T_PATH", "T_UNIX",
  "T_REFRESH", "T_IPV6_ADDR", "T_IPV6_IFACE", "T_IGNORE_UDP",
  "T_IGNORE_ICMP", "T_IGNORE_TRAFFIC", "T_BACKLOG", "T_GROUP", "T_LOG",
  "T_UDP", "T_ICMP", "T_IGMP", "T_VRRP", "T_TCP", "T_IGNORE_PROTOCOL",
  "T_LOCK", "T_STRIP_NAT", "T_BUFFER_SIZE_MAX_GROWN", "T_EXPIRE",
  "T_TIMEOUT", "T_GENERAL", "T_SYNC", "T_STATS", "T_RELAX_TRANSITIONS",
  "T_BUFFER_SIZE", "T_DELAY", "T_SYNC_MODE", "T_LISTEN_TO", "T_FAMILY",
  "T_RESEND_BUFFER_SIZE", "T_ALARM", "T_FTFW", "T_CHECKSUM",
  "T_WINDOWSIZE", "T_ON", "T_OFF", "T_REPLICATE", "T_FOR", "T_IFACE",
  "T_PURGE", "T_RESEND_QUEUE_SIZE", "T_ESTABLISHED", "T_SYN_SENT",
  "T_SYN_RECV", "T_FIN_WAIT", "T_CLOSE_WAIT", "T_LAST_ACK", "T_TIME_WAIT",
  "T_CLOSE", "T_LISTEN", "T_SYSLOG", "T_WRITE_THROUGH",
  "T_STAT_BUFFER_SIZE", "T_DESTROY_TIMEOUT", "T_RCVBUFF", "T_SNDBUFF",
  "T_NOTRACK", "T_POLL_SECS", "T_FILTER", "T_ADDRESS", "T_PROTOCOL",
  "T_STATE", "T_ACCEPT", "T_IGNORE", "T_FROM", "T_USERSPACE",
  "T_KERNELSPACE", "T_EVENT_ITER_LIMIT", "T_DEFAULT",
  "T_NETLINK_OVERRUN_RESYNC", "T_NICE", "T_IPV4_DEST_ADDR",
  "T_IPV6_DEST_ADDR", "T_SCHEDULER", "T_TYPE", "T_PRIO",
  "T_NETLINK_EVENTS_RELIABLE", "T_DISABLE_INTERNAL_CACHE",
  "T_DISABLE_EXTERNAL_CACHE", "T_ERROR_QUEUE_LENGTH", "T_IP", "T_PATH_VAL",
  "T_NUMBER", "T_SIGNED_NUMBER", "T_STRING", "'{'", "'}'", "$accept",
  "configfile", "lines", "line", "logfile_bool", "logfile_path",
  "syslog_bool", "syslog_facility", "lock", "strip_nat", "refreshtime",
  "expiretime", "timeout", "purge", "checksum", "ignore_traffic",
  "ignore_traffic_options", "ignore_traffic_option", "multicast_line",
  "multicast_options", "multicast_option", "udp_line", "udp_options",
  "udp_option", "tcp_line", "tcp_options", "tcp_option", "hashsize",
  "hashlimit", "unix_line", "unix_options", "unix_option",
  "ignore_protocol", "ignore_proto_list", "ignore_proto", "sync",
  "sync_list", "sync_line", "sync_mode_alarm", "sync_mode_ftfw",
  "sync_mode_notrack", "sync_mode_alarm_list", "sync_mode_alarm_line",
  "sync_mode_ftfw_list", "sync_mode_ftfw_line", "sync_mode_notrack_list",
  "sync_mode_notrack_line", "disable_internal_cache",
  "disable_external_cache", "resend_buffer_size", "resend_queue_size",
  "window_size", "destroy_timeout", "relax_transitions",
  "delay_destroy_msgs", "listen_to", "state_replication", "states",
  "state_proto", "state", "tcp_states", "tcp_state", "cache_writethrough",
  "general", "general_list", "general_line", "netlink_buffer_size",
  "netlink_buffer_size_max_grown", "netlink_overrun_resync",
  "netlink_events_reliable", "nice", "scheduler", "scheduler_options",
  "scheduler_line", "family", "event_iterations_limit", "poll_secs",
  "filter", "filter_list", "filter_item", "filter_protocol_list",
  "filter_protocol_item", "filter_address_list", "filter_address_item",
  "filter_state_list", "filter_state_item", "stats", "stats_list",
  "stat_line", "stat_logfile_bool", "stat_logfile_path",
  "stat_syslog_bool", "stat_syslog_facility", "buffer_size", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   123,   125
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    98,    99,    99,   100,   100,   101,   101,   101,   101,
     101,   101,   102,   102,   103,   104,   104,   105,   106,   107,
     108,   109,   110,   111,   112,   112,   113,   114,   114,   115,
     115,   116,   116,   117,   117,   118,   118,   118,   118,   118,
     118,   118,   118,   118,   118,   118,   119,   119,   120,   120,
     121,   121,   121,   121,   121,   121,   121,   121,   121,   121,
     122,   122,   123,   123,   124,   124,   124,   124,   124,   124,
     124,   124,   124,   124,   124,   125,   126,   127,   128,   128,
     129,   129,   130,   131,   131,   132,   132,   133,   134,   134,
     135,   135,   135,   135,   135,   135,   135,   135,   135,   135,
     135,   135,   135,   135,   135,   135,   135,   136,   137,   138,
     139,   139,   140,   140,   140,   140,   140,   140,   141,   141,
     142,   142,   142,   142,   142,   142,   143,   143,   144,   144,
     144,   144,   145,   145,   146,   146,   147,   148,   149,   150,
     151,   152,   153,   154,   155,   155,   156,   157,   158,   158,
     159,   159,   159,   159,   159,   159,   159,   159,   159,   160,
     160,   161,   162,   162,   163,   163,   163,   163,   163,   163,
     163,   163,   163,   163,   163,   163,   163,   163,   163,   163,
     163,   163,   164,   165,   166,   166,   166,   167,   167,   168,
     169,   170,   170,   171,   171,   172,   173,   174,   175,   175,
     175,   176,   176,   177,   177,   178,   178,   179,   179,   177,
     177,   180,   180,   181,   181,   177,   177,   182,   182,   183,
     184,   185,   185,   186,   186,   186,   186,   186,   187,   187,
     188,   189,   189,   190,   191
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     1,     1,     2,     1,     1,     1,     1,
       1,     1,     2,     2,     2,     2,     2,     2,     2,     1,
       2,     2,     2,     2,     2,     2,     4,     0,     2,     2,
       2,     4,     5,     0,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     4,     5,     0,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       4,     5,     0,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     4,     0,     2,
       2,     2,     4,     0,     2,     1,     1,     4,     0,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     5,     5,     5,
       0,     2,     1,     1,     1,     1,     1,     1,     0,     2,
       1,     1,     1,     1,     1,     1,     0,     2,     1,     1,
       1,     1,     2,     2,     2,     2,     2,     2,     2,     2,
       1,     1,     2,     4,     0,     2,     1,     1,     0,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     2,
       2,     4,     0,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     2,     2,     2,     2,     2,     2,     2,
       4,     0,     2,     2,     2,     2,     2,     2,     4,     6,
       6,     0,     2,     5,     5,     0,     2,     1,     1,     5,
       5,     0,     2,     2,     2,     5,     5,     0,     2,     3,
       4,     0,     2,     1,     1,     1,     1,     1,     2,     2,
       2,     2,     2,     2,     2
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     0,    19,     0,     0,     0,     0,     3,     4,
       8,     7,     6,    10,     9,    11,    27,    83,   162,    88,
     221,     1,     5,     0,     0,     0,     0,     0,     0,     0,
      26,    28,    85,    86,    82,    84,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   161,   166,   167,   169,   168,   170,   164,   165,
     171,   163,   172,   173,   178,   179,   180,   181,   174,   175,
     176,   177,     0,     0,     0,     0,     0,     0,   140,   141,
       0,     0,     0,   144,     0,     0,     0,    87,    90,    91,
      92,    93,    94,    95,    96,    97,    89,   100,   101,   102,
     106,    98,    99,   103,   104,   105,     0,     0,     0,   220,
     222,   223,   224,   225,   226,   227,    29,    30,    75,    76,
      78,    12,    13,    14,    18,   183,   182,   195,    15,    16,
      17,   197,     0,   201,   196,   184,   185,   186,   189,   191,
     187,   188,     0,    33,    20,     0,    48,     0,    62,    21,
      22,     0,     0,     0,   142,    24,    25,     0,    23,   159,
     160,   139,   228,   229,   230,   231,   232,   233,   234,     0,
       0,     0,     0,     0,    33,     0,    48,     0,    62,     0,
     110,   118,   126,     0,   152,   150,   151,   153,   154,   155,
     156,   157,   158,   145,   147,     0,     0,    77,    79,   201,
     201,     0,     0,     0,   198,   202,     0,     0,   190,   192,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    31,    34,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    46,    49,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    60,    63,     0,     0,
       0,   146,   143,    80,    81,     0,     0,     0,     0,     0,
       0,     0,     0,   193,   194,    32,    35,    37,    36,    38,
      40,    41,    44,    45,    39,    43,    42,    47,    50,    55,
      51,    58,    59,    54,    57,    56,    52,    53,    61,    64,
      69,    65,    72,    73,    68,    71,    70,    66,    67,    74,
     107,   112,   113,   114,   115,   111,   116,   117,     0,     0,
       0,     0,   108,   122,   123,   119,   125,   121,   120,   124,
       0,   109,   128,   129,   127,   130,   131,   199,   200,   211,
     211,   205,   205,   217,   217,   136,   138,   137,   134,   135,
     132,   133,     0,     0,     0,     0,   148,   148,     0,     0,
     209,   212,   210,   208,   207,   203,   206,   204,   215,     0,
     218,   216,   213,   214,     0,   149,   219
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     7,     8,     9,    53,    54,    55,    56,    57,    10,
      88,    89,    90,    91,    92,    11,    23,    31,    93,   175,
     222,    94,   177,   234,    95,   179,   247,    58,    59,    60,
     169,   198,    12,    24,    35,    13,    26,    96,    97,    98,
      99,   248,   305,   249,   315,   250,   324,   325,   316,   317,
     318,   319,   100,   101,   102,   103,   104,   157,   252,   193,
     359,   194,   105,    14,    25,    61,    62,    63,    64,    65,
      66,    67,   173,   209,    68,    69,    70,    71,   172,   205,
     344,   356,   342,   351,   346,   360,    15,    27,   110,   111,
     112,   113,   114,   115
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -94
static const yytype_int16 yypact[] =
{
     193,   -93,   -90,   -94,   -84,   -77,   -70,    52,   193,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,    15,   115,   119,   155,    24,   -24,   -13,
     -94,   -94,   -94,   -94,   -94,   -94,     2,    20,    28,    60,
      38,    23,    42,    49,    -7,    62,   -52,    97,    53,    59,
     105,    26,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -47,   101,   -38,   -23,   111,   114,   -94,   -94,
      13,    76,    30,   -94,   118,    65,   135,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   104,     5,   137,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,    88,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   171,   -94,   -94,   172,   -94,   173,   -94,   -94,
     -94,   174,   175,   176,   -94,   -94,   -94,   179,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,    -4,
     177,   178,   -36,    84,   -94,    -3,   -94,    54,   -94,    -1,
     -94,   -94,   -94,   180,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   184,   185,   -94,   -94,   -94,
     -94,   100,   149,   170,   -94,   -94,   182,   186,   -94,   -94,
       4,   189,   190,   191,   192,   194,   195,   200,   196,   197,
     199,   -94,   -94,    74,   198,   203,   204,   202,   206,   207,
     209,   208,   212,   -94,   -94,    25,   213,   214,   215,   205,
     210,   216,   218,   221,   222,   223,   -94,   -94,    98,   132,
      -5,   -94,   -94,   -94,   -94,    71,    89,   188,   224,   225,
     226,   227,   228,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   232,   233,
     234,   217,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     219,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,    17,    21,     7,    36,   169,   211,   237,   238,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   201,
     -94,   -94,   -94,   -94,   261,   -94,   -94
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -94,   -94,   -94,   278,   -94,   -94,   -94,   -94,   -94,   -94,
      45,    46,   -35,    -8,   -94,   -94,   -94,   -94,   -94,   123,
     -94,   -94,   122,   -94,   -94,   136,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,    67,   -94,
     -94,   -94,   -94,    70,    82,   -94,   -94,   -94,   -94,   -94,
     -94,   -49,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94,   -94,   -94,   -94,   -94,   -22,   -94,
     -17,   -94,   -11,   -94,    -2,   -94,   -94,   -94,   -94,   -94,
     -94,   -94,   -94,   -94
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint16 yytable[] =
{
     211,   212,   236,    16,   237,   195,    17,   211,   212,   213,
     214,   238,    18,   196,   215,   216,   213,   214,    28,    19,
     348,   215,   216,   132,   348,    77,    20,    29,   236,   349,
     237,   353,   142,   349,   201,   202,   203,   238,   128,   129,
     217,   145,   239,   106,   133,    84,   218,   217,   240,   143,
     165,   166,    21,   218,   151,   152,   147,   224,   146,   225,
     353,   204,   219,   220,   241,   242,   226,   116,   239,   219,
     220,   140,   141,   148,   240,   155,   156,   224,   117,   225,
     153,   243,   244,   320,   311,   107,   226,   108,   130,   245,
     241,   242,   321,   197,   221,   118,   246,   227,   135,   136,
     167,   265,   354,   228,   355,   121,   122,   243,   244,    73,
     159,   160,    30,   119,   350,   245,   125,   227,   352,   229,
     230,   109,   288,   228,   120,    36,    37,    76,    77,    38,
     124,   354,    78,   357,    79,   126,   231,   232,    39,   229,
     230,   201,   202,   203,   127,    40,   137,    41,    84,   162,
     163,   233,   123,   138,    42,   131,   231,   232,    43,   201,
     202,   203,    77,    72,   170,   171,    73,   154,   327,   206,
     207,   277,   308,   257,   258,    74,   309,   255,   256,    75,
      44,   208,    84,   310,    76,    77,   328,    45,    46,    78,
     134,    79,    80,    81,   144,   300,   164,    47,    82,    48,
      49,   139,    83,    50,   149,    84,    51,   150,    32,     1,
      33,   158,    34,   303,   313,   322,    52,    85,     2,    86,
       3,   311,   259,   260,     4,     5,     6,   183,   161,   312,
     168,   184,   185,   186,   187,   188,   189,   190,   191,   192,
     304,   314,   323,   261,   262,   272,   273,   281,   282,   364,
     292,   293,    87,   184,   185,   186,   187,   188,   189,   190,
     191,   192,   338,   339,   340,   341,   358,   174,   176,   178,
     180,   181,   182,   199,   200,   251,   253,   263,   254,   264,
     266,   267,   268,   269,   329,   366,    22,   270,   271,   278,
     275,   274,   276,   301,   302,   280,   279,   210,   223,   286,
     284,   283,   285,   287,   289,   294,   291,   290,   361,   295,
     365,   296,   297,   298,   235,   345,   299,   326,   306,   343,
     330,   331,   332,   333,   334,   335,   336,   337,   362,   363,
     307,     0,   347
};

static const yytype_int16 yycheck[] =
{
       3,     4,     3,    96,     5,     9,    96,     3,     4,    12,
      13,    12,    96,    17,    17,    18,    12,    13,     3,    96,
       3,    17,    18,    75,     3,    30,    96,    12,     3,    12,
       5,    24,    79,    12,    70,    71,    72,    12,    45,    46,
      43,    79,    43,    19,    96,    50,    49,    43,    49,    96,
      45,    46,     0,    49,    41,    42,    79,     3,    96,     5,
      24,    97,    65,    66,    65,    66,    12,    91,    43,    65,
      66,    45,    46,    96,    49,    45,    46,     3,    91,     5,
      67,    82,    83,    88,    89,    61,    12,    63,    95,    90,
      65,    66,    97,    97,    97,    93,    97,    43,    45,    46,
      95,    97,    95,    49,    97,    45,    46,    82,    83,    11,
      45,    46,    97,    93,    97,    90,    93,    43,    97,    65,
      66,    97,    97,    49,    96,     6,     7,    29,    30,    10,
      92,    95,    34,    97,    36,    93,    82,    83,    19,    65,
      66,    70,    71,    72,    95,    26,    93,    28,    50,    45,
      46,    97,    92,    94,    35,    93,    82,    83,    39,    70,
      71,    72,    30,     8,    76,    77,    11,    91,    97,    85,
      86,    97,    40,    73,    74,    20,    44,   199,   200,    24,
      61,    97,    50,    51,    29,    30,    97,    68,    69,    34,
      93,    36,    37,    38,    93,    97,    92,    78,    43,    80,
      81,    96,    47,    84,    93,    50,    87,    93,    93,    16,
      95,    93,    97,   248,   249,   250,    97,    62,    25,    64,
      27,    89,    73,    74,    31,    32,    33,    48,    93,    97,
      93,    52,    53,    54,    55,    56,    57,    58,    59,    60,
     248,   249,   250,    73,    74,    45,    46,    45,    46,    48,
      45,    46,    97,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    45,    46,    45,    46,    97,    96,    96,    96,
      96,    96,    96,    96,    96,    95,    92,    95,    93,    93,
      91,    91,    91,    91,    96,    24,     8,    93,    93,    91,
      93,    95,    93,   248,   248,    91,    93,   174,   176,    91,
      93,    95,    93,    91,    91,    95,    91,    93,    97,    93,
     359,    93,    91,    91,   178,   332,    93,   250,   248,   330,
      96,    96,    96,    96,    96,    93,    93,    93,    91,    91,
     248,    -1,   334
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    16,    25,    27,    31,    32,    33,    99,   100,   101,
     107,   113,   130,   133,   161,   184,    96,    96,    96,    96,
      96,     0,   101,   114,   131,   162,   134,   185,     3,    12,
      97,   115,    93,    95,    97,   132,     6,     7,    10,    19,
      26,    28,    35,    39,    61,    68,    69,    78,    80,    81,
      84,    87,    97,   102,   103,   104,   105,   106,   125,   126,
     127,   163,   164,   165,   166,   167,   168,   169,   172,   173,
     174,   175,     8,    11,    20,    24,    29,    30,    34,    36,
      37,    38,    43,    47,    50,    62,    64,    97,   108,   109,
     110,   111,   112,   116,   119,   122,   135,   136,   137,   138,
     150,   151,   152,   153,   154,   160,    19,    61,    63,    97,
     186,   187,   188,   189,   190,   191,    91,    91,    93,    93,
      96,    45,    46,    92,    92,    93,    93,    95,    45,    46,
      95,    93,    75,    96,    93,    45,    46,    93,    94,    96,
      45,    46,    79,    96,    93,    79,    96,    79,    96,    93,
      93,    41,    42,    67,    91,    45,    46,   155,    93,    45,
      46,    93,    45,    46,    92,    45,    46,    95,    93,   128,
      76,    77,   176,   170,    96,   117,    96,   120,    96,   123,
      96,    96,    96,    48,    52,    53,    54,    55,    56,    57,
      58,    59,    60,   157,   159,     9,    17,    97,   129,    96,
      96,    70,    71,    72,    97,   177,    85,    86,    97,   171,
     117,     3,     4,    12,    13,    17,    18,    43,    49,    65,
      66,    97,   118,   120,     3,     5,    12,    43,    49,    65,
      66,    82,    83,    97,   121,   123,     3,     5,    12,    43,
      49,    65,    66,    82,    83,    90,    97,   124,   139,   141,
     143,    95,   156,    92,    93,   176,   176,    73,    74,    73,
      74,    73,    74,    95,    93,    97,    91,    91,    91,    91,
      93,    93,    45,    46,    95,    93,    93,    97,    91,    93,
      91,    45,    46,    95,    93,    93,    91,    91,    97,    91,
      93,    91,    45,    46,    95,    93,    93,    91,    91,    93,
      97,   108,   109,   110,   111,   140,   151,   152,    40,    44,
      51,    89,    97,   110,   111,   142,   146,   147,   148,   149,
      88,    97,   110,   111,   144,   145,   146,    97,    97,    96,
      96,    96,    96,    96,    96,    93,    93,    93,    45,    46,
      45,    46,   180,   180,   178,   178,   182,   182,     3,    12,
      97,   181,    97,    24,    95,    97,   179,    97,    97,   158,
     183,    97,    91,    91,    48,   159,    24
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */


/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{


    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 12:

/* Line 1455 of yacc.c  */
#line 101 "read_config_yy.y"
    {
	strncpy(conf.logfile, DEFAULT_LOGFILE, FILENAME_MAXLEN);
}
    break;

  case 13:

/* Line 1455 of yacc.c  */
#line 106 "read_config_yy.y"
    {
}
    break;

  case 14:

/* Line 1455 of yacc.c  */
#line 110 "read_config_yy.y"
    {
	strncpy(conf.logfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 15:

/* Line 1455 of yacc.c  */
#line 115 "read_config_yy.y"
    {
	conf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
}
    break;

  case 16:

/* Line 1455 of yacc.c  */
#line 120 "read_config_yy.y"
    {
	conf.syslog_facility = -1;
}
    break;

  case 17:

/* Line 1455 of yacc.c  */
#line 125 "read_config_yy.y"
    {
	if (!strcmp((yyvsp[(2) - (2)].string), "daemon"))
		conf.syslog_facility = LOG_DAEMON;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local0"))
		conf.syslog_facility = LOG_LOCAL0;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local1"))
		conf.syslog_facility = LOG_LOCAL1;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local2"))
		conf.syslog_facility = LOG_LOCAL2;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local3"))
		conf.syslog_facility = LOG_LOCAL3;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local4"))
		conf.syslog_facility = LOG_LOCAL4;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local5"))
		conf.syslog_facility = LOG_LOCAL5;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local6"))
		conf.syslog_facility = LOG_LOCAL6;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local7"))
		conf.syslog_facility = LOG_LOCAL7;
	else {
		print_err(CTD_CFG_WARN, "'%s' is not a known syslog facility, "
					"ignoring", (yyvsp[(2) - (2)].string));
		break;
	}

	if (conf.stats.syslog_facility != -1 &&
	    conf.syslog_facility != conf.stats.syslog_facility)
	    	print_err(CTD_CFG_WARN, "conflicting Syslog facility "
					"values, defaulting to General");
}
    break;

  case 18:

/* Line 1455 of yacc.c  */
#line 157 "read_config_yy.y"
    {
	strncpy(conf.lockfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 19:

/* Line 1455 of yacc.c  */
#line 162 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`StripNAT' clause is obsolete, ignoring");
}
    break;

  case 20:

/* Line 1455 of yacc.c  */
#line 167 "read_config_yy.y"
    {
	conf.refresh = (yyvsp[(2) - (2)].val);
}
    break;

  case 21:

/* Line 1455 of yacc.c  */
#line 172 "read_config_yy.y"
    {
	conf.cache_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 22:

/* Line 1455 of yacc.c  */
#line 177 "read_config_yy.y"
    {
	conf.commit_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 23:

/* Line 1455 of yacc.c  */
#line 182 "read_config_yy.y"
    {
	conf.purge_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 24:

/* Line 1455 of yacc.c  */
#line 187 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "the use of `Checksum' outside the "
				"`Multicast' clause is ambiguous");
	/* 
	 * XXX: The use of Checksum outside of the Multicast clause is broken
	 *	if we have more than one dedicated links.
	 */
	conf.channel[0].u.mcast.checksum = 0;
}
    break;

  case 25:

/* Line 1455 of yacc.c  */
#line 198 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "the use of `Checksum' outside the "
				"`Multicast' clause is ambiguous");
	/*
	 * XXX: The use of Checksum outside of the Multicast clause is broken
	 *	if we have more than one dedicated links.
	 */
	conf.channel[0].u.mcast.checksum = 1;
}
    break;

  case 26:

/* Line 1455 of yacc.c  */
#line 209 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_NEGATIVE);

	print_err(CTD_CFG_WARN, "the clause `IgnoreTrafficFor' is obsolete. "
				"Use `Filter' instead");
}
    break;

  case 29:

/* Line 1455 of yacc.c  */
#line 222 "read_config_yy.y"
    {
	union inet_address ip;

	memset(&ip, 0, sizeof(union inet_address));

	if (!inet_aton((yyvsp[(2) - (2)].string), &ip.ipv4)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4, "
					"ignoring", (yyvsp[(2) - (2)].string));
		break;
	}

	if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET)) {
		if (errno == EEXIST)
			print_err(CTD_CFG_WARN, "IP %s is repeated "
						"in the ignore pool", (yyvsp[(2) - (2)].string));
		if (errno == ENOSPC)
			print_err(CTD_CFG_WARN, "too many IP in the "
						"ignore pool!");
	}
}
    break;

  case 30:

/* Line 1455 of yacc.c  */
#line 244 "read_config_yy.y"
    {
	union inet_address ip;

	memset(&ip, 0, sizeof(union inet_address));

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string), &ip.ipv6) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6, ignoring", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
#endif

	if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET6)) {
		if (errno == EEXIST)
			print_err(CTD_CFG_WARN, "IP %s is repeated "
						"in the ignore pool", (yyvsp[(2) - (2)].string));
		if (errno == ENOSPC)
			print_err(CTD_CFG_WARN, "too many IP in the "
						"ignore pool!");
	}

}
    break;

  case 31:

/* Line 1455 of yacc.c  */
#line 270 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_MCAST) {
		print_err(CTD_CFG_ERROR, "cannot use `Multicast' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_MCAST;
	conf.channel[conf.channel_num].channel_type = CHANNEL_MCAST;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_BUFFERED;
	conf.channel_num++;
}
    break;

  case 32:

/* Line 1455 of yacc.c  */
#line 284 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_MCAST) {
		print_err(CTD_CFG_ERROR, "cannot use `Multicast' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_MCAST;
	conf.channel[conf.channel_num].channel_type = CHANNEL_MCAST;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_DEFAULT |
						       CHANNEL_F_BUFFERED;
	conf.channel_default = conf.channel_num;
	conf.channel_num++;
}
    break;

  case 35:

/* Line 1455 of yacc.c  */
#line 303 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.mcast.in)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}

        if (conf.channel[conf.channel_num].u.mcast.ipproto == AF_INET6) {
		print_err(CTD_CFG_WARN, "your multicast address is IPv4 but "
					"is binded to an IPv6 interface? "
					"Surely, this is not what you want");
		break;
	}

	conf.channel[conf.channel_num].u.mcast.ipproto = AF_INET;
}
    break;

  case 36:

/* Line 1455 of yacc.c  */
#line 322 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string),
		      &conf.channel[conf.channel_num].u.mcast.in) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6 address", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif

	if (conf.channel[conf.channel_num].u.mcast.ipproto == AF_INET) {
		print_err(CTD_CFG_WARN, "your multicast address is IPv6 but "
					"is binded to an IPv4 interface? "
					"Surely this is not what you want");
		break;
	}

	conf.channel[conf.channel_num].u.mcast.ipproto = AF_INET6;

	if (conf.channel[conf.channel_num].channel_ifname[0] &&
	    !conf.channel[conf.channel_num].u.mcast.ifa.interface_index6) {
		unsigned int idx;

		idx = if_nametoindex((yyvsp[(2) - (2)].string));
		if (!idx) {
			print_err(CTD_CFG_WARN,
				  "%s is an invalid interface", (yyvsp[(2) - (2)].string));
			break;
		}

		conf.channel[conf.channel_num].u.mcast.ifa.interface_index6 = idx;
		conf.channel[conf.channel_num].u.mcast.ipproto = AF_INET6;
	}
}
    break;

  case 37:

/* Line 1455 of yacc.c  */
#line 362 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.mcast.ifa)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}

        if (conf.channel[conf.channel_num].u.mcast.ipproto == AF_INET6) {
		print_err(CTD_CFG_WARN, "your multicast interface is IPv4 but "
					"is binded to an IPv6 interface? "
					"Surely, this is not what you want");
		break;
	}

	conf.channel[conf.channel_num].u.mcast.ipproto = AF_INET;
}
    break;

  case 38:

/* Line 1455 of yacc.c  */
#line 381 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`IPv6_interface' not required, ignoring");
}
    break;

  case 39:

/* Line 1455 of yacc.c  */
#line 386 "read_config_yy.y"
    {
	unsigned int idx;

	__max_dedicated_links_reached();

	strncpy(conf.channel[conf.channel_num].channel_ifname, (yyvsp[(2) - (2)].string), IFNAMSIZ);

	idx = if_nametoindex((yyvsp[(2) - (2)].string));
	if (!idx) {
		print_err(CTD_CFG_WARN, "%s is an invalid interface", (yyvsp[(2) - (2)].string));
		break;
	}

	if (conf.channel[conf.channel_num].u.mcast.ipproto == AF_INET6) {
		conf.channel[conf.channel_num].u.mcast.ifa.interface_index6 = idx;
		conf.channel[conf.channel_num].u.mcast.ipproto = AF_INET6;
	}
}
    break;

  case 40:

/* Line 1455 of yacc.c  */
#line 406 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`Backlog' option inside Multicast clause is "
				"obsolete. Please, remove it from "
				"conntrackd.conf");
}
    break;

  case 41:

/* Line 1455 of yacc.c  */
#line 413 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 42:

/* Line 1455 of yacc.c  */
#line 419 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 43:

/* Line 1455 of yacc.c  */
#line 425 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 44:

/* Line 1455 of yacc.c  */
#line 431 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.checksum = 0;
}
    break;

  case 45:

/* Line 1455 of yacc.c  */
#line 437 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.checksum = 1;
}
    break;

  case 46:

/* Line 1455 of yacc.c  */
#line 443 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_UDP) {
		print_err(CTD_CFG_ERROR, "cannot use `UDP' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_UDP;
	conf.channel[conf.channel_num].channel_type = CHANNEL_UDP;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_BUFFERED;
	conf.channel_num++;
}
    break;

  case 47:

/* Line 1455 of yacc.c  */
#line 457 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_UDP) {
		print_err(CTD_CFG_ERROR, "cannot use `UDP' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_UDP;
	conf.channel[conf.channel_num].channel_type = CHANNEL_UDP;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_DEFAULT |
						       CHANNEL_F_BUFFERED;
	conf.channel_default = conf.channel_num;
	conf.channel_num++;
}
    break;

  case 50:

/* Line 1455 of yacc.c  */
#line 476 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.udp.server.ipv4)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.udp.ipproto = AF_INET;
}
    break;

  case 51:

/* Line 1455 of yacc.c  */
#line 487 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string),
		      &conf.channel[conf.channel_num].u.udp.server.ipv6) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6 address", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	conf.channel[conf.channel_num].u.udp.ipproto = AF_INET6;
}
    break;

  case 52:

/* Line 1455 of yacc.c  */
#line 504 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.udp.client)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.udp.ipproto = AF_INET;
}
    break;

  case 53:

/* Line 1455 of yacc.c  */
#line 515 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string),
		      &conf.channel[conf.channel_num].u.udp.client) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6 address", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	conf.channel[conf.channel_num].u.udp.ipproto = AF_INET6;
}
    break;

  case 54:

/* Line 1455 of yacc.c  */
#line 532 "read_config_yy.y"
    {
	int idx;

	__max_dedicated_links_reached();
	strncpy(conf.channel[conf.channel_num].channel_ifname, (yyvsp[(2) - (2)].string), IFNAMSIZ);

	idx = if_nametoindex((yyvsp[(2) - (2)].string));
	if (!idx) {
		print_err(CTD_CFG_WARN, "%s is an invalid interface", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.udp.server.ipv6.scope_id = idx;
}
    break;

  case 55:

/* Line 1455 of yacc.c  */
#line 547 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 56:

/* Line 1455 of yacc.c  */
#line 553 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 57:

/* Line 1455 of yacc.c  */
#line 559 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 58:

/* Line 1455 of yacc.c  */
#line 565 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.checksum = 0;
}
    break;

  case 59:

/* Line 1455 of yacc.c  */
#line 571 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.checksum = 1;
}
    break;

  case 60:

/* Line 1455 of yacc.c  */
#line 577 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_TCP) {
		print_err(CTD_CFG_ERROR, "cannot use `TCP' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_TCP;
	conf.channel[conf.channel_num].channel_type = CHANNEL_TCP;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_BUFFERED |
						       CHANNEL_F_STREAM |
						       CHANNEL_F_ERRORS;
	conf.channel_num++;
}
    break;

  case 61:

/* Line 1455 of yacc.c  */
#line 593 "read_config_yy.y"
    {
	if (conf.channel_type_global != CHANNEL_NONE &&
	    conf.channel_type_global != CHANNEL_TCP) {
		print_err(CTD_CFG_ERROR, "cannot use `TCP' with other "
					 "dedicated link protocols!");
		exit(EXIT_FAILURE);
	}
	conf.channel_type_global = CHANNEL_TCP;
	conf.channel[conf.channel_num].channel_type = CHANNEL_TCP;
	conf.channel[conf.channel_num].channel_flags = CHANNEL_F_DEFAULT |
						       CHANNEL_F_BUFFERED |
						       CHANNEL_F_STREAM |
						       CHANNEL_F_ERRORS;
	conf.channel_default = conf.channel_num;
	conf.channel_num++;
}
    break;

  case 64:

/* Line 1455 of yacc.c  */
#line 614 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.tcp.server.ipv4)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.tcp.ipproto = AF_INET;
}
    break;

  case 65:

/* Line 1455 of yacc.c  */
#line 625 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string),
		      &conf.channel[conf.channel_num].u.tcp.server.ipv6) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6 address", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	conf.channel[conf.channel_num].u.tcp.ipproto = AF_INET6;
}
    break;

  case 66:

/* Line 1455 of yacc.c  */
#line 642 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

	if (!inet_aton((yyvsp[(2) - (2)].string), &conf.channel[conf.channel_num].u.tcp.client)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4 address", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.tcp.ipproto = AF_INET;
}
    break;

  case 67:

/* Line 1455 of yacc.c  */
#line 653 "read_config_yy.y"
    {
	__max_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string),
		      &conf.channel[conf.channel_num].u.tcp.client) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6 address", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	conf.channel[conf.channel_num].u.tcp.ipproto = AF_INET6;
}
    break;

  case 68:

/* Line 1455 of yacc.c  */
#line 670 "read_config_yy.y"
    {
	int idx;

	__max_dedicated_links_reached();
	strncpy(conf.channel[conf.channel_num].channel_ifname, (yyvsp[(2) - (2)].string), IFNAMSIZ);

	idx = if_nametoindex((yyvsp[(2) - (2)].string));
	if (!idx) {
		print_err(CTD_CFG_WARN, "%s is an invalid interface", (yyvsp[(2) - (2)].string));
		break;
	}
	conf.channel[conf.channel_num].u.tcp.server.ipv6.scope_id = idx;
}
    break;

  case 69:

/* Line 1455 of yacc.c  */
#line 685 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 70:

/* Line 1455 of yacc.c  */
#line 691 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 71:

/* Line 1455 of yacc.c  */
#line 697 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 72:

/* Line 1455 of yacc.c  */
#line 703 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.checksum = 0;
}
    break;

  case 73:

/* Line 1455 of yacc.c  */
#line 709 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.checksum = 1;
}
    break;

  case 74:

/* Line 1455 of yacc.c  */
#line 715 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	CONFIG(channelc).error_queue_length = (yyvsp[(2) - (2)].val);
}
    break;

  case 75:

/* Line 1455 of yacc.c  */
#line 721 "read_config_yy.y"
    {
	conf.hashsize = (yyvsp[(2) - (2)].val);
}
    break;

  case 76:

/* Line 1455 of yacc.c  */
#line 726 "read_config_yy.y"
    {
	conf.limit = (yyvsp[(2) - (2)].val);
}
    break;

  case 80:

/* Line 1455 of yacc.c  */
#line 737 "read_config_yy.y"
    {
	strcpy(conf.local.path, (yyvsp[(2) - (2)].string));
}
    break;

  case 81:

/* Line 1455 of yacc.c  */
#line 742 "read_config_yy.y"
    {
	conf.local.backlog = (yyvsp[(2) - (2)].val);
}
    break;

  case 82:

/* Line 1455 of yacc.c  */
#line 747 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_NEGATIVE);

	print_err(CTD_CFG_WARN, "the clause `IgnoreProtocol' is "
				"obsolete. Use `Filter' instead");
}
    break;

  case 85:

/* Line 1455 of yacc.c  */
#line 761 "read_config_yy.y"
    {
	if ((yyvsp[(1) - (1)].val) < IPPROTO_MAX)
		ct_filter_add_proto(STATE(us_filter), (yyvsp[(1) - (1)].val));
	else
		print_err(CTD_CFG_WARN, "protocol number `%d' is freak", (yyvsp[(1) - (1)].val));
}
    break;

  case 86:

/* Line 1455 of yacc.c  */
#line 769 "read_config_yy.y"
    {
	struct protoent *pent;

	pent = getprotobyname((yyvsp[(1) - (1)].string));
	if (pent == NULL) {
		print_err(CTD_CFG_WARN, "getprotobyname() cannot find "
					"protocol `%s' in /etc/protocols", (yyvsp[(1) - (1)].string));
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);
}
    break;

  case 87:

/* Line 1455 of yacc.c  */
#line 782 "read_config_yy.y"
    {
	if (conf.flags & CTD_STATS_MODE) {
		print_err(CTD_CFG_ERROR, "cannot use both `Stats' and `Sync' "
					 "clauses in conntrackd.conf");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_SYNC_MODE;
}
    break;

  case 107:

/* Line 1455 of yacc.c  */
#line 814 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_ALARM;
}
    break;

  case 108:

/* Line 1455 of yacc.c  */
#line 819 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_FTFW;
}
    break;

  case 109:

/* Line 1455 of yacc.c  */
#line 824 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_NOTRACK;
}
    break;

  case 132:

/* Line 1455 of yacc.c  */
#line 860 "read_config_yy.y"
    {
	conf.sync.internal_cache_disable = 1;
}
    break;

  case 133:

/* Line 1455 of yacc.c  */
#line 865 "read_config_yy.y"
    {
	conf.sync.internal_cache_disable = 0;
}
    break;

  case 134:

/* Line 1455 of yacc.c  */
#line 870 "read_config_yy.y"
    {
	conf.sync.external_cache_disable = 1;
}
    break;

  case 135:

/* Line 1455 of yacc.c  */
#line 875 "read_config_yy.y"
    {
	conf.sync.external_cache_disable = 0;
}
    break;

  case 136:

/* Line 1455 of yacc.c  */
#line 880 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`ResendBufferSize' is deprecated. "
				"Use `ResendQueueSize' instead");
}
    break;

  case 137:

/* Line 1455 of yacc.c  */
#line 886 "read_config_yy.y"
    {
	conf.resend_queue_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 138:

/* Line 1455 of yacc.c  */
#line 891 "read_config_yy.y"
    {
	conf.window_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 139:

/* Line 1455 of yacc.c  */
#line 896 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`DestroyTimeout' is deprecated. Remove it");
}
    break;

  case 140:

/* Line 1455 of yacc.c  */
#line 901 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`RelaxTransitions' clause is obsolete. "
				"Please, remove it from conntrackd.conf");
}
    break;

  case 141:

/* Line 1455 of yacc.c  */
#line 907 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`DelayDestroyMessages' clause is obsolete. "
				"Please, remove it from conntrackd.conf");
}
    break;

  case 142:

/* Line 1455 of yacc.c  */
#line 913 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "the clause `ListenTo' is obsolete, ignoring");
}
    break;

  case 143:

/* Line 1455 of yacc.c  */
#line 918 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	print_err(CTD_CFG_WARN, "the clause `Replicate' is obsolete. "
				"Use `Filter' instead");
}
    break;

  case 146:

/* Line 1455 of yacc.c  */
#line 931 "read_config_yy.y"
    {
	if (strncmp((yyvsp[(1) - (1)].string), "TCP", strlen("TCP")) != 0) {
		print_err(CTD_CFG_WARN, "unsupported protocol `%s' in line %d",
					(yyvsp[(1) - (1)].string), yylineno);
	}
}
    break;

  case 150:

/* Line 1455 of yacc.c  */
#line 943 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_SENT);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_SENT);
}
    break;

  case 151:

/* Line 1455 of yacc.c  */
#line 951 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_RECV);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_RECV);
}
    break;

  case 152:

/* Line 1455 of yacc.c  */
#line 959 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_ESTABLISHED);

	__kernel_filter_add_state(TCP_CONNTRACK_ESTABLISHED);
}
    break;

  case 153:

/* Line 1455 of yacc.c  */
#line 967 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_FIN_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_FIN_WAIT);
}
    break;

  case 154:

/* Line 1455 of yacc.c  */
#line 975 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE_WAIT);
}
    break;

  case 155:

/* Line 1455 of yacc.c  */
#line 983 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LAST_ACK);

	__kernel_filter_add_state(TCP_CONNTRACK_LAST_ACK);
}
    break;

  case 156:

/* Line 1455 of yacc.c  */
#line 991 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_TIME_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_TIME_WAIT);
}
    break;

  case 157:

/* Line 1455 of yacc.c  */
#line 999 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE);
}
    break;

  case 158:

/* Line 1455 of yacc.c  */
#line 1007 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LISTEN);

	__kernel_filter_add_state(TCP_CONNTRACK_LISTEN);
}
    break;

  case 159:

/* Line 1455 of yacc.c  */
#line 1016 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`CacheWriteThrough' clause is obsolete, "
				"ignoring");
}
    break;

  case 160:

/* Line 1455 of yacc.c  */
#line 1022 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`CacheWriteThrough' clause is obsolete, "
				"ignoring");
}
    break;

  case 182:

/* Line 1455 of yacc.c  */
#line 1054 "read_config_yy.y"
    {
	conf.netlink_buffer_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 183:

/* Line 1455 of yacc.c  */
#line 1059 "read_config_yy.y"
    {
	conf.netlink_buffer_size_max_grown = (yyvsp[(2) - (2)].val);
}
    break;

  case 184:

/* Line 1455 of yacc.c  */
#line 1064 "read_config_yy.y"
    {
	conf.nl_overrun_resync = 30;
}
    break;

  case 185:

/* Line 1455 of yacc.c  */
#line 1069 "read_config_yy.y"
    {
	conf.nl_overrun_resync = -1;
}
    break;

  case 186:

/* Line 1455 of yacc.c  */
#line 1074 "read_config_yy.y"
    {
	conf.nl_overrun_resync = (yyvsp[(2) - (2)].val);
}
    break;

  case 187:

/* Line 1455 of yacc.c  */
#line 1079 "read_config_yy.y"
    {
	conf.netlink.events_reliable = 1;
}
    break;

  case 188:

/* Line 1455 of yacc.c  */
#line 1084 "read_config_yy.y"
    {
	conf.netlink.events_reliable = 0;
}
    break;

  case 189:

/* Line 1455 of yacc.c  */
#line 1089 "read_config_yy.y"
    {
	conf.nice = (yyvsp[(2) - (2)].val);
}
    break;

  case 193:

/* Line 1455 of yacc.c  */
#line 1100 "read_config_yy.y"
    {
	if (strcasecmp((yyvsp[(2) - (2)].string), "rr") == 0) {
		conf.sched.type = SCHED_RR;
	} else if (strcasecmp((yyvsp[(2) - (2)].string), "fifo") == 0) {
		conf.sched.type = SCHED_FIFO;
	} else {
		print_err(CTD_CFG_ERROR, "unknown scheduler `%s'", (yyvsp[(2) - (2)].string));
		exit(EXIT_FAILURE);
	}
}
    break;

  case 194:

/* Line 1455 of yacc.c  */
#line 1112 "read_config_yy.y"
    {
	conf.sched.prio = (yyvsp[(2) - (2)].val);
	if (conf.sched.prio < 0 || conf.sched.prio > 99) {
		print_err(CTD_CFG_ERROR, "`Priority' must be [0, 99]\n", (yyvsp[(2) - (2)].val));
		exit(EXIT_FAILURE);
	}
}
    break;

  case 195:

/* Line 1455 of yacc.c  */
#line 1121 "read_config_yy.y"
    {
	if (strncmp((yyvsp[(2) - (2)].string), "IPv6", strlen("IPv6")) == 0)
		conf.family = AF_INET6;
	else
		conf.family = AF_INET;
}
    break;

  case 196:

/* Line 1455 of yacc.c  */
#line 1129 "read_config_yy.y"
    {
	CONFIG(event_iterations_limit) = (yyvsp[(2) - (2)].val);
}
    break;

  case 197:

/* Line 1455 of yacc.c  */
#line 1134 "read_config_yy.y"
    {
	conf.flags |= CTD_POLL;
	conf.poll_kernel_secs = (yyvsp[(2) - (2)].val);
	if (conf.poll_kernel_secs == 0) {
		print_err(CTD_CFG_ERROR, "`PollSecs' clause must be > 0");
		exit(EXIT_FAILURE);
	}
}
    break;

  case 198:

/* Line 1455 of yacc.c  */
#line 1144 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 0;
}
    break;

  case 199:

/* Line 1455 of yacc.c  */
#line 1149 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 0;
}
    break;

  case 200:

/* Line 1455 of yacc.c  */
#line 1154 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 1;
}
    break;

  case 203:

/* Line 1455 of yacc.c  */
#line 1162 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 204:

/* Line 1455 of yacc.c  */
#line 1171 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_NEGATIVE);

	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_L4PROTO,
			      NFCT_FILTER_LOGIC_NEGATIVE);
}
    break;

  case 207:

/* Line 1455 of yacc.c  */
#line 1187 "read_config_yy.y"
    {
	struct protoent *pent;

	pent = getprotobyname((yyvsp[(1) - (1)].string));
	if (pent == NULL) {
		print_err(CTD_CFG_WARN, "getprotobyname() cannot find "
					"protocol `%s' in /etc/protocols", (yyvsp[(1) - (1)].string));
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);

	__kernel_filter_start();

	nfct_filter_add_attr_u32(STATE(filter),
				 NFCT_FILTER_L4PROTO,
				 pent->p_proto);
}
    break;

  case 208:

/* Line 1455 of yacc.c  */
#line 1206 "read_config_yy.y"
    {
	struct protoent *pent;

	pent = getprotobyname("tcp");
	if (pent == NULL) {
		print_err(CTD_CFG_WARN, "getprotobyname() cannot find "
					"protocol `tcp' in /etc/protocols");
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);

	__kernel_filter_start();

	nfct_filter_add_attr_u32(STATE(filter),
				 NFCT_FILTER_L4PROTO,
				 pent->p_proto);
}
    break;

  case 209:

/* Line 1455 of yacc.c  */
#line 1225 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 210:

/* Line 1455 of yacc.c  */
#line 1234 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_NEGATIVE);

	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_SRC_IPV4,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_DST_IPV4,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_SRC_IPV6,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_DST_IPV6,
			      NFCT_FILTER_LOGIC_NEGATIVE);
}
    break;

  case 213:

/* Line 1455 of yacc.c  */
#line 1259 "read_config_yy.y"
    {
	union inet_address ip;
	char *slash;
	unsigned int cidr = 32;

	memset(&ip, 0, sizeof(union inet_address));

	slash = strchr((yyvsp[(2) - (2)].string), '/');
	if (slash) {
		*slash = '\0';
		cidr = atoi(slash+1);
		if (cidr > 32) {
			print_err(CTD_CFG_WARN, "%s/%d is not a valid network, "
						"ignoring", (yyvsp[(2) - (2)].string), cidr);
			break;
		}
	}

	if (!inet_aton((yyvsp[(2) - (2)].string), &ip.ipv4)) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv4, ignoring", (yyvsp[(2) - (2)].string));
		break;
	}

	if (slash && cidr < 32) {
		/* network byte order */
		struct ct_filter_netmask_ipv4 tmp = {
			.ip = ip.ipv4,
			.mask = ipv4_cidr2mask_net(cidr)
		};

		if (!ct_filter_add_netmask(STATE(us_filter), &tmp, AF_INET)) {
			if (errno == EEXIST)
				print_err(CTD_CFG_WARN, "netmask %s is "
							"repeated in the "
							"ignore pool", (yyvsp[(2) - (2)].string));
		}
	} else {
		if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET)) {
			if (errno == EEXIST)
				print_err(CTD_CFG_WARN, "IP %s is repeated in "
							"the ignore pool", (yyvsp[(2) - (2)].string));
			if (errno == ENOSPC)
				print_err(CTD_CFG_WARN, "too many IP in the "
							"ignore pool!");
		}
	}
	__kernel_filter_start();

	/* host byte order */
	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = ntohl(ip.ipv4),
		.mask = ipv4_cidr2mask_host(cidr),
	};

	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_SRC_IPV4, &filter_ipv4);
	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_DST_IPV4, &filter_ipv4);
}
    break;

  case 214:

/* Line 1455 of yacc.c  */
#line 1318 "read_config_yy.y"
    {
	union inet_address ip;
	char *slash;
	int cidr = 128;
	struct nfct_filter_ipv6 filter_ipv6;

	memset(&ip, 0, sizeof(union inet_address));

	slash = strchr((yyvsp[(2) - (2)].string), '/');
	if (slash) {
		*slash = '\0';
		cidr = atoi(slash+1);
		if (cidr > 128) {
			print_err(CTD_CFG_WARN, "%s/%d is not a valid network, "
						"ignoring", (yyvsp[(2) - (2)].string), cidr);
			break;
		}
	}

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, (yyvsp[(2) - (2)].string), &ip.ipv6) <= 0) {
		print_err(CTD_CFG_WARN, "%s is not a valid IPv6, ignoring", (yyvsp[(2) - (2)].string));
		break;
	}
#else
	print_err(CTD_CFG_WARN, "cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	if (slash && cidr < 128) {
		struct ct_filter_netmask_ipv6 tmp;

		memcpy(tmp.ip, ip.ipv6, sizeof(uint32_t)*4);
		ipv6_cidr2mask_net(cidr, tmp.mask);
		if (!ct_filter_add_netmask(STATE(us_filter), &tmp, AF_INET6)) {
			if (errno == EEXIST)
				print_err(CTD_CFG_WARN, "netmask %s is "
							"repeated in the "
							"ignore pool", (yyvsp[(2) - (2)].string));
		}
	} else {
		if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET6)) {
			if (errno == EEXIST)
				print_err(CTD_CFG_WARN, "IP %s is repeated in "
							"the ignore pool", (yyvsp[(2) - (2)].string));
			if (errno == ENOSPC)
				print_err(CTD_CFG_WARN, "too many IP in the "
							"ignore pool!");
		}
	}
	__kernel_filter_start();

	/* host byte order */
	ipv6_addr2addr_host(ip.ipv6, filter_ipv6.addr);
	ipv6_cidr2mask_host(cidr, filter_ipv6.mask);

	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_SRC_IPV6, &filter_ipv6);
	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_DST_IPV6, &filter_ipv6);
}
    break;

  case 215:

/* Line 1455 of yacc.c  */
#line 1378 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 216:

/* Line 1455 of yacc.c  */
#line 1387 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_NEGATIVE);


	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_L4PROTO_STATE,
			      NFCT_FILTER_LOGIC_NEGATIVE);
}
    break;

  case 220:

/* Line 1455 of yacc.c  */
#line 1406 "read_config_yy.y"
    {
	if (conf.flags & CTD_SYNC_MODE) {
		print_err(CTD_CFG_ERROR, "cannot use both `Stats' and `Sync' "
					 "clauses in conntrackd.conf");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_STATS_MODE;
}
    break;

  case 228:

/* Line 1455 of yacc.c  */
#line 1427 "read_config_yy.y"
    {
	strncpy(conf.stats.logfile, DEFAULT_STATS_LOGFILE, FILENAME_MAXLEN);
}
    break;

  case 229:

/* Line 1455 of yacc.c  */
#line 1432 "read_config_yy.y"
    {
}
    break;

  case 230:

/* Line 1455 of yacc.c  */
#line 1436 "read_config_yy.y"
    {
	strncpy(conf.stats.logfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 231:

/* Line 1455 of yacc.c  */
#line 1441 "read_config_yy.y"
    {
	conf.stats.syslog_facility = DEFAULT_SYSLOG_FACILITY;
}
    break;

  case 232:

/* Line 1455 of yacc.c  */
#line 1446 "read_config_yy.y"
    {
	conf.stats.syslog_facility = -1;
}
    break;

  case 233:

/* Line 1455 of yacc.c  */
#line 1451 "read_config_yy.y"
    {
	if (!strcmp((yyvsp[(2) - (2)].string), "daemon"))
		conf.stats.syslog_facility = LOG_DAEMON;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local0"))
		conf.stats.syslog_facility = LOG_LOCAL0;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local1"))
		conf.stats.syslog_facility = LOG_LOCAL1;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local2"))
		conf.stats.syslog_facility = LOG_LOCAL2;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local3"))
		conf.stats.syslog_facility = LOG_LOCAL3;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local4"))
		conf.stats.syslog_facility = LOG_LOCAL4;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local5"))
		conf.stats.syslog_facility = LOG_LOCAL5;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local6"))
		conf.stats.syslog_facility = LOG_LOCAL6;
	else if (!strcmp((yyvsp[(2) - (2)].string), "local7"))
		conf.stats.syslog_facility = LOG_LOCAL7;
	else {
		print_err(CTD_CFG_WARN, "'%s' is not a known syslog facility, "
					"ignoring.", (yyvsp[(2) - (2)].string));
		break;
	}

	if (conf.syslog_facility != -1 &&
	    conf.stats.syslog_facility != conf.syslog_facility)
		print_err(CTD_CFG_WARN, "conflicting Syslog facility "
					"values, defaulting to General");
}
    break;

  case 234:

/* Line 1455 of yacc.c  */
#line 1483 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`LogFileBufferSize' is deprecated");
}
    break;



/* Line 1455 of yacc.c  */
#line 3712 "read_config_yy.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



/* Line 1675 of yacc.c  */
#line 1487 "read_config_yy.y"


int __attribute__((noreturn))
yyerror(char *msg)
{
	print_err(CTD_CFG_ERROR, "parsing config file in "
				 "line (%d), symbol '%s': %s",
				 yylineno, yytext, msg);
	exit(EXIT_FAILURE);
}

static void print_err(int type, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	switch(type) {
	case CTD_CFG_ERROR:
		fprintf(stderr, "ERROR: ");
		break;
	case CTD_CFG_WARN:
		fprintf(stderr, "WARNING: ");
		break;
	default:
		fprintf(stderr, "?: ");
	}
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr,"\n");
}

static void __kernel_filter_start(void)
{
	if (!STATE(filter)) {
		STATE(filter) = nfct_filter_create();
		if (!STATE(filter)) {
			print_err(CTD_CFG_ERROR, "cannot create ignore pool!");
			exit(EXIT_FAILURE);
		}
	}
}

static void __kernel_filter_add_state(int value)
{
	__kernel_filter_start();

	struct nfct_filter_proto filter_proto = {
		.proto = IPPROTO_TCP,
		.state = value
	};
	nfct_filter_add_attr(STATE(filter),
			     NFCT_FILTER_L4PROTO_STATE,
			     &filter_proto);
}

static void __max_dedicated_links_reached(void)
{
	if (conf.channel_num >= MULTICHANNEL_MAX) {
		print_err(CTD_CFG_ERROR, "too many dedicated links in "
					 "the configuration file "
					 "(Maximum: %d)", MULTICHANNEL_MAX);
		exit(EXIT_FAILURE);
	}
}

int
init_config(char *filename)
{
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	/* Zero may be a valid facility */
	CONFIG(syslog_facility) = -1;
	CONFIG(stats).syslog_facility = -1;

	yyrestart(fp);
	yyparse();
	fclose(fp);

	/* default to IPv4 */
	if (CONFIG(family) == 0)
		CONFIG(family) = AF_INET;

	/* set to default is not specified */
	if (strcmp(CONFIG(lockfile), "") == 0)
		strncpy(CONFIG(lockfile), DEFAULT_LOCKFILE, FILENAME_MAXLEN);

	/* default to 180 seconds of expiration time: cache entries */
	if (CONFIG(cache_timeout) == 0)
		CONFIG(cache_timeout) = 180;

	/* default to 60 seconds: purge kernel entries */
	if (CONFIG(purge_timeout) == 0)
		CONFIG(purge_timeout) = 60;

	/* default to 60 seconds of refresh time */
	if (CONFIG(refresh) == 0)
		CONFIG(refresh) = 60;

	if (CONFIG(resend_queue_size) == 0)
		CONFIG(resend_queue_size) = 131072;

	/* default to a window size of 300 packets */
	if (CONFIG(window_size) == 0)
		CONFIG(window_size) = 300;

	if (CONFIG(event_iterations_limit) == 0)
		CONFIG(event_iterations_limit) = 100;

	/* default number of bucket of the hashtable that are committed in
	   one run loop. XXX: no option available to tune this value yet. */
	if (CONFIG(general).commit_steps == 0)
		CONFIG(general).commit_steps = 64;

	/* if overrun, automatically resync with kernel after 30 seconds */
	if (CONFIG(nl_overrun_resync) == 0)
		CONFIG(nl_overrun_resync) = 30;

	/* default to 128 elements in the channel error queue */
	if (CONFIG(channelc).error_queue_length == 0)
		CONFIG(channelc).error_queue_length = 128;

	return 0;
}

