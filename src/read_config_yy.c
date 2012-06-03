/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison implementation for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
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
#define YYBISON_VERSION "2.5"

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

/* Line 268 of yacc.c  */
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


/* Line 268 of yacc.c  */
#line 124 "read_config_yy.c"

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
     T_OPTIONS = 346,
     T_TCP_WINDOW_TRACKING = 347,
     T_EXPECT_SYNC = 348,
     T_IP = 349,
     T_PATH_VAL = 350,
     T_NUMBER = 351,
     T_SIGNED_NUMBER = 352,
     T_STRING = 353
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
#define T_OPTIONS 346
#define T_TCP_WINDOW_TRACKING 347
#define T_EXPECT_SYNC 348
#define T_IP 349
#define T_PATH_VAL 350
#define T_NUMBER 351
#define T_SIGNED_NUMBER 352
#define T_STRING 353




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 293 of yacc.c  */
#line 53 "read_config_yy.y"

	int		val;
	char		*string;



/* Line 293 of yacc.c  */
#line 363 "read_config_yy.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 343 of yacc.c  */
#line 375 "read_config_yy.c"

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
# if defined YYENABLE_NLS && YYENABLE_NLS
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
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
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
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
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

# define YYCOPY_NEEDED 1

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

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
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
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  21
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   349

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  101
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  99
/* YYNRULES -- Number of rules.  */
#define YYNRULES  247
/* YYNRULES -- Number of states.  */
#define YYNSTATES  385

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   353

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
       2,     2,     2,    99,     2,   100,     2,     2,     2,     2,
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
      95,    96,    97,    98
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
     283,   285,   287,   289,   291,   293,   295,   297,   299,   304,
     305,   308,   311,   314,   317,   320,   325,   326,   329,   331,
     337,   343,   349,   350,   353,   355,   357,   359,   361,   363,
     365,   366,   369,   371,   373,   375,   377,   379,   381,   382,
     385,   387,   389,   391,   393,   396,   399,   402,   405,   408,
     411,   414,   417,   419,   421,   424,   429,   430,   433,   435,
     437,   438,   441,   443,   445,   447,   449,   451,   453,   455,
     457,   459,   462,   465,   470,   471,   474,   476,   478,   480,
     482,   484,   486,   488,   490,   492,   494,   496,   498,   500,
     502,   504,   506,   508,   510,   513,   516,   519,   522,   525,
     528,   531,   534,   539,   540,   543,   546,   549,   552,   555,
     558,   563,   570,   577,   578,   581,   587,   593,   594,   597,
     599,   601,   603,   609,   615,   616,   619,   622,   625,   631,
     637,   638,   641,   645,   650,   651,   654,   656,   658,   660,
     662,   664,   667,   670,   673,   676,   679,   682
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     102,     0,    -1,    -1,   103,    -1,   104,    -1,   103,   104,
      -1,   133,    -1,   116,    -1,   110,    -1,   169,    -1,   136,
      -1,   192,    -1,    19,    45,    -1,    19,    46,    -1,    19,
      95,    -1,    61,    45,    -1,    61,    46,    -1,    61,    98,
      -1,    26,    95,    -1,    27,    -1,    11,    96,    -1,    29,
      96,    -1,    30,    96,    -1,    50,    96,    -1,    43,    45,
      -1,    43,    46,    -1,    16,    99,   117,   100,    -1,    -1,
     117,   118,    -1,     3,    94,    -1,    12,    94,    -1,     8,
      99,   120,   100,    -1,     8,    79,    99,   120,   100,    -1,
      -1,   120,   121,    -1,     3,    94,    -1,    12,    94,    -1,
       4,    94,    -1,    13,    94,    -1,    49,    98,    -1,    17,
      96,    -1,    18,    96,    -1,    66,    96,    -1,    65,    96,
      -1,    43,    45,    -1,    43,    46,    -1,    20,    99,   123,
     100,    -1,    20,    79,    99,   123,   100,    -1,    -1,   123,
     124,    -1,     3,    94,    -1,    12,    94,    -1,    82,    94,
      -1,    83,    94,    -1,    49,    98,    -1,     5,    96,    -1,
      66,    96,    -1,    65,    96,    -1,    43,    45,    -1,    43,
      46,    -1,    24,    99,   126,   100,    -1,    24,    79,    99,
     126,   100,    -1,    -1,   126,   127,    -1,     3,    94,    -1,
      12,    94,    -1,    82,    94,    -1,    83,    94,    -1,    49,
      98,    -1,     5,    96,    -1,    66,    96,    -1,    65,    96,
      -1,    43,    45,    -1,    43,    46,    -1,    90,    96,    -1,
       6,    96,    -1,     7,    96,    -1,    10,    99,   131,   100,
      -1,    -1,   131,   132,    -1,     9,    95,    -1,    17,    96,
      -1,    25,    99,   134,   100,    -1,    -1,   134,   135,    -1,
      96,    -1,    98,    -1,    32,    99,   137,   100,    -1,    -1,
     137,   138,    -1,   111,    -1,   112,    -1,   113,    -1,   114,
      -1,   115,    -1,   119,    -1,   122,    -1,   125,    -1,   159,
      -1,   160,    -1,   144,    -1,   145,    -1,   146,    -1,   161,
      -1,   162,    -1,   168,    -1,   158,    -1,   139,    -1,    91,
      99,   140,   100,    -1,    -1,   140,   141,    -1,    92,    45,
      -1,    92,    46,    -1,    93,    45,    -1,    93,    46,    -1,
      93,    99,   142,   100,    -1,    -1,   142,   143,    -1,    98,
      -1,    37,    41,    99,   147,   100,    -1,    37,    42,    99,
     149,   100,    -1,    37,    67,    99,   151,   100,    -1,    -1,
     147,   148,    -1,   111,    -1,   112,    -1,   113,    -1,   114,
      -1,   159,    -1,   160,    -1,    -1,   149,   150,    -1,   156,
      -1,   155,    -1,   113,    -1,   114,    -1,   157,    -1,   154,
      -1,    -1,   151,   152,    -1,   113,    -1,   114,    -1,   153,
      -1,   154,    -1,    88,    45,    -1,    88,    46,    -1,    89,
      45,    -1,    89,    46,    -1,    40,    96,    -1,    51,    96,
      -1,    44,    96,    -1,    64,    96,    -1,    34,    -1,    36,
      -1,    38,    94,    -1,    47,   163,    48,   164,    -1,    -1,
     163,   165,    -1,    98,    -1,   167,    -1,    -1,   166,   167,
      -1,    53,    -1,    54,    -1,    52,    -1,    55,    -1,    56,
      -1,    57,    -1,    58,    -1,    59,    -1,    60,    -1,    62,
      45,    -1,    62,    46,    -1,    31,    99,   170,   100,    -1,
      -1,   170,   171,    -1,   128,    -1,   129,    -1,   105,    -1,
     106,    -1,   108,    -1,   107,    -1,   109,    -1,   130,    -1,
     172,    -1,   173,    -1,   180,    -1,   181,    -1,   182,    -1,
     183,    -1,   174,    -1,   175,    -1,   176,    -1,   177,    -1,
      35,    96,    -1,    28,    96,    -1,    80,    45,    -1,    80,
      46,    -1,    80,    96,    -1,    87,    45,    -1,    87,    46,
      -1,    81,    97,    -1,    84,    99,   178,   100,    -1,    -1,
     178,   179,    -1,    85,    98,    -1,    86,    96,    -1,    39,
      98,    -1,    78,    96,    -1,    68,    96,    -1,    69,    99,
     184,   100,    -1,    69,    75,    76,    99,   184,   100,    -1,
      69,    75,    77,    99,   184,   100,    -1,    -1,   184,   185,
      -1,    71,    73,    99,   186,   100,    -1,    71,    74,    99,
     186,   100,    -1,    -1,   186,   187,    -1,    98,    -1,    24,
      -1,    20,    -1,    70,    73,    99,   188,   100,    -1,    70,
      74,    99,   188,   100,    -1,    -1,   188,   189,    -1,     3,
      94,    -1,    12,    94,    -1,    72,    73,    99,   190,   100,
      -1,    72,    74,    99,   190,   100,    -1,    -1,   190,   191,
      -1,   166,    48,    24,    -1,    33,    99,   193,   100,    -1,
      -1,   193,   194,    -1,   195,    -1,   196,    -1,   197,    -1,
     198,    -1,   199,    -1,    19,    45,    -1,    19,    46,    -1,
      19,    95,    -1,    61,    45,    -1,    61,    46,    -1,    61,
      98,    -1,    63,    96,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,    85,    85,    86,    89,    90,    93,    94,    95,    96,
      97,    98,   101,   106,   110,   115,   120,   125,   157,   162,
     167,   172,   177,   182,   187,   198,   209,   219,   220,   222,
     244,   270,   284,   300,   301,   303,   322,   362,   381,   386,
     406,   413,   419,   425,   431,   437,   443,   457,   473,   474,
     476,   487,   504,   515,   532,   547,   553,   559,   565,   571,
     577,   593,   611,   612,   614,   625,   642,   653,   670,   685,
     691,   697,   703,   709,   715,   721,   726,   731,   733,   734,
     737,   742,   747,   757,   758,   761,   769,   782,   792,   793,
     795,   796,   797,   798,   799,   800,   801,   802,   803,   804,
     805,   806,   807,   808,   809,   810,   811,   812,   815,   817,
     818,   821,   826,   831,   843,   851,   863,   864,   866,   871,
     876,   881,   886,   887,   889,   890,   891,   892,   893,   894,
     897,   898,   900,   901,   902,   903,   904,   905,   908,   909,
     911,   912,   913,   914,   917,   922,   927,   932,   937,   943,
     948,   953,   958,   964,   970,   975,   985,   986,   988,   995,
     997,   998,  1000,  1008,  1016,  1024,  1032,  1040,  1048,  1056,
    1064,  1073,  1079,  1085,  1087,  1088,  1091,  1092,  1093,  1094,
    1095,  1096,  1097,  1098,  1099,  1100,  1101,  1102,  1103,  1104,
    1105,  1106,  1107,  1108,  1111,  1116,  1121,  1126,  1131,  1136,
    1141,  1146,  1151,  1153,  1154,  1157,  1169,  1178,  1186,  1191,
    1201,  1206,  1211,  1216,  1217,  1219,  1228,  1241,  1242,  1244,
    1263,  1282,  1301,  1310,  1332,  1333,  1335,  1394,  1454,  1463,
    1477,  1478,  1480,  1482,  1492,  1493,  1496,  1497,  1498,  1499,
    1500,  1503,  1508,  1512,  1517,  1522,  1527,  1559
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
  "T_DISABLE_EXTERNAL_CACHE", "T_ERROR_QUEUE_LENGTH", "T_OPTIONS",
  "T_TCP_WINDOW_TRACKING", "T_EXPECT_SYNC", "T_IP", "T_PATH_VAL",
  "T_NUMBER", "T_SIGNED_NUMBER", "T_STRING", "'{'", "'}'", "$accept",
  "configfile", "lines", "line", "logfile_bool", "logfile_path",
  "syslog_bool", "syslog_facility", "lock", "strip_nat", "refreshtime",
  "expiretime", "timeout", "purge", "checksum", "ignore_traffic",
  "ignore_traffic_options", "ignore_traffic_option", "multicast_line",
  "multicast_options", "multicast_option", "udp_line", "udp_options",
  "udp_option", "tcp_line", "tcp_options", "tcp_option", "hashsize",
  "hashlimit", "unix_line", "unix_options", "unix_option",
  "ignore_protocol", "ignore_proto_list", "ignore_proto", "sync",
  "sync_list", "sync_line", "option_line", "options", "option",
  "expect_list", "expect_item", "sync_mode_alarm", "sync_mode_ftfw",
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
     345,   346,   347,   348,   349,   350,   351,   352,   353,   123,
     125
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   101,   102,   102,   103,   103,   104,   104,   104,   104,
     104,   104,   105,   105,   106,   107,   107,   108,   109,   110,
     111,   112,   113,   114,   115,   115,   116,   117,   117,   118,
     118,   119,   119,   120,   120,   121,   121,   121,   121,   121,
     121,   121,   121,   121,   121,   121,   122,   122,   123,   123,
     124,   124,   124,   124,   124,   124,   124,   124,   124,   124,
     125,   125,   126,   126,   127,   127,   127,   127,   127,   127,
     127,   127,   127,   127,   127,   128,   129,   130,   131,   131,
     132,   132,   133,   134,   134,   135,   135,   136,   137,   137,
     138,   138,   138,   138,   138,   138,   138,   138,   138,   138,
     138,   138,   138,   138,   138,   138,   138,   138,   139,   140,
     140,   141,   141,   141,   141,   141,   142,   142,   143,   144,
     145,   146,   147,   147,   148,   148,   148,   148,   148,   148,
     149,   149,   150,   150,   150,   150,   150,   150,   151,   151,
     152,   152,   152,   152,   153,   153,   154,   154,   155,   156,
     157,   158,   159,   160,   161,   162,   163,   163,   164,   165,
     166,   166,   167,   167,   167,   167,   167,   167,   167,   167,
     167,   168,   168,   169,   170,   170,   171,   171,   171,   171,
     171,   171,   171,   171,   171,   171,   171,   171,   171,   171,
     171,   171,   171,   171,   172,   173,   174,   174,   174,   175,
     175,   176,   177,   178,   178,   179,   179,   180,   181,   182,
     183,   183,   183,   184,   184,   185,   185,   186,   186,   187,
     187,   187,   185,   185,   188,   188,   189,   189,   185,   185,
     190,   190,   191,   192,   193,   193,   194,   194,   194,   194,
     194,   195,   195,   196,   197,   197,   198,   199
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
       1,     1,     1,     1,     1,     1,     1,     1,     4,     0,
       2,     2,     2,     2,     2,     4,     0,     2,     1,     5,
       5,     5,     0,     2,     1,     1,     1,     1,     1,     1,
       0,     2,     1,     1,     1,     1,     1,     1,     0,     2,
       1,     1,     1,     1,     2,     2,     2,     2,     2,     2,
       2,     2,     1,     1,     2,     4,     0,     2,     1,     1,
       0,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     2,     4,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     2,     2,     2,     2,     2,
       2,     2,     4,     0,     2,     2,     2,     2,     2,     2,
       4,     6,     6,     0,     2,     5,     5,     0,     2,     1,
       1,     1,     5,     5,     0,     2,     2,     2,     5,     5,
       0,     2,     3,     4,     0,     2,     1,     1,     1,     1,
       1,     2,     2,     2,     2,     2,     2,     2
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     0,    19,     0,     0,     0,     0,     3,     4,
       8,     7,     6,    10,     9,    11,    27,    83,   174,    88,
     234,     1,     5,     0,     0,     0,     0,     0,     0,     0,
      26,    28,    85,    86,    82,    84,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   173,   178,   179,   181,   180,   182,   176,   177,
     183,   175,   184,   185,   190,   191,   192,   193,   186,   187,
     188,   189,     0,     0,     0,     0,     0,     0,   152,   153,
       0,     0,     0,   156,     0,     0,     0,     0,    87,    90,
      91,    92,    93,    94,    95,    96,    97,    89,   107,   100,
     101,   102,   106,    98,    99,   103,   104,   105,     0,     0,
       0,   233,   235,   236,   237,   238,   239,   240,    29,    30,
      75,    76,    78,    12,    13,    14,    18,   195,   194,   207,
      15,    16,    17,   209,     0,   213,   208,   196,   197,   198,
     201,   203,   199,   200,     0,    33,    20,     0,    48,     0,
      62,    21,    22,     0,     0,     0,   154,    24,    25,     0,
      23,   171,   172,   151,   109,   241,   242,   243,   244,   245,
     246,   247,     0,     0,     0,     0,     0,    33,     0,    48,
       0,    62,     0,   122,   130,   138,     0,   164,   162,   163,
     165,   166,   167,   168,   169,   170,   157,   159,     0,     0,
       0,    77,    79,   213,   213,     0,     0,     0,   210,   214,
       0,     0,   202,   204,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    31,    34,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    46,    49,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      60,    63,     0,     0,     0,   158,   155,     0,     0,   108,
     110,    80,    81,     0,     0,     0,     0,     0,     0,     0,
       0,   205,   206,    32,    35,    37,    36,    38,    40,    41,
      44,    45,    39,    43,    42,    47,    50,    55,    51,    58,
      59,    54,    57,    56,    52,    53,    61,    64,    69,    65,
      72,    73,    68,    71,    70,    66,    67,    74,   119,   124,
     125,   126,   127,   123,   128,   129,     0,     0,     0,     0,
     120,   134,   135,   131,   137,   133,   132,   136,     0,   121,
     140,   141,   139,   142,   143,   111,   112,   113,   114,   116,
     211,   212,   224,   224,   217,   217,   230,   230,   148,   150,
     149,   146,   147,   144,   145,     0,     0,     0,     0,     0,
     160,   160,   118,   115,   117,     0,     0,   222,   225,   223,
     221,   220,   219,   215,   218,   216,   228,     0,   231,   229,
     226,   227,     0,   161,   232
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     7,     8,     9,    53,    54,    55,    56,    57,    10,
      89,    90,    91,    92,    93,    11,    23,    31,    94,   178,
     226,    95,   180,   238,    96,   182,   251,    58,    59,    60,
     172,   202,    12,    24,    35,    13,    26,    97,    98,   198,
     260,   355,   364,    99,   100,   101,   252,   313,   253,   323,
     254,   332,   333,   324,   325,   326,   327,   102,   103,   104,
     105,   106,   159,   256,   196,   377,   197,   107,    14,    25,
      61,    62,    63,    64,    65,    66,    67,   176,   213,    68,
      69,    70,    71,   175,   209,   358,   374,   356,   368,   360,
     378,    15,    27,   112,   113,   114,   115,   116,   117
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -77
static const yytype_int16 yypact[] =
{
     194,   -76,   -68,   -77,   -49,   -39,   -14,    98,   194,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,     0,   -42,   124,   153,    10,    20,    28,
     -77,   -77,   -77,   -77,   -77,   -77,    36,    40,    50,    56,
      77,    79,    82,    86,    30,    90,   -50,    92,    42,   104,
     117,   121,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -73,   122,   -44,    34,   135,   145,   -77,   -77,
     -23,   126,   149,   -77,   147,   152,   181,   177,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,    73,    47,
     184,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -10,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   182,   -77,   -77,   183,   -77,   185,
     -77,   -77,   -77,   186,   187,   188,   -77,   -77,   -77,   180,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,    -4,   189,   190,    99,    62,   -77,    -3,   -77,
      29,   -77,    -1,   -77,   -77,   -77,   131,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   130,   195,
     196,   -77,   -77,   -77,   -77,    81,   133,   175,   -77,   -77,
     193,   197,   -77,   -77,     4,   200,   201,   203,   204,   205,
     207,   206,   198,   208,   209,   -77,   -77,    74,   212,   211,
     214,   221,   213,   216,   217,   215,   220,   -77,   -77,    25,
     222,   219,   224,   223,   226,   230,   231,   228,   234,   233,
     -77,   -77,     9,    76,    53,   -77,   -77,   225,     6,   -77,
     -77,   -77,   -77,   109,   142,   218,   232,   235,   236,   237,
     238,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   242,   243,   244,   227,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   229,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,    46,    21,    24,    37,    60,
     199,   210,   -77,   -77,   -77,   239,   247,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   202,   -77,   -77,
     -77,   -77,   259,   -77,   -77
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -77,   -77,   -77,   292,   -77,   -77,   -77,   -77,   -77,   -77,
      67,    68,    -7,    11,   -77,   -77,   -77,   -77,   -77,   125,
     -77,   -77,   144,   -77,   -77,   140,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,    71,   -77,   -77,   -77,   -77,    78,    80,
     -77,   -77,   -77,   -77,   -77,   -77,   -35,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   -77,   -77,    75,   -77,    -2,   -77,     1,   -77,     2,
     -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77,   -77
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint16 yytable[] =
{
     215,   216,   240,    28,   241,   199,   144,   215,   216,   217,
     218,   242,    29,   200,   219,   220,   217,   218,   153,   154,
      73,   219,   220,    16,   365,   134,   145,   365,   240,   108,
     241,    17,   228,   366,   229,   147,   366,   242,    76,    77,
     221,   230,   243,    78,   155,    79,   222,   221,   244,   135,
      18,   337,   338,   222,    32,   148,    33,   370,    34,    84,
      19,   371,   223,   224,   245,   246,   173,   174,   243,   223,
     224,   109,   231,   110,   244,   130,   131,   228,   232,   229,
     370,   247,   248,    77,   371,    20,   230,   137,   138,   249,
     245,   246,   168,   169,   233,   234,   201,   225,    21,   250,
      30,   123,   124,    84,   273,   339,    77,   247,   248,   308,
     111,   235,   236,   149,   118,   249,   316,   231,   165,   166,
     317,   367,   119,   232,   369,   296,    84,   318,   132,   237,
      36,    37,   120,   150,    38,   372,   121,   373,   139,   233,
     234,   328,   319,    39,   362,   170,   363,   210,   211,   122,
      40,   125,    41,   329,   265,   266,   235,   236,   372,    42,
     375,    72,   212,    43,    73,   319,   142,   143,   167,   205,
     206,   207,   126,    74,   285,   127,   320,    75,   128,   205,
     206,   207,    76,    77,   129,    44,   133,    78,   136,    79,
      80,    81,    45,    46,   157,   158,    82,   161,   162,   208,
      83,   140,    47,    84,    48,    49,   267,   268,    50,   340,
       1,    51,   205,   206,   207,    85,   141,    86,   146,     2,
     156,     3,   257,   258,    52,     4,     5,     6,   186,   255,
     259,   151,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   152,   341,   160,    87,   311,   321,   330,   269,   270,
     382,   280,   281,    88,   187,   188,   189,   190,   191,   192,
     193,   194,   195,   312,   322,   331,   289,   290,   300,   301,
     335,   336,   351,   352,   353,   354,   164,   163,   263,   264,
     171,   177,   179,   384,   181,   183,   184,   185,   203,   204,
     261,   271,   262,   272,   274,   275,   282,   276,   277,   376,
      22,   278,   214,   279,   283,   284,   286,   287,   288,   294,
     379,   291,   292,   293,   295,   298,   297,   342,   299,   309,
     310,   239,   305,   227,   302,   334,   303,   304,   306,   307,
     314,   343,   315,   380,   344,   345,   346,   347,   348,   349,
     350,   381,   383,   359,   357,     0,     0,     0,     0,   361
};

#define yypact_value_is_default(yystate) \
  ((yystate) == (-77))

#define yytable_value_is_error(yytable_value) \
  YYID (0)

static const yytype_int16 yycheck[] =
{
       3,     4,     3,     3,     5,     9,    79,     3,     4,    12,
      13,    12,    12,    17,    17,    18,    12,    13,    41,    42,
      11,    17,    18,    99,     3,    75,    99,     3,     3,    19,
       5,    99,     3,    12,     5,    79,    12,    12,    29,    30,
      43,    12,    43,    34,    67,    36,    49,    43,    49,    99,
      99,    45,    46,    49,    96,    99,    98,    20,   100,    50,
      99,    24,    65,    66,    65,    66,    76,    77,    43,    65,
      66,    61,    43,    63,    49,    45,    46,     3,    49,     5,
      20,    82,    83,    30,    24,    99,    12,    45,    46,    90,
      65,    66,    45,    46,    65,    66,   100,   100,     0,   100,
     100,    45,    46,    50,   100,    99,    30,    82,    83,   100,
     100,    82,    83,    79,    94,    90,    40,    43,    45,    46,
      44,   100,    94,    49,   100,   100,    50,    51,    98,   100,
       6,     7,    96,    99,    10,    98,    96,   100,    96,    65,
      66,    88,    89,    19,    98,    98,   100,    85,    86,    99,
      26,    95,    28,   100,    73,    74,    82,    83,    98,    35,
     100,     8,   100,    39,    11,    89,    45,    46,    95,    70,
      71,    72,    95,    20,   100,    96,   100,    24,    96,    70,
      71,    72,    29,    30,    98,    61,    96,    34,    96,    36,
      37,    38,    68,    69,    45,    46,    43,    45,    46,   100,
      47,    97,    78,    50,    80,    81,    73,    74,    84,   100,
      16,    87,    70,    71,    72,    62,    99,    64,    96,    25,
      94,    27,    92,    93,   100,    31,    32,    33,    48,    98,
     100,    96,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    96,   100,    96,    91,   252,   253,   254,    73,    74,
      48,    45,    46,   100,    52,    53,    54,    55,    56,    57,
      58,    59,    60,   252,   253,   254,    45,    46,    45,    46,
      45,    46,    45,    46,    45,    46,    99,    96,   203,   204,
      96,    99,    99,    24,    99,    99,    99,    99,    99,    99,
      95,    98,    96,    96,    94,    94,    98,    94,    94,   100,
       8,    96,   177,    96,    96,    96,    94,    96,    94,    94,
     100,    98,    96,    96,    94,    96,    94,    99,    94,   252,
     252,   181,    94,   179,    98,   254,    96,    96,    94,    96,
     252,    99,   252,    94,    99,    99,    99,    99,    96,    96,
      96,    94,   377,   345,   343,    -1,    -1,    -1,    -1,   347
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    16,    25,    27,    31,    32,    33,   102,   103,   104,
     110,   116,   133,   136,   169,   192,    99,    99,    99,    99,
      99,     0,   104,   117,   134,   170,   137,   193,     3,    12,
     100,   118,    96,    98,   100,   135,     6,     7,    10,    19,
      26,    28,    35,    39,    61,    68,    69,    78,    80,    81,
      84,    87,   100,   105,   106,   107,   108,   109,   128,   129,
     130,   171,   172,   173,   174,   175,   176,   177,   180,   181,
     182,   183,     8,    11,    20,    24,    29,    30,    34,    36,
      37,    38,    43,    47,    50,    62,    64,    91,   100,   111,
     112,   113,   114,   115,   119,   122,   125,   138,   139,   144,
     145,   146,   158,   159,   160,   161,   162,   168,    19,    61,
      63,   100,   194,   195,   196,   197,   198,   199,    94,    94,
      96,    96,    99,    45,    46,    95,    95,    96,    96,    98,
      45,    46,    98,    96,    75,    99,    96,    45,    46,    96,
      97,    99,    45,    46,    79,    99,    96,    79,    99,    79,
      99,    96,    96,    41,    42,    67,    94,    45,    46,   163,
      96,    45,    46,    96,    99,    45,    46,    95,    45,    46,
      98,    96,   131,    76,    77,   184,   178,    99,   120,    99,
     123,    99,   126,    99,    99,    99,    48,    52,    53,    54,
      55,    56,    57,    58,    59,    60,   165,   167,   140,     9,
      17,   100,   132,    99,    99,    70,    71,    72,   100,   185,
      85,    86,   100,   179,   120,     3,     4,    12,    13,    17,
      18,    43,    49,    65,    66,   100,   121,   123,     3,     5,
      12,    43,    49,    65,    66,    82,    83,   100,   124,   126,
       3,     5,    12,    43,    49,    65,    66,    82,    83,    90,
     100,   127,   147,   149,   151,    98,   164,    92,    93,   100,
     141,    95,    96,   184,   184,    73,    74,    73,    74,    73,
      74,    98,    96,   100,    94,    94,    94,    94,    96,    96,
      45,    46,    98,    96,    96,   100,    94,    96,    94,    45,
      46,    98,    96,    96,    94,    94,   100,    94,    96,    94,
      45,    46,    98,    96,    96,    94,    94,    96,   100,   111,
     112,   113,   114,   148,   159,   160,    40,    44,    51,    89,
     100,   113,   114,   150,   154,   155,   156,   157,    88,   100,
     113,   114,   152,   153,   154,    45,    46,    45,    46,    99,
     100,   100,    99,    99,    99,    99,    99,    99,    96,    96,
      96,    45,    46,    45,    46,   142,   188,   188,   186,   186,
     190,   190,    98,   100,   143,     3,    12,   100,   189,   100,
      20,    24,    98,   100,   187,   100,   100,   166,   191,   100,
      94,    94,    48,   167,    24
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
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
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


/* This macro is provided for backward compatibility. */

#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
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

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (0, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  YYSIZE_T yysize1;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = 0;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                yysize1 = yysize + yytnamerr (0, yytname[yyx]);
                if (! (yysize <= yysize1
                       && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                  return 2;
                yysize = yysize1;
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  yysize1 = yysize + yystrlen (yyformat);
  if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
    return 2;
  yysize = yysize1;

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
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


/*----------.
| yyparse.  |
`----------*/

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
  if (yypact_value_is_default (yyn))
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
      if (yytable_value_is_error (yyn))
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

/* Line 1806 of yacc.c  */
#line 102 "read_config_yy.y"
    {
	strncpy(conf.logfile, DEFAULT_LOGFILE, FILENAME_MAXLEN);
}
    break;

  case 13:

/* Line 1806 of yacc.c  */
#line 107 "read_config_yy.y"
    {
}
    break;

  case 14:

/* Line 1806 of yacc.c  */
#line 111 "read_config_yy.y"
    {
	strncpy(conf.logfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 15:

/* Line 1806 of yacc.c  */
#line 116 "read_config_yy.y"
    {
	conf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
}
    break;

  case 16:

/* Line 1806 of yacc.c  */
#line 121 "read_config_yy.y"
    {
	conf.syslog_facility = -1;
}
    break;

  case 17:

/* Line 1806 of yacc.c  */
#line 126 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 158 "read_config_yy.y"
    {
	strncpy(conf.lockfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 19:

/* Line 1806 of yacc.c  */
#line 163 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`StripNAT' clause is obsolete, ignoring");
}
    break;

  case 20:

/* Line 1806 of yacc.c  */
#line 168 "read_config_yy.y"
    {
	conf.refresh = (yyvsp[(2) - (2)].val);
}
    break;

  case 21:

/* Line 1806 of yacc.c  */
#line 173 "read_config_yy.y"
    {
	conf.cache_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 22:

/* Line 1806 of yacc.c  */
#line 178 "read_config_yy.y"
    {
	conf.commit_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 23:

/* Line 1806 of yacc.c  */
#line 183 "read_config_yy.y"
    {
	conf.purge_timeout = (yyvsp[(2) - (2)].val);
}
    break;

  case 24:

/* Line 1806 of yacc.c  */
#line 188 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 199 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 210 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_NEGATIVE);

	print_err(CTD_CFG_WARN, "the clause `IgnoreTrafficFor' is obsolete. "
				"Use `Filter' instead");
}
    break;

  case 29:

/* Line 1806 of yacc.c  */
#line 223 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 245 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 271 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 285 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 304 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 323 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 363 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 382 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`IPv6_interface' not required, ignoring");
}
    break;

  case 39:

/* Line 1806 of yacc.c  */
#line 387 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 407 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`Backlog' option inside Multicast clause is "
				"obsolete. Please, remove it from "
				"conntrackd.conf");
}
    break;

  case 41:

/* Line 1806 of yacc.c  */
#line 414 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 42:

/* Line 1806 of yacc.c  */
#line 420 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 43:

/* Line 1806 of yacc.c  */
#line 426 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 44:

/* Line 1806 of yacc.c  */
#line 432 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.checksum = 0;
}
    break;

  case 45:

/* Line 1806 of yacc.c  */
#line 438 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.mcast.checksum = 1;
}
    break;

  case 46:

/* Line 1806 of yacc.c  */
#line 444 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 458 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 477 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 488 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 505 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 516 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 533 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 548 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 56:

/* Line 1806 of yacc.c  */
#line 554 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 57:

/* Line 1806 of yacc.c  */
#line 560 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 58:

/* Line 1806 of yacc.c  */
#line 566 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.checksum = 0;
}
    break;

  case 59:

/* Line 1806 of yacc.c  */
#line 572 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.udp.checksum = 1;
}
    break;

  case 60:

/* Line 1806 of yacc.c  */
#line 578 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 594 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 615 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 626 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 643 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 654 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 671 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 686 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.port = (yyvsp[(2) - (2)].val);
}
    break;

  case 70:

/* Line 1806 of yacc.c  */
#line 692 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.sndbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 71:

/* Line 1806 of yacc.c  */
#line 698 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.rcvbuf = (yyvsp[(2) - (2)].val);
}
    break;

  case 72:

/* Line 1806 of yacc.c  */
#line 704 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.checksum = 0;
}
    break;

  case 73:

/* Line 1806 of yacc.c  */
#line 710 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	conf.channel[conf.channel_num].u.tcp.checksum = 1;
}
    break;

  case 74:

/* Line 1806 of yacc.c  */
#line 716 "read_config_yy.y"
    {
	__max_dedicated_links_reached();
	CONFIG(channelc).error_queue_length = (yyvsp[(2) - (2)].val);
}
    break;

  case 75:

/* Line 1806 of yacc.c  */
#line 722 "read_config_yy.y"
    {
	conf.hashsize = (yyvsp[(2) - (2)].val);
}
    break;

  case 76:

/* Line 1806 of yacc.c  */
#line 727 "read_config_yy.y"
    {
	conf.limit = (yyvsp[(2) - (2)].val);
}
    break;

  case 80:

/* Line 1806 of yacc.c  */
#line 738 "read_config_yy.y"
    {
	strcpy(conf.local.path, (yyvsp[(2) - (2)].string));
}
    break;

  case 81:

/* Line 1806 of yacc.c  */
#line 743 "read_config_yy.y"
    {
	conf.local.backlog = (yyvsp[(2) - (2)].val);
}
    break;

  case 82:

/* Line 1806 of yacc.c  */
#line 748 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_NEGATIVE);

	print_err(CTD_CFG_WARN, "the clause `IgnoreProtocol' is "
				"obsolete. Use `Filter' instead");
}
    break;

  case 85:

/* Line 1806 of yacc.c  */
#line 762 "read_config_yy.y"
    {
	if ((yyvsp[(1) - (1)].val) < IPPROTO_MAX)
		ct_filter_add_proto(STATE(us_filter), (yyvsp[(1) - (1)].val));
	else
		print_err(CTD_CFG_WARN, "protocol number `%d' is freak", (yyvsp[(1) - (1)].val));
}
    break;

  case 86:

/* Line 1806 of yacc.c  */
#line 770 "read_config_yy.y"
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

/* Line 1806 of yacc.c  */
#line 783 "read_config_yy.y"
    {
	if (conf.flags & CTD_STATS_MODE) {
		print_err(CTD_CFG_ERROR, "cannot use both `Stats' and `Sync' "
					 "clauses in conntrackd.conf");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_SYNC_MODE;
}
    break;

  case 111:

/* Line 1806 of yacc.c  */
#line 822 "read_config_yy.y"
    {
	CONFIG(sync).tcp_window_tracking = 1;
}
    break;

  case 112:

/* Line 1806 of yacc.c  */
#line 827 "read_config_yy.y"
    {
	CONFIG(sync).tcp_window_tracking = 0;
}
    break;

  case 113:

/* Line 1806 of yacc.c  */
#line 832 "read_config_yy.y"
    {
	CONFIG(flags) |= CTD_EXPECT;
	CONFIG(netlink).subsys_id = NFNL_SUBSYS_NONE;
	CONFIG(netlink).groups = NF_NETLINK_CONNTRACK_NEW |
				 NF_NETLINK_CONNTRACK_UPDATE |
				 NF_NETLINK_CONNTRACK_DESTROY |
				 NF_NETLINK_CONNTRACK_EXP_NEW |
				 NF_NETLINK_CONNTRACK_EXP_UPDATE |
				 NF_NETLINK_CONNTRACK_EXP_DESTROY;
}
    break;

  case 114:

/* Line 1806 of yacc.c  */
#line 844 "read_config_yy.y"
    {
	CONFIG(netlink).subsys_id = NFNL_SUBSYS_CTNETLINK;
	CONFIG(netlink).groups = NF_NETLINK_CONNTRACK_NEW |
				 NF_NETLINK_CONNTRACK_UPDATE |
				 NF_NETLINK_CONNTRACK_DESTROY;
}
    break;

  case 115:

/* Line 1806 of yacc.c  */
#line 852 "read_config_yy.y"
    {
	CONFIG(flags) |= CTD_EXPECT;
	CONFIG(netlink).subsys_id = NFNL_SUBSYS_NONE;
	CONFIG(netlink).groups = NF_NETLINK_CONNTRACK_NEW |
				 NF_NETLINK_CONNTRACK_UPDATE |
				 NF_NETLINK_CONNTRACK_DESTROY |
				 NF_NETLINK_CONNTRACK_EXP_NEW |
				 NF_NETLINK_CONNTRACK_EXP_UPDATE |
				 NF_NETLINK_CONNTRACK_EXP_DESTROY;
}
    break;

  case 118:

/* Line 1806 of yacc.c  */
#line 867 "read_config_yy.y"
    {
	exp_filter_add(STATE(exp_filter), (yyvsp[(1) - (1)].string));
}
    break;

  case 119:

/* Line 1806 of yacc.c  */
#line 872 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_ALARM;
}
    break;

  case 120:

/* Line 1806 of yacc.c  */
#line 877 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_FTFW;
}
    break;

  case 121:

/* Line 1806 of yacc.c  */
#line 882 "read_config_yy.y"
    {
	conf.flags |= CTD_SYNC_NOTRACK;
}
    break;

  case 144:

/* Line 1806 of yacc.c  */
#line 918 "read_config_yy.y"
    {
	conf.sync.internal_cache_disable = 1;
}
    break;

  case 145:

/* Line 1806 of yacc.c  */
#line 923 "read_config_yy.y"
    {
	conf.sync.internal_cache_disable = 0;
}
    break;

  case 146:

/* Line 1806 of yacc.c  */
#line 928 "read_config_yy.y"
    {
	conf.sync.external_cache_disable = 1;
}
    break;

  case 147:

/* Line 1806 of yacc.c  */
#line 933 "read_config_yy.y"
    {
	conf.sync.external_cache_disable = 0;
}
    break;

  case 148:

/* Line 1806 of yacc.c  */
#line 938 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`ResendBufferSize' is deprecated. "
				"Use `ResendQueueSize' instead");
}
    break;

  case 149:

/* Line 1806 of yacc.c  */
#line 944 "read_config_yy.y"
    {
	conf.resend_queue_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 150:

/* Line 1806 of yacc.c  */
#line 949 "read_config_yy.y"
    {
	conf.window_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 151:

/* Line 1806 of yacc.c  */
#line 954 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`DestroyTimeout' is deprecated. Remove it");
}
    break;

  case 152:

/* Line 1806 of yacc.c  */
#line 959 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`RelaxTransitions' clause is obsolete. "
				"Please, remove it from conntrackd.conf");
}
    break;

  case 153:

/* Line 1806 of yacc.c  */
#line 965 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`DelayDestroyMessages' clause is obsolete. "
				"Please, remove it from conntrackd.conf");
}
    break;

  case 154:

/* Line 1806 of yacc.c  */
#line 971 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "the clause `ListenTo' is obsolete, ignoring");
}
    break;

  case 155:

/* Line 1806 of yacc.c  */
#line 976 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	print_err(CTD_CFG_WARN, "the clause `Replicate' is obsolete. "
				"Use `Filter' instead");
}
    break;

  case 158:

/* Line 1806 of yacc.c  */
#line 989 "read_config_yy.y"
    {
	if (strncmp((yyvsp[(1) - (1)].string), "TCP", strlen("TCP")) != 0) {
		print_err(CTD_CFG_WARN, "unsupported protocol `%s' in line %d",
					(yyvsp[(1) - (1)].string), yylineno);
	}
}
    break;

  case 162:

/* Line 1806 of yacc.c  */
#line 1001 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_SENT);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_SENT);
}
    break;

  case 163:

/* Line 1806 of yacc.c  */
#line 1009 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_RECV);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_RECV);
}
    break;

  case 164:

/* Line 1806 of yacc.c  */
#line 1017 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_ESTABLISHED);

	__kernel_filter_add_state(TCP_CONNTRACK_ESTABLISHED);
}
    break;

  case 165:

/* Line 1806 of yacc.c  */
#line 1025 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_FIN_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_FIN_WAIT);
}
    break;

  case 166:

/* Line 1806 of yacc.c  */
#line 1033 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE_WAIT);
}
    break;

  case 167:

/* Line 1806 of yacc.c  */
#line 1041 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LAST_ACK);

	__kernel_filter_add_state(TCP_CONNTRACK_LAST_ACK);
}
    break;

  case 168:

/* Line 1806 of yacc.c  */
#line 1049 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_TIME_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_TIME_WAIT);
}
    break;

  case 169:

/* Line 1806 of yacc.c  */
#line 1057 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE);
}
    break;

  case 170:

/* Line 1806 of yacc.c  */
#line 1065 "read_config_yy.y"
    {
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LISTEN);

	__kernel_filter_add_state(TCP_CONNTRACK_LISTEN);
}
    break;

  case 171:

/* Line 1806 of yacc.c  */
#line 1074 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`CacheWriteThrough' clause is obsolete, "
				"ignoring");
}
    break;

  case 172:

/* Line 1806 of yacc.c  */
#line 1080 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`CacheWriteThrough' clause is obsolete, "
				"ignoring");
}
    break;

  case 194:

/* Line 1806 of yacc.c  */
#line 1112 "read_config_yy.y"
    {
	conf.netlink_buffer_size = (yyvsp[(2) - (2)].val);
}
    break;

  case 195:

/* Line 1806 of yacc.c  */
#line 1117 "read_config_yy.y"
    {
	conf.netlink_buffer_size_max_grown = (yyvsp[(2) - (2)].val);
}
    break;

  case 196:

/* Line 1806 of yacc.c  */
#line 1122 "read_config_yy.y"
    {
	conf.nl_overrun_resync = 30;
}
    break;

  case 197:

/* Line 1806 of yacc.c  */
#line 1127 "read_config_yy.y"
    {
	conf.nl_overrun_resync = -1;
}
    break;

  case 198:

/* Line 1806 of yacc.c  */
#line 1132 "read_config_yy.y"
    {
	conf.nl_overrun_resync = (yyvsp[(2) - (2)].val);
}
    break;

  case 199:

/* Line 1806 of yacc.c  */
#line 1137 "read_config_yy.y"
    {
	conf.netlink.events_reliable = 1;
}
    break;

  case 200:

/* Line 1806 of yacc.c  */
#line 1142 "read_config_yy.y"
    {
	conf.netlink.events_reliable = 0;
}
    break;

  case 201:

/* Line 1806 of yacc.c  */
#line 1147 "read_config_yy.y"
    {
	conf.nice = (yyvsp[(2) - (2)].val);
}
    break;

  case 205:

/* Line 1806 of yacc.c  */
#line 1158 "read_config_yy.y"
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

  case 206:

/* Line 1806 of yacc.c  */
#line 1170 "read_config_yy.y"
    {
	conf.sched.prio = (yyvsp[(2) - (2)].val);
	if (conf.sched.prio < 0 || conf.sched.prio > 99) {
		print_err(CTD_CFG_ERROR, "`Priority' must be [0, 99]\n", (yyvsp[(2) - (2)].val));
		exit(EXIT_FAILURE);
	}
}
    break;

  case 207:

/* Line 1806 of yacc.c  */
#line 1179 "read_config_yy.y"
    {
	if (strncmp((yyvsp[(2) - (2)].string), "IPv6", strlen("IPv6")) == 0)
		conf.family = AF_INET6;
	else
		conf.family = AF_INET;
}
    break;

  case 208:

/* Line 1806 of yacc.c  */
#line 1187 "read_config_yy.y"
    {
	CONFIG(event_iterations_limit) = (yyvsp[(2) - (2)].val);
}
    break;

  case 209:

/* Line 1806 of yacc.c  */
#line 1192 "read_config_yy.y"
    {
	conf.flags |= CTD_POLL;
	conf.poll_kernel_secs = (yyvsp[(2) - (2)].val);
	if (conf.poll_kernel_secs == 0) {
		print_err(CTD_CFG_ERROR, "`PollSecs' clause must be > 0");
		exit(EXIT_FAILURE);
	}
}
    break;

  case 210:

/* Line 1806 of yacc.c  */
#line 1202 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 0;
}
    break;

  case 211:

/* Line 1806 of yacc.c  */
#line 1207 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 0;
}
    break;

  case 212:

/* Line 1806 of yacc.c  */
#line 1212 "read_config_yy.y"
    {
	CONFIG(filter_from_kernelspace) = 1;
}
    break;

  case 215:

/* Line 1806 of yacc.c  */
#line 1220 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 216:

/* Line 1806 of yacc.c  */
#line 1229 "read_config_yy.y"
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

  case 219:

/* Line 1806 of yacc.c  */
#line 1245 "read_config_yy.y"
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

  case 220:

/* Line 1806 of yacc.c  */
#line 1264 "read_config_yy.y"
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

  case 221:

/* Line 1806 of yacc.c  */
#line 1283 "read_config_yy.y"
    {
	struct protoent *pent;

	pent = getprotobyname("udp");
	if (pent == NULL) {
		print_err(CTD_CFG_WARN, "getprotobyname() cannot find "
					"protocol `udp' in /etc/protocols");
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);

	__kernel_filter_start();

	nfct_filter_add_attr_u32(STATE(filter),
				 NFCT_FILTER_L4PROTO,
				 pent->p_proto);
}
    break;

  case 222:

/* Line 1806 of yacc.c  */
#line 1302 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 223:

/* Line 1806 of yacc.c  */
#line 1311 "read_config_yy.y"
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

  case 226:

/* Line 1806 of yacc.c  */
#line 1336 "read_config_yy.y"
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

  case 227:

/* Line 1806 of yacc.c  */
#line 1395 "read_config_yy.y"
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

  case 228:

/* Line 1806 of yacc.c  */
#line 1455 "read_config_yy.y"
    {
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
}
    break;

  case 229:

/* Line 1806 of yacc.c  */
#line 1464 "read_config_yy.y"
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

  case 233:

/* Line 1806 of yacc.c  */
#line 1483 "read_config_yy.y"
    {
	if (conf.flags & CTD_SYNC_MODE) {
		print_err(CTD_CFG_ERROR, "cannot use both `Stats' and `Sync' "
					 "clauses in conntrackd.conf");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_STATS_MODE;
}
    break;

  case 241:

/* Line 1806 of yacc.c  */
#line 1504 "read_config_yy.y"
    {
	strncpy(conf.stats.logfile, DEFAULT_STATS_LOGFILE, FILENAME_MAXLEN);
}
    break;

  case 242:

/* Line 1806 of yacc.c  */
#line 1509 "read_config_yy.y"
    {
}
    break;

  case 243:

/* Line 1806 of yacc.c  */
#line 1513 "read_config_yy.y"
    {
	strncpy(conf.stats.logfile, (yyvsp[(2) - (2)].string), FILENAME_MAXLEN);
}
    break;

  case 244:

/* Line 1806 of yacc.c  */
#line 1518 "read_config_yy.y"
    {
	conf.stats.syslog_facility = DEFAULT_SYSLOG_FACILITY;
}
    break;

  case 245:

/* Line 1806 of yacc.c  */
#line 1523 "read_config_yy.y"
    {
	conf.stats.syslog_facility = -1;
}
    break;

  case 246:

/* Line 1806 of yacc.c  */
#line 1528 "read_config_yy.y"
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

  case 247:

/* Line 1806 of yacc.c  */
#line 1560 "read_config_yy.y"
    {
	print_err(CTD_CFG_WARN, "`LogFileBufferSize' is deprecated");
}
    break;



/* Line 1806 of yacc.c  */
#line 3861 "read_config_yy.c"
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
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
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
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
      if (!yypact_value_is_default (yyn))
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
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
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



/* Line 2067 of yacc.c  */
#line 1564 "read_config_yy.y"


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
	CONFIG(netlink).subsys_id = -1;

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
		CONFIG(general).commit_steps = 8192;

	/* if overrun, automatically resync with kernel after 30 seconds */
	if (CONFIG(nl_overrun_resync) == 0)
		CONFIG(nl_overrun_resync) = 30;

	/* default to 128 elements in the channel error queue */
	if (CONFIG(channelc).error_queue_length == 0)
		CONFIG(channelc).error_queue_length = 128;

	if (CONFIG(netlink).subsys_id == -1) {
		CONFIG(netlink).subsys_id = NFNL_SUBSYS_CTNETLINK;
		CONFIG(netlink).groups = NF_NETLINK_CONNTRACK_NEW |
					 NF_NETLINK_CONNTRACK_UPDATE |
					 NF_NETLINK_CONNTRACK_DESTROY;
	}

	return 0;
}

