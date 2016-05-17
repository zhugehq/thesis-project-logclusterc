
/*
 LogClusterC version 0.03
 Copyright (C) 2016 Zhuge Chen, Risto Vaarandi and Mauno Pihelgas
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/*
 LogCluster is a density-based data clustering algorithm for event logs,
 introduced by Risto Vaarandi and Mauno Pihelgas in 2015.
 
 A detialed discussion of the LogCluster algorithm can be found in the paper
 ( http://ristov.github.io/publications/cnsm15-logcluster-web.pdf ) published at
 CNSM 2015.
 */

#include <sys/types.h> /* for system typedefs, e.g., time_t */
#include <stdio.h>
#include <string.h>    /* for strcmp(), strcpy(), etc. */
#include <time.h>      /* for time() and ctime() */
#include <stdlib.h>    /* for malloc(), atoi/f() and rand() */
#include <getopt.h>    /* for get_opt_long() */
#include <ctype.h>     /* for tolower() */
#include <regex.h>     /* for regcomp() and regexec() */
#include <glob.h>      /* for glob() */
#include <syslog.h>    /* for syslog() */

/* Type definitions */

typedef unsigned long support_t;
typedef unsigned long tableindex_t;
typedef unsigned long linenumber_t;
typedef unsigned long wordnumber_t;

/* Constant strings */

#define VERSIONINFO "LogClusterC version 0.03, \
Copyright (C) 2016 Zhuge Chen, Risto Vaarandi and Mauno Pihelgas"

#define USAGEINFO "\n\
Options:\n\
--input=<file_name> or <file_pattern> ...\n\
--support=<support>\n\
--rsupport=<relative_support>\n\
--separator=<word_separator_regexp>\n\
--lfilter=<line_filter_regexp>\n\
--template=<line_conversion_template>\n\
--syslog=<syslog_facility>\n\
--wsize=<wordsketch_size>\n\
--wweight=<word_weight_threshold>\n\
--weightf=<word_weight_function> (1, 2)\n\
--wfilter=<word_filter_regexp>\n\
--wsearch=<word_search_regexp>\n\
--wreplace=<word_replace_string>\n\
--outliers=<outlier_file>\n\
--aggrsup\n\
--debug=<debug_level> (1, 2, 3)\n\
--byteoffset=<byte_offset>\n\
--csize=<clustersketch_size>\n\
--initseed=<seed>\n\
--wtablesize=<wordtable_size>\n\
--outputmode=<output_mode> (1)\n\
--detailtoken\n\
--help, -h\n\
--version\n\
\n\
"

#define HELPINFO "\n\
--input=<file_name> or <file_pattern>\n\
Find clusters from file, or files matching the <file_pattern>.\n\
For example, --input=/var/log/remote/*.log finds clusters from all files\n\
with the .log extension in /var/log/remote.\n\
This option can be specified multiple times.\n\
\n\
--support=<support>\n\
Find clusters (line patterns) that match at least <support> lines in input\n\
file(s). Each line pattern consists of word constants and variable parts,\n\
where individual words occur at least <support> times in input files(s).\n\
For example, --support=1000 finds clusters (line patterns) which consist\n\
of words that occur at least in 1000 log file lines, with each cluster\n\
matching at least 1000 log file lines.\n\
\n\
--rsupport=<relative_support>\n\
This option takes a real number from the range 0..100 for its value, and\n\
sets relative support threshold in percentage of total number of input lines.\n\
For example, if 20000 lines are read from input file(s), --rsupport=0.1 is\n\
equivalent to --support=20.\n\
\n\
--separator=<word_separator_regexp>\n\
Regular expression which matches separating characters between words.\n\
Default value for <word_separator_regexp> is \\s+ (i.e., regular expression\n\
that matches one or more whitespace characters).\n\
\n\
--lfilter=<line_filter_regexp>\n\
When clustering log file lines from file(s) given with --input option(s),\n\
process only lines which match the regular expression. For example,\n\
--lfilter='sshd\\[\\d+\\]:' finds clusters for log file lines that\n\
contain the string sshd[<pid>]: (i.e., sshd syslog messages).\n\
\n\
--template=<line_conversion_template>\n\
After the regular expression given with --lfilter option has matched a line,\n\
convert the line by substituting match variables in <line_conversion_template>.\n\
For example, if --lfilter='(sshd\\[\\d+\\]:.*)' option is given, only sshd\n\
syslog messages are considered during clustering, e.g.:\n\
Apr 15 12:00:00 myhost sshd[123]: this is a test\n\
When the above line matches the regular expression (sshd\\[\\d+\\]:.*),\n\
$1 match variable is set to:\n\
sshd[123]: this is a test\n\
If --template='$1' option is given, the original input line\n\
Apr 15 12:00:00 myhost sshd[123]: this is a test\n\
is converted to\n\
sshd[123]: this is a test\n\
(i.e., the timestamp and hostname of the sshd syslog message are ignored).\n\
Please note that <line_conversion_template> supports not only numeric\n\
match variables (such as $2 or ${12}), but also named match variables with\n\
$+{name} syntax (such as $+{ip} or $+{hostname}).\n\
This option can not be used without --lfilter option.\n\
\n\
--syslog=<syslog_facility>\n\
Log messages about the progress of clustering to syslog, using the given\n\
facility. For example, --syslog=local2 logs to syslog with local2 facility.\n\
You can also use this option with out argument, like '--syslog', which will\n\
set facility to local2.\n\
\n\
--wsize=<wordsketch_size>\n\
Instead of finding frequent words by keeping each word with an occurrence\n\
counter in memory, use a sketch of <wordsketch_size> counters for filtering\n\
out infrequent words from the word frequency estimation process. This\n\
option requires an additional pass over input files, but can save large\n\
amount of memory, since most words in log files are usually infrequent.\n\
For example, --wsize=250000 uses a sketch of 250,000 counters for filtering.\n\
\n\
--wweight=<word_weight_threshold>\n\
This option enables word weight based heuristic for joining clusters.\n\
The option takes a positive real number not greater than 1 for its value.\n\
With this option, an additional pass over input files is made, in order\n\
to find dependencies between frequent words.\n\
For example, if 5% of log file lines that contain the word 'Interface'\n\
also contain the word 'eth0', and 15% of the log file lines with the word\n\
'unstable' also contain the word 'eth0', dependencies dep(Interface, eth0)\n\
and dep(unstable, eth0) are memorized with values 0.05 and 0.15, respectively.\n\
Also, dependency dep(eth0, eth0) is memorized with the value 1.0.\n\
Dependency information is used for calculating the weight of words in line\n\
patterns of all detected clusters. The function for calculating the weight\n\
can be set with --weightf option.\n\
For instance, if --weightf=1 and the line pattern of a cluster is\n\
'Interface eth0 unstable', then given the example dependencies above,\n\
the weight of the word 'eth0' is calculated in the following way:\n\
(dep(Interface, eth0) + dep(eth0, eth0)\n\
+ dep(unstable, eth0)) / number of words = (0.05 + 1.0 + 0.15) / 3 = 0.4\n\
If the weights of 'Interface' and 'unstable' are 1, and the word weight\n\
threshold is set to 0.5 with --wweight option, the weight of 'eth0'\n\
remains below threshold. If another cluster is identified where all words\n\
appear in the same order, and all words with sufficient weight are identical,\n\
two clusters are joined. For example, if clusters 'Interface eth0 unstable'\n\
and 'Interface eth1 unstable' are detected where the weights of 'Interface'\n\
and 'unstable' are sufficient in both clusters, but the weights of 'eth0'\n\
and 'eth1' are smaller than the word weight threshold, the clusters are\n\
joined into a new cluster 'Interface (eth0|eth1) unstable'.\n\
\n\
--weightf=<word_weight_function>\n\
This option takes an integer for its value which denotes a word weight\n\
function, with the default value being 1. The function is used for finding\n\
weights of words in cluster line patterns if --wweight option has been given.\n\
If W1,...,Wk are words of the cluster line pattern, value 1 denotes the\n\
function that finds the weight of the word Wi in the following way:\n\
(dep(W1, Wi) + ... + dep(Wk, Wi)) / k\n\
Value 2 denotes the function that will first find unique words U1,...Up from\n\
W1,...Wk (p <= k, and if Ui = Uj then i = j). The weight of the word Ui is\n\
then calculated as follows:\n\
if p>1 then (dep(U1, Ui) + ... + dep(Up, Ui) - dep(Ui, Ui)) / (p - 1)\n\
if p=1 then 1\n\
\n\
--wfilter=<word_filter_regexp>\n\
--wsearch=<word_search_regexp>\n\
--wreplace=<word_replace_string>\n\
These options are used for generating additional words during the clustering\n\
process, in order to detect frequent words that match the same template.\n\
If the regular expression <word_filter_regexp> matches the word, all\n\
substrings in the word that match the regular expression <word_search_regexp>\n\
are replaced with the string <word_replace_string>. The result of search-\n\
and-replace operation is treated like a regular word, and can be used as\n\
a part of a cluster candidate. However, when both the original word and\n\
the result of search-and-replace are frequent, original word is given\n\
a preference during the clustering process.\n\
For example, if the following options are provided\n\
--wfilter='[.:]' --wsearch='[0-9]+' --wreplace=N\n\
the words 10.1.1.1 and 10.1.1.2:80 are converted into N.N.N.N and N.N.N.N:N\n\
Note that --wfilter option requires the presence of --wsearch and --wreplace,\n\
while --wsearch and --wreplace are ignored without --wfilter.\n\
\n\
--outliers=<outlier_file>\n\
If this option is given, an additional pass over input files is made, in order\n\
to find outliers. All outlier lines are written to the given file.\n\
\n\
--aggrsup\n\
If this option is given, for each cluster candidate other candidates are\n\
identified which represent more specific line patterns. After detecting such\n\
candidates, their supports are added to the given candidate. For example,\n\
if the given candidate is 'Interface * down' with the support 20, and\n\
candidates 'Interface eth0 down' (support 10) and 'Interface eth1 down'\n\
(support 5) are detected as more specific, the support of 'Interface * down'\n\
will be set to 35 (20+10+5).\n\
\n\
--debug=<debug_level> (1,2,3)\n\
Increase logging verbosity by generating debug output. Debug level 1 displays\n\
a summary after each phase is done. Debug level 2 displays the processing\n\
status after every 200,000 lines are analysed. Debug level 3 displays the\n\
processing status every 5 seconds. When analysing large log files bigger than\n\
1GB, debug level 2 or 3 is sugguested.\n\
For the sake of consistency with Perl version, you can also use this option\n\
without argument, like '--debug', which will set debug level to 1.\n\
\n\
--byteoffset=<byte_offset>\n\
When processing the input file(s), ignore the first <byte offset> bytes of \n\
every line. This option can be used to filter out the possibly irrelevant\n\
information in the beginning of every line (e.g., timestamp and hostname). The\n\
default value for the option is zero, i.e., no bytes are ignored.\n\
\n\
--csize=<clustersketch_size>\n\
The size of the cluster candidate summary vector(sketch). The default value for\n\
the option is zero, i.e., no summary vector will be generated. This option and\n\
the option --aggrsup are mutually exclusive, since -aggrsup requires the\n\
presence of all candidates in order to produce correct results, but when the\n\
summar vector is employed, not all candidates are inserted into the candidate\n\
table.\n\
\n\
--initseed=<seed>\n\
The value that is used to initialize the rand(3) based random number generator\n\
which is used to generate seed values for string hashing functions inside\n\
LogCluster. The default value for the option is 1.\n\
\n\
--wtablesize=<wordtable_size>\n\
The number of slots in the vocabulary hash table. The default value for the\n\
option is 100,000.\n\
\n\
--outputmode=<output_mode> (1)\n\
This program outputs the clusters with a support value descending order. This\n\
option changes the way of outputing clusters. When output mode is set to 1,\n\
the clusters will be sorted by their constant number, from small to big. In\n\
another word, the clusters will be sorted by their complexity, from simple to\n\
complex.\n\
You can also use this option with out argument, like '--outputmode', which will\n\
set output mode to 1.\n\
\n\
--detailtoken\n\
If Join_Cluster heuristic('--wweight' option) is used, this option can make the\n\
output more detailed. For the sake of simplicity, by default, if a token has\n\
only one word, it will not be surrounded by parentheses. With this option on,\n\
as long as it is a token, there will be parentheses surrounded, indicating\n\
it is under word weight threshold.\n\
For example, if \"interface\", \"up\" and \"down\" are under word weight\n\
threshold. By default, output is\n\
Interface eth0 (up|down)\n\
With this option, output is\n\
(Interface) eth0 (up|down)\n\
This option is meaningless without '--wweight' option.\n\
\n\
--help, or -h\n\
Print this help.\n\
\n\
--version\n\
Print the version information.\n\
"

#define MALLOC_ERR_6000 "malloc() failed! Function: main()."
#define MALLOC_ERR_6001 "malloc() failed! Function: init_input_parameters()."
#define MALLOC_ERR_6002 "malloc() failed! Function: create_trie_node()."
#define MALLOC_ERR_6003 "malloc() failed! Function: build_prefix_trie()."
#define MALLOC_ERR_6004 "malloc() failed! Function: build_input_file_chain()."
#define MALLOC_ERR_6005 "malloc() failed! Function: build_template_chain()."
#define MALLOC_ERR_6006 "malloc() failed! Function: parse_options()."
#define MALLOC_ERR_6007 "malloc() failed! Function: add_elem()."
#define MALLOC_ERR_6008 "malloc() failed! Function: find_words()."
#define MALLOC_ERR_6009 "malloc() failed! Function: create_cluster_instance()."
#define MALLOC_ERR_6010 "malloc() failed! Function: create_cluster_with_token_instance()."
#define MALLOC_ERR_6011 "malloc() failed. Function: adjust_cluster_with_token_instance()."
#define MALLOC_ERR_6012 "malloc() failed. Function: debug_1_print_frequent_words()."
#define MALLOC_ERR_6013 "malloc() failed. Function: debug_1_print_cluster_candidates()."
#define MALLOC_ERR_6014 "malloc() failed. Function: step_1_create_word_sketch()."
#define MALLOC_ERR_6015 "malloc() failed. Function: step_1_create_vocabulary()."
#define MALLOC_ERR_6016 "malloc() failed. Function: step_2_create_cluster_sketch()."
#define MALLOC_ERR_6017 "malloc() failed. Function: step_2_find_cluster_candidates()."
#define MALLOC_ERR_6018 "malloc() failed. Function: print_clusters_default_1()."
#define MALLOC_ERR_6019 "malloc() failed. Function: print_clusters_if_join_cluster_default_0()."
#define MALLOC_ERR_6020 "malloc() failed. Function: __print_clusters_if_join_cluster_default_0()."

/* Configurable enviroment variables */

/* Maximum length of a line. */
#define MAXLINELEN 10240
/* Maximum length of a word, should be at least MAXLINELEN+4. */
#define MAXWORDLEN 10248
/* Maximum number of words in one line. */
#define MAXWORDS 512
/* Maximum log message length. */
#define MAXLOGMSGLEN 256
/* Maximum number of () expressions in regexp. */
#define MAXPARANEXPR 100
/* Character that starts backreference variables. */
#define BACKREFCHAR '$'
/* Maximum digit length, that is displayed in output. E.g. the number of
 frequent words and clusters.*/
#define MAXDIGITBIT 32
/* Separator character used for building hash keys of the cluster hash table. */
#define CLUSTERSEP '\n'
/* Maximum hash key length in cluster hash table. */
#define MAXKEYLEN 20480
/* Token length used in Join_Clusters. Token is an identifier for the words that
 is below word weight threshold. */
#define TOKENLEN 10
/* Word hash table's default size is 100000. */
#define DEF_WORD_TABLE_SIZE 100000
/* InitSeed is default to 1. It is used to generate random numbers, which help
 in the string hashing processes. */
#define DEF_INIT_SEED 1
/* Debug_2_interval defines after how many lines program status will refresh.
 Debug_3_interval is the time interval(seconds) to refresh status. */
#define DEBUG_2_INTERVAL 200000
#define DEBUG_3_INTERVAL 5
/* If --syslog option is given, log messages under or equal to
 DEF_SYSLOG_THRESHOLD will be written to Syslog. Setting it to LOG_NOTICE(5),
 (see syslog.h) can prevent potential massive LOG_INFO and LOG_DEBUG messages
 from polluting Syslog. */
#define DEF_SYSLOG_THRESHOLD LOG_NOTICE
/* If user doesn't append an argument after --syslog option, the default syslog
 facility is "local2". */
#define DEF_SYSLOG_FACILITY "local2"
/* Words are separated by space. Tab is not considered as a separator. */
//#define DEF_WORD_DELM "[ \t]+"
#define DEF_WORD_DELM "[ ]+"

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))

static char *pSyslogFacilityList[] =
{
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "log_audit",
    "log_alert",
    "cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7"
};

/* Struct definitions */

struct Cluster;

/* This struct stores input file(s)'s path(s).
 
 lineNumber is the count of lines of this file. It is used for debug purpose,
 helps in the calculation of the mining process status. */
struct InputFile {
    char *pName;
    linenumber_t lineNumber;
    struct InputFile *pNext;
};

/* This struct stores elements that are placed into hash tables. One element can
 be a word or a cluster candidate.
 
 pKey is the identifier(description).
 
 count increments every time when element's identifier occurs.
 
 number is a sequential and unique ID, which is assigned to an element when it
 first appears.
 
 If an element is a cluster candidate, there will be a dedicated struct Cluster
 assigned to it, which contains more detailed information about this cluster
 candidate. Between Elem and Cluster, there is a bidirectional link pointing to
 each other.
 
 pNext points to the next element that shares the same hash slot, if there is
 any. */
struct Elem {
    char *pKey;
    support_t count;
    wordnumber_t number;
    struct Cluster *pCluster;
    struct Elem *pNext;
};

/* This struct stores information of templates, which is set with option
 '--template'. */
struct TemplElem {
    char *pStr;
    int data;
    struct TemplElem *pNext;
};

/* Word frequency statistics. */
struct WordFreqStat {
    wordnumber_t ones;
    wordnumber_t twos;
    wordnumber_t fives;
    wordnumber_t tens;
    wordnumber_t twenties;
};

/* This struct stores detailed information about cluster candidates(potential
 clusters). It has a bidirectional link with {struct Elem}.
 
 constants is the number of frequent words in this cluster candidate.
 
 count increments everytime when this cluster candidate occurs.
 
 fullWildcard stores the wildcard information of this cluster candidate,
 fullWildcard[0] is the number of minimum wildcard in tail. fullWildcard[1] is
 the number of maximum wildcard in tail. fullWildcard[2] is the number of
 minimum wildcard of the 1st constant. fullWildcard[3] is the number of the
 maximum wildcard of the 1st constant. fullWildcard[4] and fullWildcard[5]
 are for the 2nd constant, and so on..
 
 For example, if a cluster candidate is "*{8,9} Interface *{0,7} break *{2,3}",
 its fullWildcard will store 2,3,8,9,0,7.
 
 pElem is the bidirectional link, towards the element which is stored in cluster
 hash table.
 
 ppWord is an array that stores each constant's element, which is stored in word
 hash table.
 
 If Aggregate_Supports heuristics is used('--aggrsup' option), pLastNode is the
 address of the cluster candidate's last node in prefix tree. According to this
 address, this cluster candidate's parent and other relatives can be back
 tracked. Prefix tree(aka trie) is build for efficiently looking up for cluster
 candidates that have a comman prefix, thus efficiently checking if one cluster
 candidate's support value can be aggregated to another.
 
 If Join_Clusters heuristics is used('--wweight' option), bIsJoined is the flag
 indicates whether this cluster has token(word that is under word weight
 threshold). If a cluster has token, it will be ignored in the process of
 printing clusters. Instead, programme will print the joined cluster which is
 stored in another struct({struct ClusterWithToken}) which is dedicated to
 Join_Clusters heuristics.
 
 pNext: Besides the cluster hash table, which stores {struct Elem} address, we
 have an organized array table(pClusterFamily[]) to store {struct Cluster}
 address, assigning each cluster candidate into slot according to it constants(
 the number of frequent words). pNext stores the address of next
 {struct Cluster} sharing the same slot in pClusterFamily[].
 
 For example, cluster candidates with description "Interface *{1,2} down" and
 "User login *{1,1}" share the same slot pClusterFamily[2]. */
struct Cluster {
    int constants;
    support_t count;
    int fullWildcard[(MAXWORDS + 1) * 2];
    struct Elem *pElem;
    struct Elem **ppWord;
    struct TrieNode *pLastNode;
    char bIsJoined;
    struct Cluster *pNext;
};

/*This struct is dedicated to Join_Clusters heuristics.
 
 More details are in the description of {struct ClusterWithToken}. */
struct Token {
    struct Elem *pWord;
    struct Token *pNext;
};

/*This struct is dedicated to Join_Clusters heuristics.
 
 If a cluster has token, this cluster's bIsJoined will be marked, and this
 cluster's information stored in {struct Cluster} will be copied into a new
 struct {struct ClusterWithToken}.
 
 Compared to {struct Cluster}, there are only two different attributes: pNext
 and ppToken. The other attributes store the same information as in former
 {struct Cluster}.
 
 pNext: We continue to use the same way of storage organization as
 {struct Cluster}, but only uses a different name pClusterWithTokenFamily[].
 pNext stores the address of next {struct ClusterWithToken} that shares the same
 slot.
 
 ppToken: For every cluster that has token and thus transfered into
 {struct ClusterWithToken}, we malloc an array according to its constants. Every
 constant has a slot to store tokens, which contain the original words(which are
 frequent words, but are under word weight threshold). When printing clusters in
 pClusterWithTokenFamily[], we can know the original words from ppToken, and
 print strings contain word summary, such like:
 
 Interface *{2,3}(A|B|C) *{0,2}
 */
struct ClusterWithToken {
    int constants;
    support_t count;
    int fullWildcard[(MAXWORDS + 1) * 2];
    struct Elem *pElem;
    struct Elem **ppWord;
    struct TrieNode  *pLastNode;
    char bIsJoined;
    struct ClusterWithToken *pNext;
    
    /*The order of elements in this struct matters. In later process, type
     {struct ClusterWithToken} and type {struct Cluster} will be force
     transfered to each other.*/
    struct Token **ppToken;
};

/* This struct is dedicated to Aggregate_Supports heuristics.
 
 Every node is a constant or wildcard(*{min,max}) in cluster candidates.
 
 Every node has only one pParent, pNext and pChlid.
 
 pIsEnd indicates a cluster candidates ends in this node, and stores the address
 of {struct Cluster}. Otherwise, it is null(0).
 
 When node is a constant(frequent word), pWord stores the address of
 {struct Elem}.
 
 When node is a wildcard, we store its minimum and maximum value in wildcardMin
 and wildcardMax.
 
 hashValue is for efficently inserting and looking up. We use strcmp() or
 wildcardMin/Max compare to see if the node to be inserted is already exist,
 only if their hashValue is equal.
 
 When node is a constant, hashValue is calculated by str2hash() function, with a
 hash module size (frequent word number) * 3.
 
 When node is a wildcard, its hashValue is (frequent word number) * 3. All
 wildcards, regardless of their minimun and maximum, have the same hashValue.
 
 Nodes in the same horizontal level and with a common parent, are arranged
 from left to right with a descending hashValue. Therefore, when inserting new
 node in prefix tree, we check if it already exist by comparing hashValue, with
 an order from big to small. In other words, wildcards are always in the front
 part of comparison, which obeys the statistics feature of cluster candidates.
 */
struct TrieNode {
    struct TrieNode *pParent;
    struct TrieNode *pNext;
    struct TrieNode *pChild;
    struct Cluster *pIsEnd;
    struct Elem *pWord;
    int wildcardMin;
    int wildcardMax;
    wordnumber_t hashValue;
};

/* This struct stores parameters. */
struct Parameters {
    /* >>>Below are parameters that can be changed by command line options. */
    char bAggrsupFlag;
    char bDetailedTokenFlag;
    char *pDelim;
    char *pFilter;
    char *pOutlier;
    char *pSyslogFacility;
    char *pWordFilter;
    char *pWordReplace;
    char *pWordSearch;
    double pctSupport;
    double wordWeightThreshold;
    int byteOffset;
    int debug;
    int outputMode;
    int wordWeightFunction;
    struct InputFile *pInputFiles;
    struct TemplElem *pTemplate;
    support_t support;
    tableindex_t clusterSketchSize;
    tableindex_t wordSketchSize;
    tableindex_t wordTableSize;
    unsigned int initSeed;
    
    /* >>>Below are parameters that are not visibe to user. */
    
    /* >>>>>> Common usage */
    char bSyslogFlag;
    /* biggestConstants stores the biggest constants ever happend to cluster
     candidates, in order to avoid unnecessay iterations to pClusterFamily[],
     who has a size of MAXWORDS + 1, which equals to 513. A normal log line with
     a normal length, usually has constants no more than 30. */
    int biggestConstants;
    /* syslogFacilityNum is calcualted according to user input and syslog.h. */
    int syslogFacilityNum;
    /* syslogThreshold is default to LOG_NOTICE(5). */
    int syslogThreshold;
    regex_t delim_regex;
    regex_t filter_regex;
    /*pClusterFamily[] stores {struct Cluster} according to their constants. */
    struct Cluster *pClusterFamily[MAXWORDS + 1];
    /* ppClusterTable stores the pointer of every cluster candidate elem. So
     does ppWordTable. */
    struct Elem **ppClusterTable;
    struct Elem **ppWordTable;
    support_t *pClusterSketch;
    support_t *pWordSketch;
    tableindex_t clusterSketchSeed;
    tableindex_t clusterTableSeed;
    tableindex_t clusterTableSize;
    tableindex_t wordSketchSeed;
    tableindex_t wordTableSeed;
    wordnumber_t clusterCandiNum;
    wordnumber_t clusterNum;
    wordnumber_t freWordNum;
    wordnumber_t trieNodeNum;
    
    /* >>>>>> Used in Aggregate_Supports heuristics. */
    /* prefixWildcardMax/Min are used for temporary storage, when comparing
     wildcard nodes to see if it already exist. */
    int prefixWildcardMax;
    int prefixWildcardMin;
    /* pPrefixRet is used for temporary storage. */
    struct TrieNode *pPrefixRet;
    struct TrieNode *pPrefixRoot;
    tableindex_t prefixSketchSeed;
    /* wildcardHash and prefixSketchSize will be set to
     (frequent word number) * 3. */
    wordnumber_t prefixSketchSize;
    wordnumber_t wildcardHash;
    
    /* >>>>>> Used in Join_Clusters heuristics. */
    /* The content of token. Default is "token". If "token" is already among
     the frequent words, random string that is not among frquent words will be
     generated and replace it.*/
    char token[TOKENLEN];
    /* Temporarily mark a cluster's constant as token, for upcoming process's
     usage. If this cluster has token, tokenMarker[0] is set to 1.
     Corresponding constants's slot will also be set to 1. */
    char tokenMarker[MAXWORDS + 1];
    /* When we calculate a cluter's constants' word weight, using function_2,
     we will get every unique word out of constants. In order to avoid doing
     this job every time for each constant in the same cluster(the result will
     be the same), we use this pointer to indicate current cluster that is
     under processing. We do this getting_unique_words job again only if our
     target cluster differs from pCurrentCluster. */
    struct Cluster *pCurrentCluster;
    /* An array storages Clusters that have token. It's simialr as
     pClusterFamily[]. */
    struct ClusterWithToken *pClusterWithTokenFamily[MAXWORDS + 1];
    /* JoinedClusterInput/OutputNum are used for statistics purpose. They
     record how many clusters have been joined, and how many new clusters the
     joined clusters have generated. */
    tableindex_t joinedClusterInputNum;
    tableindex_t joinedClusterOutputNum;
    /* Word Dependency Matrix Breadth will be (number of frequent words) + 1. */
    tableindex_t wordDepMatrixBreadth;
    /* Short for wordNumberStorage, used for temporarily store the constants'
     numbers, as their identifier. The numbers will be used to update word
     dependency matrix. */
    wordnumber_t wordNumStr[MAXWORDS + 1];
    /* This matrix is a square matix. We need one pass over the data set to get
     this matrix. The matrix will be updated once, after each reading of a
     single log line. To optimize performance, this pass over the data set is
     intergrated with find_cluster_candidates()(doing two different jobs at
     the same pass over the data set). */
    wordnumber_t *wordDepMatrix;
    
    /* >>>>>> Used in '--debug' option. */
    /* Temporarily storage cluster candidates' description before printing them
     out in debug mode. */
    char clusterDescription[MAXLOGMSGLEN];
    /* linecount is the total number of lines in all input files. It is used
     for calculation of processing status. */
    support_t linecount;
    int dataPassTimes;
    support_t totalLineNum;
    char totalLineNumDigit[MAXDIGITBIT];
    time_t timeStorage;
    
    /* >>>>>> Used in '--wfilter/--wsearch/--wreplace'options. */
    regex_t wfilter_regex;
    regex_t wsearch_regex;
    //char *pWordFilter;
    //char *pWordSearch;
    //char *pWordReplace;
    /* To avoid modifying original words that is gotten from log lines, we use
     tmpStr to make a copy of it and do modification on this copy.
     With current functions, it is fine to direct modify original words, but
     we define and use this tmpStr, in case there are other functions being
     added in the future that are sensitive to this issue. */
    char tmpStr[MAXWORDLEN];
    
};

/* Function declarations */

void log_msg(char *message, int logLv, struct Parameters* pPara);
tableindex_t str2hash(char *string, tableindex_t modulo, tableindex_t h);
void print_cluster_to_string(struct Cluster *pCluster,
                             struct Parameters *pParam);
void replace_string_for_word_search(long long start, long long end,
                                    char *pOriginStr, char *pStr);
int is_word_filtered(char *pStr, struct Parameters *pParam);
char *word_search_replace(char *pOriginStr, struct Parameters *pParam);
int is_word_repeated(wordnumber_t *storage, wordnumber_t wordNumber,
                     int serial);


/* Initialization of parameters */
int init_input_parameters(struct Parameters *pParam)
{
    int i;
    char *defSyslogFacility = DEF_SYSLOG_FACILITY;
    
    pParam->support = 0;
    pParam->pctSupport = 0;
    pParam->pInputFiles = 0;
    pParam->initSeed = DEF_INIT_SEED;
    pParam->wordTableSize = DEF_WORD_TABLE_SIZE;
    pParam->bSyslogFlag = 0;
    pParam->bDetailedTokenFlag = 0;
    
    pParam->pSyslogFacility = (char *) malloc(strlen(defSyslogFacility) + 1);
    if (!pParam->pSyslogFacility)
    {
        log_msg(MALLOC_ERR_6001, LOG_ERR, pParam);
        exit(1);
    }
    strcpy(pParam->pSyslogFacility, defSyslogFacility);
    
    pParam->pDelim = 0;
    pParam->byteOffset = 0;
    pParam->pFilter = 0;
    pParam->pTemplate = 0;
    pParam->wordSketchSize = 0;
    pParam->clusterSketchSize = 0;
    pParam->bAggrsupFlag = 0;
    pParam->wordWeightThreshold = 0;
    pParam->wordWeightFunction = 1;
    pParam->pOutlier = 0;
    pParam->debug = 0;
    pParam->outputMode = 0;
    
    pParam->syslogThreshold = DEF_SYSLOG_THRESHOLD;
    pParam->syslogFacilityNum = LOG_LOCAL2;
    pParam->wordTableSeed = 0;
    pParam->ppWordTable = 0;
    pParam->pWordSketch = 0;
    pParam->wordSketchSeed = 0;
    pParam->linecount = 0;
    pParam->dataPassTimes = 0;
    pParam->totalLineNum = 0;
    *pParam->totalLineNumDigit = 0;
    pParam->timeStorage = 0;
    pParam->freWordNum = 0;
    pParam->clusterNum = 0;
    pParam->clusterCandiNum = 0;
    pParam->pClusterSketch = 0;
    pParam->clusterSketchSeed = 0;
    pParam->clusterTableSize = 0;
    pParam->ppClusterTable = 0;
    pParam->clusterTableSeed = 0;
    pParam->biggestConstants = 0;
    pParam->wordDepMatrix = 0;
    pParam->wordDepMatrixBreadth = 0;
    pParam->trieNodeNum = 0;
    
    /* struct Cluster *clusterFamily[MAXWORDS + 1]; */
    for (i = 0; i < MAXWORDS + 1; i++)
    {
        pParam->pClusterFamily[i] = 0;
    }
    
    /* The initialzition of regex_t delim_regex is integrated to function
     validate_parameters(). */
    
    /* The initialzition of regex_t filter_regex is integrated to function
     validate_parameters(). */
    
    pParam->wildcardHash = 0;
    pParam->prefixSketchSize = 0;
    pParam->prefixSketchSeed = 0;
    pParam->prefixWildcardMin = 0;
    pParam->prefixWildcardMax = 0;
    pParam->pPrefixRoot = 0;
    pParam->pPrefixRet = 0;
    
    /* If "token" is in frequent words, another random string that is not in
     frequent words will replace "token". */
    strcpy(pParam->token, "token");
    
    for (i = 0; i <= MAXWORDS; i++)
    {
        pParam->tokenMarker[i] = 0;
    }
    
    pParam->joinedClusterInputNum = 0;
    pParam->joinedClusterOutputNum = 0;
    
    for (i = 0; i < MAXWORDS + 1; i++)
    {
        pParam->pClusterWithTokenFamily[i] = 0;
    }
    
    for (i = 0; i < MAXWORDS + 1; i++)
    {
        pParam->wordNumStr[i] = 0;
    }
    
    pParam->pCurrentCluster = 0;
    
    *pParam->clusterDescription = 0;
    
    /* The initialzition of regex_t wfilter_regex and wsearch_regex is 
     integrated to function validate_parameters(). */
    pParam->pWordFilter = 0;
    pParam->pWordSearch = 0;
    pParam->pWordReplace = 0;
    *pParam->tmpStr = 0;
    
    return 1;
}


/* Ates Goral's solution for generating random string. Used for token
 generation. */
/* http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c */
void gen_random_string(char *s, const int len)
{
    int i;
    static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";
    
    for (i = 0; i < len; ++i)
    {
        /* Maybe rand() % (sizeof(alphanum)) ? */
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    s[len] = 0;
}

/* The first parameter indicates whether the node is constant or wildcard. If
 node is constant, it will be the pointer of {struct Elem}. If node is
 wildcard, it will be null(0). */
struct TrieNode *create_trie_node(struct Elem *pElem, struct TrieNode *pParent,
                                  struct TrieNode *pPrev,
                                  struct Parameters *pParam)
{
    struct TrieNode *pNode = (struct TrieNode *)
    malloc(sizeof(struct TrieNode));
    
    if (!pNode)
    {
        log_msg(MALLOC_ERR_6002, LOG_ERR, pParam);
        exit(1);
    }
    
    pParam->trieNodeNum++;
    
    if (pElem == 0)
    {
        pNode->hashValue = pParam->wildcardHash;
        pNode->wildcardMin = pParam->prefixWildcardMin;
        pNode->wildcardMax = pParam->prefixWildcardMax;
    }
    else
    {
        pNode->hashValue = str2hash(pElem->pKey, pParam->prefixSketchSize,
                                    pParam->prefixSketchSeed);
        pNode->wildcardMin = 0;
        pNode->wildcardMax = 0;
    }
    
    pNode->pWord = pElem;
    
    pNode->pParent = pParent;
    pNode->pChild = 0;
    
    if (pPrev != 0)
    {
        pNode->pNext = pPrev->pNext;
        pPrev->pNext = pNode;
    }
    else
    {
        pNode->pNext = pParent->pChild;
        pParent->pChild = pNode;
    }
    
    pNode->pIsEnd = 0;
    
    return pNode;
}

/* Insert wildcard into trie. */
int insert_cluster_into_trie_wildcard(struct TrieNode *pParent, int min,
                                      int max, struct Parameters *pParam)
{
    struct TrieNode *ptr;
    ptr = pParent->pChild;
    
    while (ptr)
    {
        if (ptr->hashValue == pParam->wildcardHash)
        {
            if (ptr->wildcardMin == min && ptr->wildcardMax == max)
            {
                pParam->pPrefixRet = ptr;
                return 1;
            }
            else
            {
                ptr = ptr->pNext;
            }
            
        }
        else
        {
            pParam->pPrefixRet = 0;
            return 0;
        }
    }
    
    pParam->pPrefixRet = 0;
    return 0;
}

/* Insert constant into trie. */
int insert_cluster_into_trie_word(struct TrieNode *pParent, struct Elem *pWord,
                                  struct Parameters *pParam)
{
    wordnumber_t hash;
    struct TrieNode *ptr, *pPrev;
    
    hash = str2hash(pWord->pKey, pParam->prefixSketchSize,
                    pParam->prefixSketchSeed);
    
    ptr = pParent->pChild;
    pPrev = 0;
    
    while (ptr)
    {
        if (ptr->hashValue > hash)
        {
            pPrev = ptr;
            ptr = ptr->pNext;
            continue;
        }
        
        if (ptr->hashValue == hash)
        {
            if (!strcmp(ptr->pWord->pKey, pWord->pKey))
            {
                pParam->pPrefixRet = ptr;
                return 1;
            }
            else
            {
                pPrev = ptr;
                ptr = ptr->pNext;
                continue;
            }
            
        }
        
        if (ptr->hashValue < hash)
        {
            pParam->pPrefixRet = pPrev;
            return 0;
        }
    }
    
    pParam->pPrefixRet = pPrev;
    return 0;
}

void insert_cluster_into_trie(struct TrieNode *pRoot, struct Cluster *pCluster,
                              struct Parameters *pParam)
{
    int i;
    int wildcardMin, wildcardMax;
    struct TrieNode *ptr;
    ptr = pRoot;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        if (pCluster->fullWildcard[i * 2 + 1] != 0)
        {
            //insert_wild_card
            wildcardMin = pCluster->fullWildcard[i * 2];
            wildcardMax = pCluster->fullWildcard[i * 2 + 1];
            if (insert_cluster_into_trie_wildcard(ptr, wildcardMin, wildcardMax,
                                                  pParam))
            {
                //Found
                ptr = pParam->pPrefixRet;
            }
            else
            {
                //Not found
                pParam->prefixWildcardMin = wildcardMin;
                pParam->prefixWildcardMax = wildcardMax;
                
                ptr = create_trie_node(0, ptr, pParam->pPrefixRet, pParam);
            }
            
            //insert_word
            if (insert_cluster_into_trie_word(ptr, pCluster->ppWord[i], pParam))
            {
                //Found
                ptr = pParam->pPrefixRet;
            }
            else
            {   //Not found
                ptr = create_trie_node(pCluster->ppWord[i], ptr,
                                       pParam->pPrefixRet, pParam);
            }
            
        }
        else
        {
            //insert_word
            if (insert_cluster_into_trie_word(ptr, pCluster->ppWord[i], pParam))
            {
                //Found
                ptr = pParam->pPrefixRet;
            }
            else
            {   //Not found
                ptr = create_trie_node(pCluster->ppWord[i], ptr,
                                       pParam->pPrefixRet, pParam);
            }
        }
    }
    
    // Deal with the tail.
    if (pCluster->fullWildcard[1] != 0)
    {
        //insert_wild_card
        wildcardMin = pCluster->fullWildcard[0];
        wildcardMax = pCluster->fullWildcard[1];
        if (insert_cluster_into_trie_wildcard(ptr, wildcardMin, wildcardMax,
                                              pParam))
        {
            //Found
            ptr = pParam->pPrefixRet;
        }
        else
        {
            //Not found
            pParam->prefixWildcardMin = wildcardMin;
            pParam->prefixWildcardMax = wildcardMax;
            
            ptr = create_trie_node(0, ptr, pParam->pPrefixRet, pParam);
        }
    }
    
    ptr->pIsEnd = pCluster;
    pCluster->pLastNode = ptr;
}

/* Find the first wildcard of a cluster candidates, counting from left to
 right. In other words, find the first constant, who has a wildcard. */
int get_first_wildcard_location(struct Cluster *pCluster)
{
    int i;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        if (pCluster->fullWildcard[i * 2 + 1] != 0)
        {
            return i;
        }
    }
    
    if (pCluster->fullWildcard[1] != 0)
    {
        return 0;
    }
    
    return -1;
}

/* Find the nearest wildcard, counting from the lowest leaf towards root. */
int get_first_wildcard_reverse_depth(struct Cluster *pCluster)
{
    int location;
    int i;
    int reverseDepth;
    
    location = get_first_wildcard_location(pCluster);
    
    if (location == -1)
    {
        return 0;
    }
    
    if (location == 0)
    {
        return 1;
    }
    
    reverseDepth = 0;
    
    for (i = location; i <= pCluster->constants; i++)
    {
        
        if (pCluster->fullWildcard[i * 2 + 1] != 0)
        {
            reverseDepth++;
        }
        reverseDepth++;
    }
    
    if (pCluster->fullWildcard[1] != 0)
    {
        reverseDepth++;
    }
    
    return reverseDepth;
    
}

/* Find the common parent of a cluster candidate. From this node on, who is
 considered as the common parent, we will find all the child branches. Those
 branches have potential of being specified expressions of our cluster
 candidate, thus their support values can be aggregated to our cluster
 candidate's support value. */
struct TrieNode *get_common_parent(struct Cluster *pCluster)
{
    struct TrieNode *ptr;
    int reverseDepth;
    int i;
    
    reverseDepth = get_first_wildcard_reverse_depth(pCluster);
    ptr = pCluster->pLastNode;
    
    for (i = 1; i <= reverseDepth; i++)
    {
        ptr = ptr->pParent;
    }
    
    /* ptr is the parent of the first wildcard node. */
    return ptr;
}

int find_more_specific_tail(struct TrieNode *pParent, struct Cluster*pCluster,
                            int min, int max)
{
    struct TrieNode *ptr;
    
    for (ptr = pParent->pChild; ptr; ptr = ptr->pNext)
    {
        if (ptr->wildcardMax == 0)
        {
            min += 1;
            max += 1;
        }
        else
        {
            min += ptr->wildcardMin;
            max += ptr->wildcardMax;
        }
        
        if (min < pCluster->fullWildcard[0])
        {
            find_more_specific_tail(ptr, pCluster, min, max);
            if (ptr->wildcardMax == 0)
            {
                min -= 1;
                max -= 1;
            }
            else
            {
                min -= ptr->wildcardMin;
                max -= ptr->wildcardMax;
            }
            continue;
        }
        
        if (max > pCluster->fullWildcard[1])
        {
            /* Exceeds the legal jump range. Not possible to be a more specific
             cluster candidates any more. */
            //break;
            if (ptr->wildcardMax == 0)
            {
                min -= 1;
                max -= 1;
            }
            else
            {
                min -= ptr->wildcardMin;
                max -= ptr->wildcardMax;
            }
            
            continue;
        }
        
        if (ptr->pIsEnd && (ptr->pIsEnd != pCluster))
        {
            //agrreate support
            //pCluster->count += ptr->pIsEnd->count;
            pCluster->pElem->count += ptr->pIsEnd->count;
        }
        
        find_more_specific_tail(ptr, pCluster, min, max);
        if (ptr->wildcardMax == 0)
        {
            min -= 1;
            max -= 1;
        }
        else
        {
            min -= ptr->wildcardMin;
            max -= ptr->wildcardMax;
        }
        //continue;
    }
    
    return 0;
}

/* The function to find the more specific cluster candidates for a certain
 cluster candidate. */
int find_more_specific(struct TrieNode *pParent, struct Cluster *pCluster,
                       int constant, int min, int max, wordnumber_t hash,
                       struct Parameters *pParam)
{
    struct TrieNode *ptr;
    wordnumber_t hashTmp;
    
    /* To find the 0st constant, means to deal with the tail of the cluster
     candidates. */
    if (constant == 0)
    {
        find_more_specific_tail(pParent, pCluster, min, max);
        return 0;
    }
    
    for (ptr = pParent->pChild; ptr; ptr = ptr->pNext)
    {
        if (ptr->wildcardMax == 0)
        {
            min += 1;
            max += 1;
        }
        else
        {
            min += ptr->wildcardMin;
            max += ptr->wildcardMax;
        }
        
        /* If the jump time is not enough to staisfy the minimum wildcard, jump
         down the tree once more, still looking for this constant. */
        if (min - 1 < pCluster->fullWildcard[constant * 2])
        {
            find_more_specific(ptr, pCluster, constant, min, max, hash, pParam);
            
            /* This node is done. Deal with its brothers. */
            if (ptr->wildcardMax == 0)
            {
                min -= 1;
                max -= 1;
            }
            else
            {
                min -= ptr->wildcardMin;
                max -= ptr->wildcardMax;
            }
            continue;
        }
        
        if (max - 1 > pCluster->fullWildcard[(constant * 2) + 1])
        {
            /* Jumped over the maximum limit. Not possible to be more specific
             cluster candidate anymore. */
            //break;
            
            if (ptr->wildcardMax == 0)
            {
                min -= 1;
                max -= 1;
            }
            else
            {
                min -= ptr->wildcardMin;
                max -= ptr->wildcardMax;
            }
            continue;
        }
        
        if (ptr->hashValue == hash &&
            (!strcmp(ptr->pWord->pKey, pCluster->ppWord[constant]->pKey)))
        {   //Found
            /* The constants are not all found, continue to look up next
             constant. */
            if (constant < pCluster->constants)
            {
                hashTmp = str2hash(pCluster->ppWord[constant + 1]->pKey,
                                   pParam->prefixSketchSize,
                                   pParam->prefixSketchSeed);
                find_more_specific(ptr, pCluster, constant + 1, 0, 0, hashTmp,
                                   pParam);
                
                /* After coming back, continue to deal with brothers. */
                if (ptr->wildcardMax == 0)
                {
                    min -= 1;
                    max -= 1;
                }
                else
                {
                    min -= ptr->wildcardMin;
                    max -= ptr->wildcardMax;
                }
                continue;
            }
            /* If all the constants are found. There will be two cases to be
             considered:
             1. there is a wildcard in tail.(Tail means what is after the last
             constant).
             2. there is no wildcard in tail. */
            if (constant == pCluster->constants)
            {
                /* If there is no wildcard in tail, and if this node is a
                 cluster candidate's end node, one result is found. We
                 aggregate the support value. */
                if (pCluster->fullWildcard[1] == 0)
                {
                    if (ptr->pIsEnd && (ptr->pIsEnd != pCluster))
                    {
                        //agrreate support
                        //pCluster->count += ptr->pIsEnd->count;
                        pCluster->pElem->count += ptr->pIsEnd->count;
                    }
                    
                    /* Continue to deal with its brothers. */
                    if (ptr->wildcardMax == 0)
                    {
                        min -= 1;
                        max -= 1;
                    }
                    else
                    {
                        min -= ptr->wildcardMin;
                        max -= ptr->wildcardMax;
                    }
                    continue;
                }
                else
                {
                    /* If there is a wildcard in tail, continue. Note the third
                     parameter is set to 0, which is different from normal
                     cases, and will triger function find_more_specific_tail().
                     */
                    if (pCluster->fullWildcard[0] == 0 && ptr->pIsEnd &&
                        (ptr->pIsEnd != pCluster))
                    {
                        //agrreate support
                        //pCluster->count += ptr->pIsEnd->count;
                        pCluster->pElem->count += ptr->pIsEnd->count;
                    }
                    
                    find_more_specific(ptr, pCluster, 0, 0, 0, hash, pParam);
                    
                    if (ptr->wildcardMax == 0)
                    {
                        min -= 1;
                        max -= 1;
                    }
                    else
                    {
                        min -= ptr->wildcardMin;
                        max -= ptr->wildcardMax;
                    }
                    continue;
                }
            }
            
        }
        else
        {
            find_more_specific(ptr, pCluster, constant, min, max, hash, pParam);
            
            if (ptr->wildcardMax == 0)
            {
                min -= 1;
                max -= 1;
            }
            else
            {
                min -= ptr->wildcardMin;
                max -= ptr->wildcardMax;
            }
            continue;
        }
    }
    
    return 0;
}

/* This function is called by function aggregate_candidates(). */
void aggregate_candidate(struct Cluster *pCluster, struct Parameters *pParam)
{
    struct TrieNode *pParent;
    int firstWildcardLoc;
    wordnumber_t hash;
    
    firstWildcardLoc = get_first_wildcard_location(pCluster);
    hash = 0;
    
    if (firstWildcardLoc)
    {
        hash = str2hash(pCluster->ppWord[firstWildcardLoc]->pKey,
                        pParam->prefixSketchSize, pParam->prefixSketchSeed);
    }
    
    pParent = get_common_parent(pCluster);
    find_more_specific(pParent, pCluster, firstWildcardLoc, 0, 0, hash, pParam);
    
}

/* There is a potential support value overlapping problem. Though rare, because
 the order I select cluster candidates to aggregate is from small constants to
 big constants, it could still happen.
 
 I am thinking of using the count in {struct Elem} as a mid-way storage,
 therefore the count in {struct Cluster} remains the unchanged during the
 aggregate process. After the aggregate process is done for every cluster
 candidates, transfer the count in {struct Elem} to {struct Cluster}. */
void aggregate_candidates(struct Parameters *pParam)
{
    int i;
    struct Cluster *ptr;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterFamily[i];
        while (ptr)
        {
            if (get_first_wildcard_location(ptr) >= 0)
            {
                aggregate_candidate(ptr, pParam);
            }
            ptr = ptr->pNext;
        }
    }
    
    /* After aggregation is done, assign each cluster candidates with the
     post-processed support value. ptr->pElem->count acts as a mid transfer. */
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterFamily[i];
        while (ptr)
        {
            ptr->count = ptr->pElem->count;
            
            ptr = ptr->pNext;
        }
    }
}

/* This function iterates all cluster candiates and build the prefix tree. */
struct TrieNode *build_prefix_trie(struct Parameters *pParam)
{
    int i = 0;
    struct Cluster *ptr;
    
    struct TrieNode *pRoot = (struct TrieNode *)
    malloc(sizeof(struct TrieNode));
    if (!pRoot)
    {
        log_msg(MALLOC_ERR_6003, LOG_ERR, pParam);
        exit(1);
    }
    
    pParam->trieNodeNum = 1;
    /* Root has unique id. */
    pRoot->hashValue = pParam->wildcardHash + 1;
    
    pRoot->pParent = 0;
    pRoot->pChild = 0;
    pRoot->pNext = 0;
    pRoot->pWord = 0;
    pRoot->wildcardMin = 0;
    pRoot->wildcardMax = 0;
    pRoot->pIsEnd = 0;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterFamily[i];
        while (ptr)
        {
            //build cluster into trie..
            insert_cluster_into_trie(pRoot, ptr, pParam);
            ptr = ptr->pNext;
        }
    }
    
    pParam->pPrefixRoot = pRoot;
    return pRoot;
}

void free_trie_nodes(struct TrieNode *pNode, struct Parameters *pParam)
{
    struct TrieNode *pNext, *pParent;
    
    if (pNode == 0)
    {
        return;
    }
    
    /*
     if (pParam->pPrefixRoot == 0)
     {
     return;
     }
     */
    
    //ptr = pNode;
    
    //debug purpose
    //char *tmp = "null11";
    //debug purpose...
    
    while (pNode)
    {
        free_trie_nodes(pNode->pChild, pParam);
        
        if (pParam->pPrefixRoot == 0)
        {
            return;
        }
        
        if (pNode != pParam->pPrefixRoot)
        {
            pNode->pParent->pChild = pNode->pNext;
        }
        
        pNext = pNode->pNext;
        pParent = pNode->pParent;
        
        //debug purpose
        //if (pNode->pWord) {
        //    log_msg(pNode->pWord->pKey, LOG_INFO, pParam);
        
        //}
        //else
        //{
        //    log_msg(tmp, LOG_INFO, pParam);
        //}
        //debug purpose...
        
        if (pNode == pParam->pPrefixRoot)
        {
            pParam->pPrefixRoot = 0;
        }
        
        free((void *) pNode);
        pNode = pNext;
        if (!pNode)
        {
            pNode =pParent;
            //pParent->pChild = 0;
        }
    }
    
}

/* Insert commas into numbers, between every three digits. */
/* Based on @Greg Hewgill's, from ideasman42. */
/* http://stackoverflow.com/questions/1449805/how-to-format-a-number-from-1123456789-to-1-123-456-789-in-c */
size_t str_format_int_grouped(char dst[MAXDIGITBIT], unsigned long num)
{
    char src[MAXDIGITBIT];
    char *p_src = src;
    char *p_dst = dst;
    
    const char separator = ',';
    int num_len, commas;
    
    num_len = sprintf(src, "%lu", num);
    
    if (*p_src == '-')
    {
        *p_dst++ = *p_src++;
        num_len--;
    }
    
    for (commas = 2 - num_len % 3; *p_src; commas = (commas + 1) % 3)
    {
        *p_dst++ = *p_src++;
        if (commas == 1)
        {
            *p_dst++ = separator;
        }
    }
    *--p_dst = '\0';
    
    return (size_t)(p_dst - dst);
}

int validate_parameters_template(struct Parameters *pParam)
{
    struct TemplElem *ptr;
    char logStr[MAXLOGMSGLEN];
    
    for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
    {
        if (!ptr->pStr && (ptr->data < 0 || ptr->data > MAXPARANEXPR -1))
        {
            sprintf(logStr, "'-t' or '--template' option requires"
                    "backreference variables to be in range $0...$%d",
                    MAXPARANEXPR - 1);
            log_msg(logStr, LOG_ERR, pParam);
            return 0;
        }
    }
    return 1;
}

int change_syslog_facility_number(struct Parameters *pParam)
{
    int i;
    
    for (i = 0; i < ARR_SIZE(pSyslogFacilityList); i++)
    {
        if (!strcmp(pParam->pSyslogFacility, pSyslogFacilityList[i]))
        {
            switch (i)
            {
                case 0:
                    pParam->syslogFacilityNum = LOG_KERN;
                    break;
                case 1:
                    pParam->syslogFacilityNum = LOG_USER;
                    break;
                case 2:
                    pParam->syslogFacilityNum = LOG_MAIL;
                    break;
                case 3:
                    pParam->syslogFacilityNum = LOG_DAEMON;
                    break;
                case 4:
                    pParam->syslogFacilityNum = LOG_AUTH;
                    break;
                case 5:
                    pParam->syslogFacilityNum = LOG_SYSLOG;
                    break;
                case 6:
                    pParam->syslogFacilityNum = LOG_LPR;
                    break;
                case 7:
                    pParam->syslogFacilityNum = LOG_NEWS;
                    break;
                case 8:
                    pParam->syslogFacilityNum = LOG_UUCP;
                    break;
                case 9:
                    pParam->syslogFacilityNum = LOG_CRON;
                    break;
                case 10:
                    pParam->syslogFacilityNum = LOG_AUTHPRIV;
                    break;
                case 11:
                    pParam->syslogFacilityNum = LOG_FTP;
                    break;
                case 12:
                case 13:
                case 14:
                case 15:
                    pParam->syslogFacilityNum = LOG_LOCAL2;
                    break;
                case 16:
                    pParam->syslogFacilityNum = LOG_LOCAL0;
                    break;
                case 17:
                    pParam->syslogFacilityNum = LOG_LOCAL1;
                    break;
                case 18:
                    pParam->syslogFacilityNum = LOG_LOCAL2;
                    break;
                case 19:
                    pParam->syslogFacilityNum = LOG_LOCAL3;
                    break;
                case 20:
                    pParam->syslogFacilityNum = LOG_LOCAL4;
                    break;
                case 21:
                    pParam->syslogFacilityNum = LOG_LOCAL5;
                    break;
                case 22:
                    pParam->syslogFacilityNum = LOG_LOCAL6;
                    break;
                case 23:
                    pParam->syslogFacilityNum = LOG_LOCAL7;
                    break;
                default:
                    pParam->syslogFacilityNum = LOG_LOCAL2;
                    break;
            }
            break;
        }
        else
        {
            if (i == ARR_SIZE(pSyslogFacilityList) - 1)
            {
                log_msg("'--syslog' option requires a legal string as "
                        "parameter, e.g. \"local2\".", LOG_ERR, pParam);
                return 0;
            }
        }
    }
    
    return 1;
}

int validate_parameters(struct Parameters *pParam)
{
    char *defSyslogFacility = DEF_SYSLOG_FACILITY;
    
    if (pParam->support <= 0 && pParam->pctSupport <= 0)
    {
        log_msg("'-s', '--support' or '--rsupport' option requires a positive"
                "number as parameter", LOG_ERR, pParam);
        return 0;
    }
    
    if (!pParam->pInputFiles)
    {
        log_msg("No input files specified", LOG_ERR, pParam);
        return 0;
    }
    
    //Comparison of unsigned expression < 0 is always false.
    if (pParam->initSeed <= 0)
    {
        log_msg("'-i' or '--initseed' option requires a positive number or "
                "zero as parameter", LOG_ERR, pParam);
        return 0;
    }
    
    if (pParam->wordTableSize <= 0)
    {
        log_msg("'-w' or '--wtablesize' option requires a positive number as "
                "parameter", LOG_ERR, pParam);
        return 0;
    }
    
    if (strcmp(pParam->pSyslogFacility, defSyslogFacility))
    {
        //tune facility
        if(!change_syslog_facility_number(pParam))
        {
            return 0;
        }
    }
    
    if (pParam->pDelim)
    {
        if (regcomp(&pParam->delim_regex, pParam->pDelim, REG_EXTENDED))
        {
            log_msg("Bad regular expression given with '-d' or '--separator' "
                    "option", LOG_ERR, pParam);
            return 0;
        }
    }
    else
    {
        regcomp(&pParam->delim_regex, DEF_WORD_DELM, REG_EXTENDED);
    }
    
    if (pParam->byteOffset < 0)
    {
        log_msg("'-b' or '--byteoffset' option requires a positive number as "
                "parameter", LOG_ERR, pParam);
        return 0;
    }
    
    if (pParam->pFilter && regcomp(&pParam->filter_regex, pParam->pFilter,
                                   REG_EXTENDED))
    {
        log_msg("Bad regular expression given with '-f' or '--lfilter' option",
                LOG_ERR, pParam);
        return 0;
    }
    
    if (pParam->pWordFilter)
    {
        if (!pParam->pWordSearch || !pParam->pWordReplace)
        {
            log_msg("If you set '--wfilter' option, '--wsearch' and "
                    "'--wreplace' must be set as well", LOG_ERR, pParam);
            return 0;
        }
    }
    
    if (pParam->pWordFilter && regcomp(&pParam->wfilter_regex,
                                       pParam->pWordFilter, REG_EXTENDED))
    {
        log_msg("Bad regular expression given with '--wfilter' option",
                LOG_ERR, pParam);
        return 0;
    }
    
    if (pParam->pWordSearch && regcomp(&pParam->wsearch_regex,
                                       pParam->pWordSearch, REG_EXTENDED))
    {
        log_msg("Bad regular expression given with '--wsearch' option",
                LOG_ERR, pParam);
        return 0;
    }
    
    if (!validate_parameters_template(pParam))
    {
        return 0;
    }
    
    //Comparison of unsigned expression < 0 is always false
    //if (pParam->wordSketchSize < 0)
    //{
    //    log_msg("'-v' or '--wsize' option requires a positive number as "
    //"parameter", LOG_ERR, pParam);
    //    return 0;
    //}
    
    //if (pParam->clusterSketchSize < 0)
    //{
    //    log_msg("'-c' or '--csize' option requires a positive number as "
    //"parameter", LOG_ERR, pParam);
    //    return 0;
    //}
    
    if (pParam->wordWeightThreshold < 0 || pParam->wordWeightThreshold > 1)
    {
        log_msg("'--wweight' option requires a valid number: 0<number<=1",
                LOG_ERR, pParam);
        return 0;
    }
    
    if (pParam->wordWeightFunction != 1 && pParam->wordWeightFunction != 2)
    {
        log_msg("'--weightf' option requires a valid number: 1 or 2", LOG_ERR,
                pParam);
        return 0;
    }
    
    if (pParam->debug != 0 && pParam->debug != 1 && pParam->debug != 2 &&
        pParam->debug != 3)
    {
        log_msg("'--debug' option requires a valid number: 1, 2 or 3", LOG_ERR,
                pParam);
        return 0;
    }
    
    if (pParam->outputMode != 0 && pParam->outputMode != 1)
    {
        log_msg("'--outputMode' option requires a valid number: 1", LOG_ERR,
                pParam);
        return 0;
    }
    
    if (pParam->clusterSketchSize && pParam->bAggrsupFlag)
    {
        log_msg("'--csize' option can not be used together with '--aggrsup' "
                "option", LOG_ERR, pParam);
        return 0;
    }
    
    return 1;
}

/* Fast string hashing algorithm by M.V.Ramakrishna and Justin Zobel. */
tableindex_t str2hash(char *string, tableindex_t modulo, tableindex_t h)
{
    int i;
    for (i = 0; string[i] != 0; ++i)
    {
        h = h ^ ((h << 5) + (h >> 2) + string[i]);
    }
    return h % modulo;
}

/* String lower case convertion, by by J.F. Sebastian. */
void string_lowercase(char *p)
{
    for ( ; *p; ++p) *p = tolower(*p);
}

/* Log message operator. It refines a message into timestamped format, and
 forwards it to user terminal. It also forwards the message to Syslog. */
void log_msg(char *message, int logLv, struct Parameters* pParam)
{
    time_t t;
    char *timestamp;
    
    t = time(0);
    timestamp = ctime(&t);
    timestamp[strlen(timestamp) - 1] = 0;
    fprintf(stderr, "%s: %s\n", timestamp, message);
    
    if (pParam->bSyslogFlag == 1)
    {
        syslog(logLv, "%s", message);
    }
}

void print_usage()
{
    fprintf(stderr, "\n");
    fprintf(stderr, VERSIONINFO);
    fprintf(stderr, "\n");
    fprintf(stderr, USAGEINFO);
}

void build_input_file_chain(char *pFilename, struct Parameters *pParam)
{
    struct InputFile *ptr;
    char logStr[MAXLOGMSGLEN];
    
    if (!pParam->pInputFiles)
    {
        pParam->pInputFiles = (struct InputFile *)
        malloc(sizeof(struct InputFile));
        if (!pParam->pInputFiles)
        {
            log_msg(MALLOC_ERR_6004, LOG_ERR, pParam);
            exit(1);
        }
        pParam->pInputFiles->pName = (char *) malloc(strlen(pFilename) +
                                                     1);
        if (!pParam->pInputFiles->pName)
        {
            log_msg(MALLOC_ERR_6004, LOG_ERR, pParam);
            exit(1);
        }
        strcpy(pParam->pInputFiles->pName, pFilename);
        pParam->pInputFiles->lineNumber = 0;
        pParam->pInputFiles->pNext = 0;
    }
    else
    {
        for (ptr = pParam->pInputFiles; ptr->pNext; ptr = ptr->pNext);
        ptr->pNext = (struct InputFile *) malloc(sizeof(struct InputFile));
        if (!ptr->pNext)
        {
            log_msg(MALLOC_ERR_6004, LOG_ERR, pParam);
            exit(1);
        }
        ptr = ptr->pNext;
        ptr->pName = (char *) malloc(strlen(pFilename) + 1);
        if (!ptr->pName)
        {
            log_msg(MALLOC_ERR_6004, LOG_ERR, pParam);
            exit(1);
        }
        strcpy(ptr->pName, pFilename);
        ptr->lineNumber = 0;
        ptr->pNext = 0;
    }
    
    sprintf(logStr, "File %s is added", pFilename);
    log_msg(logStr, LOG_INFO, pParam);
}

/* File path wildcard supporting. */
void glob_filenames(char *pPattern, struct Parameters *pParam)
{
    glob_t globResults;
    char **ppFileNameVector;
    int i;
    
    glob(pPattern, GLOB_NOCHECK, 0, &globResults);
    
    ppFileNameVector = globResults.gl_pathv;
    
    for (i = 0; i < globResults.gl_pathc; i++)
    {
        build_input_file_chain(ppFileNameVector[i], pParam);
    }
    
    globfree(&globResults);
}

void build_template_chain(char *opt, struct Parameters *pParam)
{
    static struct TemplElem *ptr = 0;
    int i, start, len;
    char *addr;
    
    i = 0;
    while (opt[i])
    {
        if (pParam->pTemplate)
        {
            ptr->pNext = (struct TemplElem *) malloc(sizeof(struct TemplElem));
            if (!ptr->pNext)
            {
                log_msg(MALLOC_ERR_6005, LOG_ERR, pParam);
                exit(1);
            }
            ptr = ptr->pNext;
        }
        else
        {
            pParam->pTemplate = (struct TemplElem *)
            malloc(sizeof(struct TemplElem));
            if (!pParam->pTemplate)
            {
                log_msg(MALLOC_ERR_6005, LOG_ERR, pParam);
                exit(1);
            }
            ptr = pParam->pTemplate;
        }
        
        if (opt[i] != BACKREFCHAR)
        {
            start = i;
            while (opt[i] && opt[i] != BACKREFCHAR)
            {
                i++;
            }
            len = i -start;
            ptr->pStr = (char *) malloc(len + 1);
            if (!ptr->pStr)
            {
                log_msg(MALLOC_ERR_6005, LOG_ERR, pParam);
                exit(1);
                
            }
            strncpy(ptr->pStr, opt + start, len);
            ptr->pStr[len] = 0;
            ptr->data = len;
        }
        else
        {
            ptr->pStr = 0;
            ptr->data = (int) strtol(opt + i + 1, &addr, 10);
            i = (int) (addr - opt);
        }
        
        ptr->pNext = 0;
    }
}

struct Elem *add_elem(char *pKey, struct Elem **ppTable,
                      tableindex_t tablesize, tableindex_t seed,
                      struct Parameters *pParam)
{
    tableindex_t hash;
    struct Elem *ptr, *pPrev;
    
    hash = str2hash(pKey, tablesize, seed);
    
    if (ppTable[hash])
    {
        pPrev = 0;
        ptr = ppTable[hash];
        
        while (ptr)
        {
            if (!strcmp(pKey, ptr->pKey))
            {
                break;
            }
            pPrev = ptr;
            ptr = ptr->pNext;
        }
        
        if (ptr)
        {
            ptr->count++;
            
            if (pPrev)
            {
                pPrev->pNext = ptr->pNext;
                ptr->pNext = ppTable[hash];
                ppTable[hash] = ptr;
            }
            
        }
        else
        {
            ptr = (struct Elem *) malloc(sizeof(struct Elem));
            if (!ptr)
            {
                log_msg(MALLOC_ERR_6007, LOG_ERR, pParam);
                exit(1);
            }
            
            ptr->pKey = (char *) malloc(strlen(pKey) + 1);
            if (!ptr->pKey)
            {
                log_msg(MALLOC_ERR_6007, LOG_ERR, pParam);
                exit(1);
            }
            
            strcpy(ptr->pKey, pKey);
            ptr->count = 1;
            ptr->pNext = ppTable[hash];
            
            ppTable[hash] = ptr;
            
        }
    }
    else
    {
        ptr = (struct Elem *) malloc(sizeof(struct Elem));
        if (!ptr)
        {
            log_msg(MALLOC_ERR_6007, LOG_ERR, pParam);
            exit(1);
        }
        
        ptr->pKey = (char *) malloc(strlen(pKey) + 1);
        if (!ptr->pKey)
        {
            log_msg(MALLOC_ERR_6007, LOG_ERR, pParam);
            exit(1);
        }
        
        strcpy(ptr->pKey, pKey);
        ptr->count = 1;
        ptr->pNext = 0;
        
        ppTable[hash] = ptr;
    }
    
    return ptr;
}

int find_words_debug_0_1(char *line, char (*words)[MAXWORDLEN],
                         struct Parameters *pParam)
{
    regmatch_t match[MAXPARANEXPR];
    
    int i, j, linelen, len;
    struct TemplElem *ptr;
    char *buffer = NULL;
    
    if (*line == 0)
    {
        return 0;
    }
    
    linelen = (int) strlen(line);
    
    
    if (pParam->byteOffset >= linelen)  { return 0; }
    
    if (pParam->byteOffset)
    {
        line += pParam->byteOffset;
        linelen -= pParam->byteOffset;
    }
    
    if (pParam->pFilter)
    {
        if (regexec(&pParam->filter_regex, line, MAXPARANEXPR, match, 0))
        {
            return 0;
        }
        
        if (pParam->pTemplate)
        {
            
            len = 0;
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                if (ptr->pStr)
                {
                    len += ptr->data;
                }
                else if (!ptr->data)
                {
                    len += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len += match[ptr->data].rm_eo - match[ptr->data].rm_so;
                }
            }
            
            i = 0;
            //free((void *) buffer);
            buffer = (char *) malloc(len + 1);
            if (!buffer)
            {
                log_msg(MALLOC_ERR_6008, LOG_ERR, pParam);
                exit(1);
            }
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                
                if (ptr->pStr)
                {
                    strncpy(buffer + i, ptr->pStr, ptr->data);
                    i += ptr->data;
                }
                else if (!ptr->data)
                {
                    strncpy(buffer + i, line, linelen);
                    i += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len = (int) (match[ptr->data].rm_eo -
                                 match[ptr->data].rm_so);
                    strncpy(buffer + i, line + match[ptr->data].rm_so, len);
                    i += len;
                }
            }
            
            buffer[i] = 0;
            line = buffer;
        }
        
    }
    
    for (i = 0; i < MAXWORDS; ++i)
    {
        if (regexec(&pParam->delim_regex, line, 1, match, 0))
        {  /* This is the last word. */
            for (j = 0; line[j] != 0; j++)
            {
                words[i][j] = line[j];
            }
            words[i][j] = 0;
            
            break;
        }
        
        for (j = 0; j < match[0].rm_so; ++j)
        {
            words[i][j] = line[j];
        }
        
        words[i][j] = 0;
        
        line += match[0].rm_eo;
        
        if (*line == 0)
        {
            break;
        }
    }
    
    if (pParam->pTemplate)
    {
        free((void *) buffer);
    }
    
    /* Return the word numbers in the line, including the repeated ones. */
    if (i == MAXWORDS)
    {
        return i;
    }
    else
    {
        return i+1;
    }
}

int find_words_debug_2(char *line, char (*words)[MAXWORDLEN],
                       struct Parameters *pParam)
{
    regmatch_t match[MAXPARANEXPR];
    
    int i, j, linelen, len;
    struct TemplElem *ptr;
    char *buffer = NULL;
    
    //debug2
    static support_t linecnt = 0;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    double pct;
    
    if (*line == 0)
    {
        return 0;
    }
    
    linelen = (int) strlen(line);
    
    
    if (pParam->byteOffset >= linelen)  { return 0; }
    
    if (pParam->byteOffset)
    {
        line += pParam->byteOffset;
        linelen -= pParam->byteOffset;
    }
    
    if (pParam->pFilter)
    {
        if (regexec(&pParam->filter_regex, line, MAXPARANEXPR, match, 0))
        {
            return 0;
        }
        
        if (pParam->pTemplate)
        {
            
            len = 0;
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                if (ptr->pStr)
                {
                    len += ptr->data;
                }
                else if (!ptr->data)
                {
                    len += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len += match[ptr->data].rm_eo - match[ptr->data].rm_so;
                }
            }
            
            i = 0;
            //free((void *) buffer);
            buffer = (char *) malloc(len + 1);
            if (!buffer)
            {
                log_msg(MALLOC_ERR_6008, LOG_ERR, pParam);
                exit(1);
            }
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                
                if (ptr->pStr)
                {
                    strncpy(buffer + i, ptr->pStr, ptr->data);
                    i += ptr->data;
                }
                else if (!ptr->data)
                {
                    strncpy(buffer + i, line, linelen);
                    i += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len = (int) (match[ptr->data].rm_eo -
                                 match[ptr->data].rm_so);
                    strncpy(buffer + i, line + match[ptr->data].rm_so, len);
                    i += len;
                }
            }
            
            buffer[i] = 0;
            line = buffer;
        }
        
    }
    
    for (i = 0; i < MAXWORDS; ++i)
    {
        if (regexec(&pParam->delim_regex, line, 1, match, 0))
        {  /* This is the last word. */
            for (j = 0; line[j] != 0; j++)
            {
                words[i][j] = line[j];
            }
            words[i][j] = 0;
            
            break;
        }
        
        for (j = 0; j < match[0].rm_so; ++j)
        {
            words[i][j] = line[j];
        }
        
        words[i][j] = 0;
        
        line += match[0].rm_eo;
        
        if (*line == 0)
        {
            break;
        }
    }
    
    if (pParam->pTemplate)
    {
        free((void *) buffer);
    }
    
    //debug_2
    linecnt++;
    if (linecnt % DEBUG_2_INTERVAL == 0)
    {
        str_format_int_grouped(digit, linecnt);
        if (pParam->totalLineNum)
        {
            pct = (double) linecnt / pParam->totalLineNum;
            sprintf(logStr, "%.2f%% Finished. - %s lines out of %s", pct * 100,
                    digit, pParam->totalLineNumDigit);
        }
        else
        {
            sprintf(logStr, "UNKNOWN%% Finished. - %s lines out of UNKNOWN.",
                    digit);
        }
        
        log_msg(logStr, LOG_DEBUG, pParam);
    }
    
    /* Return the word numbers in the line, including the repeated ones. */
    if (i == MAXWORDS)
    {
        return i;
    }
    else
    {
        return i+1;
    }
}

int find_words_debug_3(char *line, char (*words)[MAXWORDLEN],
                       struct Parameters *pParam)
{
    regmatch_t match[MAXPARANEXPR];
    
    int i, j, linelen, len;
    struct TemplElem *ptr;
    char *buffer = NULL;
    
    //debug3
    static support_t linecnt = 0;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    double pct;
    
    if (*line == 0)
    {
        return 0;
    }
    
    linelen = (int) strlen(line);
    
    
    if (pParam->byteOffset >= linelen)  { return 0; }
    
    if (pParam->byteOffset)
    {
        line += pParam->byteOffset;
        linelen -= pParam->byteOffset;
    }
    
    if (pParam->pFilter)
    {
        if (regexec(&pParam->filter_regex, line, MAXPARANEXPR, match, 0))
        {
            return 0;
        }
        
        if (pParam->pTemplate)
        {
            
            len = 0;
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                if (ptr->pStr)
                {
                    len += ptr->data;
                }
                else if (!ptr->data)
                {
                    len += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len += match[ptr->data].rm_eo - match[ptr->data].rm_so;
                }
            }
            
            i = 0;
            //free((void *) buffer);
            buffer = (char *) malloc(len + 1);
            if (!buffer)
            {
                log_msg(MALLOC_ERR_6008, LOG_ERR, pParam);
                exit(1);
            }
            
            for (ptr = pParam->pTemplate; ptr; ptr = ptr->pNext)
            {
                
                if (ptr->pStr)
                {
                    strncpy(buffer + i, ptr->pStr, ptr->data);
                    i += ptr->data;
                }
                else if (!ptr->data)
                {
                    strncpy(buffer + i, line, linelen);
                    i += linelen;
                }
                else if (match[ptr->data].rm_so != -1  &&
                         match[ptr->data].rm_eo != -1)
                {
                    len = (int) (match[ptr->data].rm_eo -
                                 match[ptr->data].rm_so);
                    strncpy(buffer + i, line + match[ptr->data].rm_so, len);
                    i += len;
                }
            }
            
            buffer[i] = 0;
            line = buffer;
        }
        
    }
    
    for (i = 0; i < MAXWORDS; ++i)
    {
        if (regexec(&pParam->delim_regex, line, 1, match, 0))
        {  /* This is the last word. */
            for (j = 0; line[j] != 0; j++)
            {
                words[i][j] = line[j];
            }
            words[i][j] = 0;
            
            break;
        }
        
        for (j = 0; j < match[0].rm_so; ++j)
        {
            words[i][j] = line[j];
        }
        
        words[i][j] = 0;
        
        line += match[0].rm_eo;
        
        if (*line == 0)
        {
            break;
        }
    }
    
    if (pParam->pTemplate)
    {
        free((void *) buffer);
    }
    
    //debug_3
    linecnt++;
    if (time(0) != pParam->timeStorage && time(0) % DEBUG_3_INTERVAL == 0)
    {
        pParam->timeStorage = time(0);
        str_format_int_grouped(digit, linecnt);
        if (pParam->totalLineNum)
        {
            pct = (double) linecnt / pParam->totalLineNum;
            sprintf(logStr, "%.2f%% Finished. - %s lines out of %s", pct * 100,
                    digit, pParam->totalLineNumDigit);
        }
        else
        {
            sprintf(logStr, "UNKNOWN%% Finished. - %s lines out of UNKNOWN.",
                    digit);
        }
        
        log_msg(logStr, LOG_DEBUG, pParam);
    }
    
    /* Return the word numbers in the line, including the repeated ones. */
    if (i == MAXWORDS)
    {
        return i;
    }
    else
    {
        return i+1;
    }
}

/* The three sub functions can be intergrated into one function. However, for
 the sake of performance and code readability, they are divided. When making
 changes to one function, don't forget to also change the corresponding lines
 in the other two functions. */
int find_words(char *line, char (*words)[MAXWORDLEN], struct Parameters *pParam)
{
    switch (pParam->debug)
    {
        case 0:
        case 1:
            return find_words_debug_0_1(line, words, pParam);
            break;
        case 2:
            return find_words_debug_2(line, words, pParam);
            break;
        case 3:
            return find_words_debug_3(line, words, pParam);
            break;
        default:
            break;
    }
    
    return 0;
}

/* This is a redundant function, which works similarly as function
 create_vocabulary(), but with consideration of '--wordfilter' option. Since
 this function has a coding style with overlaping IFs, it could be read while
 comparing function create_vocabulary() to see the differences. */

/* This redundant function can be intergated into its original function.
 However, for the sake of performance and readability of the original function,
 this function is separated as an alone function. */

/* In program, if '--wfilter' option is not used, this function will not be
 called. */

/* When making changes to this funciton, don't forget to also change its
 original function. */
wordnumber_t create_vocabulary_with_wfilter(struct Parameters *pParam)
{
    wordnumber_t number = 0;
    tableindex_t j, hash;
    struct InputFile *pFilePtr;
    FILE *pFile;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];   /*10240*/
    char words[MAXWORDS][MAXWORDLEN];   /*512 10248*/
    int i, len, wordcount, distinctWords;
    struct Elem *word;
    support_t linecount;
    char newWord[MAXWORDLEN];
    
    *newWord = 0;
    
    for (j = 0; j < pParam->wordTableSize; j++)
    {
        pParam->ppWordTable[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            distinctWords = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                if (words[i][0] == 0)
                {
                    continue;
                }
                
                if (pParam->wordSketchSize)
                {
                    hash = str2hash(words[i], pParam->wordSketchSize,
                                    pParam->wordSketchSeed);
                    
                    if (pParam->pWordSketch[hash] >= pParam->support)
                    {
                        word = add_elem(words[i], pParam->ppWordTable,
                                        pParam->wordTableSize,
                                        pParam->wordTableSeed,
                                        pParam);
                        
                        distinctWords++;
                        
                        if (word->count == 1)
                        {
                            number++;
                            word->number = number;
                        }
                        
                        /* If word is repeated..its support will not increment
                         more than once in one log line. */
                        if (is_word_repeated(pParam->wordNumStr, word->number,
                                             distinctWords))
                        {
                            distinctWords--;
                            word->count--;
                        }
                        else
                        {
                            pParam->wordNumStr[distinctWords] = word->number;
                        }
                        
                    }
                    
                    if (is_word_filtered(words[i], pParam))
                    {
                        strcpy(newWord, word_search_replace(words[i], pParam));
                        hash = str2hash(newWord, pParam->wordSketchSize,
                                        pParam->wordSketchSeed);
                        
                        if (pParam->pWordSketch[hash] >= pParam->support)
                        {
                            word = add_elem(newWord, pParam->ppWordTable,
                                            pParam->wordTableSize,
                                            pParam->wordTableSeed,
                                            pParam);
                            
                            distinctWords++;
                            
                            if (word->count == 1)
                            {
                                number++;
                                word->number = number;
                            }
                            
                            /* If word is repeated..its support will not
                             increment more than once in one log line. */
                            if (is_word_repeated(pParam->wordNumStr,
                                                 word->number, distinctWords))
                            {
                                distinctWords--;
                                word->count--;
                            }
                            else
                            {
                                pParam->wordNumStr[distinctWords]= word->number;
                            }
                            
                        }
                    }
                }
                else
                {
                    word = add_elem(words[i], pParam->ppWordTable,
                                    pParam->wordTableSize,
                                    pParam->wordTableSeed,
                                    pParam);
                    
                    distinctWords++;
                    
                    if (word->count == 1)
                    {
                        number++;
                        word->number = number;
                    }
                    
                    /* If word is repeated..its support will not increment more
                     than once in one log line. */
                    if (is_word_repeated(pParam->wordNumStr, word->number,
                                         distinctWords))
                    {
                        distinctWords--;
                        word->count--;
                    }
                    else
                    {
                        pParam->wordNumStr[distinctWords] = word->number;
                    }
                    
                    if (is_word_filtered(words[i], pParam))
                    {
                        strcpy(newWord, word_search_replace(words[i], pParam));
                        word = add_elem(newWord, pParam->ppWordTable,
                                        pParam->wordTableSize,
                                        pParam->wordTableSeed,
                                        pParam);
                        
                        distinctWords++;
                        
                        if (word->count == 1)
                        {
                            number++;
                            word->number = number;
                        }
                        
                        /* If word is repeated..its support will not increment
                         more than once in one log line. */
                        if (is_word_repeated(pParam->wordNumStr, word->number,
                                             distinctWords))
                        {
                            distinctWords--;
                            word->count--;
                        }
                        else
                        {
                            pParam->wordNumStr[distinctWords] = word->number;
                        }
                    }
                }
            }
            
            linecount++;
        }
        
        fclose(pFile);
        
    }
    
    if (!pParam->linecount)
    {
        pParam->linecount = linecount;
    }
    
    if (!pParam->support)
    {
        pParam->support = linecount * pParam->pctSupport / 100;
    }
    
    return number;
}

wordnumber_t create_vocabulary(struct Parameters *pParam)
{
    wordnumber_t number = 0;
    tableindex_t j, hash;
    struct InputFile *pFilePtr;
    FILE *pFile;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    int i, len, wordcount, distinctWords;
    struct Elem *word;
    support_t linecount;
    
    
    for (j = 0; j < pParam->wordTableSize; j++)
    {
        pParam->ppWordTable[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            distinctWords = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                if (words[i][0] == 0)
                {
                    continue;
                }
                
                /* The tehcnique to save memory space. */
                if (pParam->wordSketchSize)
                {
                    hash = str2hash(words[i], pParam->wordSketchSize,
                                    pParam->wordSketchSeed);
                    if (pParam->pWordSketch[hash] < pParam->support)
                    {
                        continue;
                    }
                }
                
                word = add_elem(words[i], pParam->ppWordTable,
                                pParam->wordTableSize, pParam->wordTableSeed,
                                pParam);
                distinctWords++;
                
                if (word->count == 1)
                {
                    number++;
                    word->number = number;
                }
                
                /* If word is repeated..its support will not increment more than
                 once in one log line. */
                if (is_word_repeated(pParam->wordNumStr, word->number,
                                     distinctWords))
                {
                    distinctWords--;
                    word->count--;
                }
                else
                {
                    pParam->wordNumStr[distinctWords] = word->number;
                }
                
            }
            
            linecount++;
        }
        
        fclose(pFile);
        
    }
    
    if (!pParam->linecount)
    {
        pParam->linecount = linecount;
    }
    
    if (!pParam->support)
    {
        pParam->support = linecount * pParam->pctSupport / 100;
    }
    
    return number;
}

void free_delim(struct Parameters *pParam)
{
    regfree(&pParam->delim_regex);
    if (pParam->pDelim)
    {
        free((void *) pParam->pDelim);
    }
}

void free_filter(struct Parameters *pParam)
{
    if (pParam->pFilter)
    {
        regfree(&pParam->filter_regex);
        free((void *) pParam->pFilter);
    }
    
}

void free_wfilter(struct Parameters *pParam)
{
    if (pParam->pWordFilter)
    {
        regfree(&pParam->wfilter_regex);
        free((void *) pParam->pWordFilter);
    }
}

void free_wsearch(struct Parameters *pParam)
{
    if (pParam->pWordSearch)
    {
        regfree(&pParam->wsearch_regex);
        free((void *) pParam->pWordSearch);
    }
}

void free_wreplace(struct Parameters *pParam)
{
    if (pParam->pWordReplace)
    {
        free((void *) pParam->pWordReplace);
    }
}

void free_template(struct Parameters *pParam)
{
    struct TemplElem *ptr, *pNext;
    
    ptr = pParam->pTemplate;
    
    while (ptr)
    {
        pNext = ptr->pNext;
        free((void *) ptr->pStr);
        free((void *) ptr);
        ptr = pNext;
    }
}

void free_word_table(struct Parameters *pParam)
{
    tableindex_t i;
    struct Elem *ptr, *pNext;
    
    for (i = 0; i < pParam->wordTableSize; ++i)
    {
        
        if (!pParam->ppWordTable[i])  { continue; }
        
        ptr = pParam->ppWordTable[i];
        
        while (ptr)
        {
            
            pNext = ptr->pNext;
            
            free((void *) ptr->pKey);
            free((void *) ptr);
            
            ptr = pNext;
            
        }
        
    }
    
    free((void *) pParam->ppWordTable);
}

void free_cluster_table(struct Parameters *pParam)
{
    tableindex_t i;
    struct Elem *ptr, *pNext;
    
    if (pParam->ppClusterTable)
    {
        for (i = 0; i < pParam->clusterTableSize; ++i)
        {
            
            if (!pParam->ppClusterTable[i])  { continue; }
            
            ptr = pParam->ppClusterTable[i];
            
            while (ptr)
            {
                pNext = ptr->pNext;
                
                free((void *) ptr->pKey);
                free((void *) ptr);
                
                ptr = pNext;
            }
        }
        
        free((void *) pParam->ppClusterTable);
    }
    
}

void free_word_sketch(struct Parameters *pParam)
{
    if (pParam->pWordSketch)
    {
        free((void *) pParam->pWordSketch);
    }
    
}

void free_cluster_sketch(struct Parameters *pParam)
{
    if (pParam->pClusterSketch)
    {
        free((void *) pParam->pClusterSketch);
    }
}

void free_inputfiles(struct Parameters *pParam)
{
    struct InputFile *ptr, *pNext;
    
    ptr = pParam->pInputFiles;
    
    while (ptr)
    {
        pNext = ptr->pNext;
        free((void *) ptr->pName);
        free((void *) ptr);
        ptr = pNext;
    }
}

void free_cluster_instances(struct Parameters *pParam)
{
    int i;
    struct Cluster *ptr, *pNext;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterFamily[i];
        while (ptr)
        {
            pNext = ptr->pNext;
            free((void *) ptr->ppWord);
            free((void *) ptr);
            ptr = pNext;
        }
    }
}

void free_syslog_facility(struct Parameters *pParam)
{
    free((void *) pParam->pSyslogFacility);
}

void free_outlier(struct Parameters *pParam)
{
    if (pParam->pOutlier)
    {
        free((void *) pParam->pOutlier);
    }
}

void free_token(struct ClusterWithToken *pClusterWithToken)
{
    int i;
    struct Token *ptr, *pNext;
    
    for (i = 1; i <= pClusterWithToken->constants; i++)
    {
        ptr = pClusterWithToken->ppToken[i];
        
        while (ptr)
        {
            pNext = ptr->pNext;
            free((void *) ptr);
            ptr = pNext;
        }
    }
}

void free_cluster_with_token_instances(struct Parameters *pParam)
{
    int i;
    struct ClusterWithToken *ptr, *pNext;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterWithTokenFamily[i];
        
        while (ptr)
        {
            pNext = ptr->pNext;
            free_token(ptr);
            free((void *) ptr->ppToken);
            free((void *) ptr->ppWord);
            free((void *) ptr);
            ptr = pNext;
        }
    }
}

void sort_elements(struct Elem **ppArray, wordnumber_t size,
                   struct Parameters *pParam)
{
    int i, j, imax;
    struct Elem *tmp;
    
    for (j = 0; j < size - 1; j++)
    {
        imax = j;
        
        for (i = j + 1; i < size; i++)
        {
            if (ppArray[i]->count > ppArray[imax]->count)
            {
                imax = i;
            }
        }
        tmp = ppArray[j];
        ppArray[j] = ppArray[imax];
        ppArray[imax] = tmp;
    }
}

/* The debug result is sorted, according to support in a descending order. */
void debug_1_print_frequent_words(struct Parameters *pParam)
{
    struct Elem **ppSortedArray;
    int i, j;
    struct Elem *ptr;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            pParam->freWordNum);
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6012, LOG_ERR, pParam);
        exit(1);
    }
    
    j = 0;
    
    for (i = 0; i < pParam->wordTableSize; i++)
    {
        if (!pParam->ppWordTable[i])
        {
            continue;
        }
        
        ptr = pParam->ppWordTable[i];
        
        while (ptr)
        {
            ppSortedArray[j] = ptr;
            j++;
            ptr = ptr->pNext;
        }
    }
    
    sort_elements(ppSortedArray, pParam->freWordNum, pParam);
    
    for (i = 0; i < pParam->freWordNum; i++)
    {
        str_format_int_grouped(digit, ppSortedArray[i]->count);
        sprintf(logStr, "Frequent word: %s -- occurs in %s lines",
                ppSortedArray[i]->pKey, digit);
        log_msg(logStr, LOG_DEBUG, pParam);
    }
    
    free((void *) ppSortedArray);
}

/* The debug result is sorted, according to support in a descending order. */
void debug_1_print_cluster_candidates(struct Parameters *pParam)
{
    struct Elem **ppSortedArray;
    int i, j;
    struct Elem *ptr;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            pParam->clusterCandiNum);
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6013, LOG_ERR, pParam);
        exit(1);
    }
    
    j = 0;
    
    for (i = 0; i < pParam->clusterTableSize; i++)
    {
        if (!pParam->ppClusterTable[i])
        {
            continue;
        }
        
        ptr = pParam->ppClusterTable[i];
        
        while (ptr)
        {
            ppSortedArray[j] = ptr;
            j++;
            ptr = ptr->pNext;
        }
    }
    
    sort_elements(ppSortedArray, pParam->clusterCandiNum, pParam);
    
    for (i = 0; i < pParam->clusterCandiNum; i++)
    {
        str_format_int_grouped(digit, ppSortedArray[i]->count);
        print_cluster_to_string(ppSortedArray[i]->pCluster, pParam);
        sprintf(logStr, "Cluster candidate with support %s: %s", digit,
                pParam->clusterDescription);
        log_msg(logStr, LOG_DEBUG, pParam);
    }
    
    free((void *) ppSortedArray);
}

/* Function dedicated to '--wfilter/--wsearch/--wreplace' options. */
void replace_string_for_word_search(long long start, long long end,
                                    char *pOriginStr, char *pStr)
{
    char tmp[MAXWORDLEN];
    int j, u, lenOriginStr, lenStr;
    long long i;
    
    *tmp = 0;
    j = 0;
    
    lenOriginStr = (int) strlen(pOriginStr);
    lenStr = (int) strlen(pStr);
    
    for (i = end; i < lenOriginStr; i++)
    {
        tmp[j] = pOriginStr[i];
        j++;
    }
    tmp[j] = 0;
    
    for (u = 0; u < lenStr; u++)
    {
        pOriginStr[start] = pStr[u];
        start++;
    }
    pOriginStr[start] = 0;
    
    strcat(pOriginStr, tmp);
}

/* Check if the word can be filtered and replaced with user specified string.
 The word should not only contain the regex in '--wfilter', but also contain
 the regex in '--wsearch' option. Otherwise, if it only satisfies '--wfilter',
 it will be counted twice when build the vocabulary. Then it will cause other
 sequentially problems. */
int is_word_filtered(char *pStr, struct Parameters *pParam)
{
    if (!regexec(&pParam->wfilter_regex, pStr, 0, 0, 0) &&
        !regexec(&pParam->wsearch_regex, pStr, 0, 0, 0))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* Avoid endless loop. There will be endless loop if this function is not
 called, in the example below:
 --wfilter=’=’, --wsearch=’=.+’, and --wreplace=’=VALUE’
 After replacing matched string with user specified string '=VALUE', the regex
 is still true, thus it causes endless loop, keeping replacing '=VALUE' with
 '=VALUE'. */
int check_endless_loop(long long start, long long end, struct Parameters *pParm)
{
    long long i;
    int j;
    
    j = 0;
    for (i = start; i < end; i++)
    {
        if (pParm->tmpStr[i] != pParm->pWordReplace[j])
        {
            return 1;
        }
        else
        {
            j++;
        }
    }
    return 0;
}

char *word_search_replace(char *pOriginStr, struct Parameters *pParam)
{
    regmatch_t match[MAXPARANEXPR];
    int cnt;
    
    strcpy(pParam->tmpStr, pOriginStr);
    cnt = 0;
    
    while (1)
    {
        if (!regexec(&pParam->wsearch_regex, pParam->tmpStr, 1, match, 0))
        {
            if (cnt && !check_endless_loop(match[0].rm_so, match[0].rm_eo,
                                           pParam))
            {
                break;
            }
            replace_string_for_word_search(match[0].rm_so, match[0].rm_eo,
                                           pParam->tmpStr, pParam->pWordReplace);
            cnt++;
        }
        else
        {
            break;
        }
    }
    
    return pParam->tmpStr;
}

/* This is a redundant function, which works similarly as function
 create_word_sketch(), but with consideration of '--wordfilter' option. Since
 this function has a coding style with overlaping IFs, it could be read while
 comparing function create_word_sketch() to see the differences. */

/* This redundant function can be intergated into its original function.
 However, for the sake of performance and readability of the original function,
 this function is separated as an alone function. */

/* In program, if '--wfilter' option is not used, this function will not be
 called. */

/* When making changes to this funciton, don't forget to also change its
 original function. */
tableindex_t create_word_sketch_with_wfilter(struct Parameters *pParam)
{
    FILE *pFile;
    tableindex_t hash, j, oversupport;
    int len, i, wordcount;
    support_t linecount;
    struct InputFile *pFilePtr;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    
    
    linecount = 0;
    
    for (j = 0; j < pParam->wordSketchSize; j++)
    {
        pParam->pWordSketch[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            for (i = 0; i < wordcount; i++)
            {
                if (words[i][0] == 0)
                {
                    continue;
                }
                
                hash = str2hash(words[i], pParam->wordSketchSize,
                                pParam->wordSketchSeed);
                
                pParam->pWordSketch[hash]++;
                
                if (is_word_filtered(words[i], pParam))
                {
                    hash = str2hash(word_search_replace(words[i], pParam),
                                    pParam->wordSketchSize,
                                    pParam->wordSketchSeed);
                    
                    pParam->pWordSketch[hash]++;
                }
            }
            
            linecount++;
        }
        
        fclose(pFile);
    }
    
    if (!pParam->linecount)
    {
        pParam->linecount = linecount;
    }
    
    if (!pParam->support)
    {
        pParam->support = linecount * pParam->pctSupport / 100;
    }
    
    oversupport = 0;
    
    for (j = 0; j < pParam->wordSketchSize; j++)
    {
        if (pParam->pWordSketch[j] >= pParam->support)
        {
            oversupport++;
        }
    }
    
    return oversupport;
}

tableindex_t create_word_sketch(struct Parameters *pParam)
{
    FILE *pFile;
    tableindex_t hash, j, oversupport;
    int len, i, wordcount;
    support_t linecount;
    struct InputFile *pFilePtr;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    
    linecount = 0;
    
    for (j = 0; j < pParam->wordSketchSize; j++)
    {
        pParam->pWordSketch[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            for (i = 0; i < wordcount; i++)
            {
                if (words[i][0] == 0)
                {
                    continue;
                }
                
                hash = str2hash(words[i], pParam->wordSketchSize,
                                pParam->wordSketchSeed);
                
                pParam->pWordSketch[hash]++;
            }
            
            linecount++;
        }
        
        fclose(pFile);
    }
    
    if (!pParam->linecount)
    {
        pParam->linecount = linecount;
    }
    
    if (!pParam->support)
    {
        pParam->support = linecount * pParam->pctSupport / 100;
    }
    
    oversupport = 0;
    
    for (j = 0; j < pParam->wordSketchSize; j++)
    {
        if (pParam->pWordSketch[j] >= pParam->support)
        {
            oversupport++;
        }
    }
    
    return oversupport;
}

wordnumber_t find_frequent_words(struct Parameters *pParam, wordnumber_t sum)
{
    tableindex_t i;
    wordnumber_t freWordNum;
    struct Elem *ptr, *pPrev, *pNext;
    struct WordFreqStat stat;
    char logStr[MAXLOGMSGLEN];
    float pct;
    char digit[MAXDIGITBIT];
    
    freWordNum = 0;
    
    stat.ones = 0;
    stat.twos = 0;
    stat.fives = 0;
    stat.tens = 0;
    stat.twenties = 0;
    
    for (i = 0; i < pParam->wordTableSize; i++)
    {
        if (!pParam->ppWordTable[i])
        {
            continue;
        }
        
        pPrev = 0;
        ptr = pParam->ppWordTable[i];
        
        while (ptr)
        {
            if (ptr->count == 1)  { stat.ones++; }
            if (ptr->count <= 2)  { stat.twos++; }
            if (ptr->count <= 5)  { stat.fives++; }
            if (ptr->count <= 10) { stat.tens++; }
            if (ptr->count <= 20) { stat.twenties++; }
            
            if (ptr->count < pParam->support)
            {
                if (pPrev)
                {
                    pPrev->pNext = ptr->pNext;
                }
                else
                {
                    pParam->ppWordTable[i] = ptr->pNext;
                }
                
                pNext = ptr->pNext;
                
                free((void *) ptr->pKey);
                free((void *) ptr);
                
                ptr = pNext;
            }
            else
            {
                /* Every frequent word gets a unique sequential ID, beginning
                 from 1, ending at FreWordNum. This unique ID is useful in word
                 dependency calculation. */
                ptr->number = ++freWordNum;
                pPrev = ptr;
                ptr = ptr->pNext;
            }
        }
    }
    
    str_format_int_grouped(digit, freWordNum);
    sprintf(logStr, "%s frequent words were found.", digit);
    log_msg(logStr, LOG_NOTICE, pParam);
    
    if (!freWordNum)
    {
        return 0;
    }
    
    str_format_int_grouped(digit, stat.ones);
    pct = ((float) stat.ones) / sum;
    sprintf(logStr, "%d%% - %s words in vocabulary occur 1 time.",
            (int) (pct * 100), digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, stat.twos);
    pct = ((float) stat.twos) / sum;
    sprintf(logStr, "%d%% - %s words in vocabulary occur 2 times or less.",
            (int) (pct * 100), digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, stat.fives);
    pct = ((float) stat.fives) / sum;
    sprintf(logStr, "%d%% - %s words in vocabulary occur 5 times or less.",
            (int) (pct * 100), digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, stat.tens);
    pct = ((float) stat.tens) / sum;
    sprintf(logStr, "%d%% - %s words in vocabulary occur 10 times or less.",
            (int) (pct * 100), digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, stat.twenties);
    pct = ((float) stat.twenties) / sum;
    sprintf(logStr, "%d%% - %s words in vocabulary occur 20 times or less.",
            (int) (pct * 100), digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, sum - freWordNum);
    pct = ((float) (sum - freWordNum)) / sum;
    sprintf(logStr, "%.2f%% - %s words in vocabulary occur less than "
            "%lu(support) times.", pct * 100, digit,
            (unsigned long) pParam->support);
    log_msg(logStr, LOG_INFO, pParam);
    
    return freWordNum;
}

struct Elem *find_elem(char *key, struct Elem **table, tableindex_t tablesize,
                       tableindex_t seed)
{
    tableindex_t hash;
    struct Elem *ptr, *pPrev;
    
    pPrev = 0;
    hash = str2hash(key, tablesize, seed);
    
    for (ptr = table[hash]; ptr; ptr = ptr->pNext)
    {
        if (!strcmp(key, ptr->pKey))
        {
            break;
        }
        pPrev = ptr;
    }
    /* After success finding, Move-To-Front */
    if (ptr && pPrev)
    {
        pPrev->pNext = ptr->pNext;
        ptr->pNext = table[hash];
        table[hash] = ptr;
    }
    
    return ptr;
}

/* This is a redundant function, which works similarly as function
 create_cluster_candidate_sketch(), but with consideration of '--wordfilter'
 option. Since this function has a coding style with overlaping IFs, it could
 be read while comparing function create_cluster_candidate_sketch() to see the
 differences. */

/* This redundant function can be intergated into its original function.
 However, for the sake of performance and readability of the original function,
 this function is separated as an alone function. */

/* In program, if '--wfilter' option is not used, this function will not be
 called. */

/* When making changes to this funciton, don't forget to also change its
 original function. */
tableindex_t create_cluster_candidate_sketch_with_wfilter(struct Parameters
                                                          *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash, oversupport;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int len, wordcount, last, i;
    struct Elem *pWord;
    char newWord[MAXWORDLEN];
    
    *newWord = 0;
    
    for (j = 0; j < pParam->clusterSketchSize; j++)
    {
        pParam->pClusterSketch[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            last = 0;
            *key = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    /* last records the location of the last constant. */
                    last = i + 1;
                }
                else if(is_word_filtered(words[i], pParam))
                {
                    strcpy(newWord, word_search_replace(words[i], pParam));
                    pWord = find_elem(newWord, pParam->ppWordTable,
                                      pParam->wordTableSize,
                                      pParam->wordTableSeed);
                    if (words[i][0] != 0 && pWord)
                    {
                        strcat(key, newWord);
                        len = (int) strlen(key);
                        key[len] = CLUSTERSEP;
                        key[len + 1] = 0;
                        last = i + 1;
                    }
                }
            }
            
            if (!last)
            {
                /* !last means there is no frequent word in this line. */
                continue;
            }
            
            hash = str2hash(key, pParam->clusterSketchSize,
                            pParam->clusterSketchSeed);
            pParam->pClusterSketch[hash]++;
        }
        
        fclose(pFile);
    }
    
    oversupport = 0;
    for (j = 0; j < pParam->clusterSketchSize; j++)
    {
        if (pParam->pClusterSketch[j] >= pParam->support)
        {
            oversupport++;
        }
    }
    
    return oversupport;
}


tableindex_t create_cluster_candidate_sketch(struct Parameters *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash, oversupport;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int len, wordcount, last, i;
    struct Elem *pWord;
    
    for (j = 0; j < pParam->clusterSketchSize; j++)
    {
        pParam->pClusterSketch[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            last = 0;
            *key = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    //last records the location of the last constant. */
                    last = i + 1;
                }
            }
            
            if (!last)
            {
                /* !last means there is no frequent word in this line. */
                continue;
            }
            
            hash = str2hash(key, pParam->clusterSketchSize,
                            pParam->clusterSketchSeed);
            pParam->pClusterSketch[hash]++;
        }
        
        fclose(pFile);
    }
    
    oversupport = 0;
    for (j = 0; j < pParam->clusterSketchSize; j++)
    {
        if (pParam->pClusterSketch[j] >= pParam->support)
        {
            oversupport++;
        }
    }
    
    return oversupport;
}

struct Cluster *create_cluster_instance(struct Elem* pClusterElem,
                                        int constants, int wildcard[],
                                        struct Elem *pStorage[],
                                        struct Parameters *pParam)
{
    struct Cluster *ptr;
    int i = 0;
    
    ptr = (struct Cluster *) malloc(sizeof(struct Cluster));
    
    if (!ptr)
    {
        log_msg(MALLOC_ERR_6009, LOG_ERR, pParam);
        exit(1);
    }
    
    ptr->ppWord = (struct Elem **) malloc((constants + 1) *
                                          sizeof(struct Elem *));
    if (!ptr->ppWord)
    {
        log_msg(MALLOC_ERR_6009, LOG_ERR, pParam);
        exit(1);
    }
    
    //Initializtion..
    ptr->ppWord[0] = 0; //reserved..
    for (i = 1; i <= constants; i++)
    {
        ptr->ppWord[i] = pStorage[i];
        ptr->fullWildcard[i * 2] = wildcard[i];
        ptr->fullWildcard[i * 2 + 1] = wildcard[i];
    }
    
    ptr->fullWildcard[0] = wildcard[0];
    ptr->fullWildcard[1] = wildcard[0];
    
    ptr->constants = constants;
    ptr->count = 0;
    ptr->bIsJoined = 0;
    ptr->pLastNode = 0;
    
    //Build bidirectional link.
    pClusterElem->pCluster = ptr;
    ptr->pElem = pClusterElem;
    
    //Find a more organized place to store the new pointers of struct Cluster.
    if (pParam->pClusterFamily[constants])
    {
        ptr->pNext = pParam->pClusterFamily[constants];
        pParam->pClusterFamily[constants] = ptr;
    }
    else
    {
        ptr->pNext = 0;
        pParam->pClusterFamily[constants] = ptr;
    }
    
    if (constants > pParam->biggestConstants)
    {
        /* biggestConstants saves time for later iteration. */
        pParam->biggestConstants = constants;
    }
    
    return ptr;
}

/* Adjust the minimum and maximum of the wildcards. */
void adjust_cluster_instance(struct Elem* pClusterElem, int constants,
                             int wildcard[], struct Parameters *pParam)
{
    struct Cluster *ptr;
    int i;
    
    ptr = pClusterElem->pCluster;
    ptr->count++;
    
    for (i = 0; i <= constants; i++)
    {
        if (wildcard[i] < ptr->fullWildcard[i * 2])
        {
            ptr->fullWildcard[i * 2] = wildcard[i];
        }
        else if (wildcard[i] > ptr->fullWildcard[i * 2 + 1])
        {
            ptr->fullWildcard[i * 2 + 1] = wildcard[i];
        }
        
    }
    
}

/* This is a redundant function, which works similarly as function
 create_cluster_candidates(), but with consideration of '--wordfilter'
 option. Since this function has a coding style with overlaping IFs, it could
 be read while comparing function create_cluster_candidates() to see the
 differences. */

/* This redundant function can be intergated into its original function.
 However, for the sake of performance and readability of the original function,
 this function is separated as an alone function. */

/* In program, if '--wfilter' option is not used, this function will not be
 called. */

/* When making changes to this funciton, don't forget to also change its
 original function. */
wordnumber_t create_cluster_candidates_with_wfilter(struct Parameters *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int wildcard[MAXWORDS + 1];
    int len, wordcount, i, constants, variables;
    struct Elem *pWord, *pElem;
    struct Elem *pStorage[MAXWORDS + 1];
    wordnumber_t clusterCount;
    char newWord[MAXWORDLEN];
    
    *newWord = 0;
    
    for (j = 0; j < pParam->clusterTableSize; j++)
    {
        pParam->ppClusterTable[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            *key = 0;
            constants = 0;
            variables = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    
                    constants++;
                    pStorage[constants] = pWord;
                    wildcard[constants] = variables;
                    variables = 0;
                }
                else if(is_word_filtered(words[i], pParam))
                {
                    strcpy(newWord, word_search_replace(words[i], pParam));
                    pWord = find_elem(newWord, pParam->ppWordTable,
                                      pParam->wordTableSize,
                                      pParam->wordTableSeed);
                    if (words[i][0] != 0 && pWord)
                    {
                        strcat(key, newWord);
                        len = (int) strlen(key);
                        key[len] = CLUSTERSEP;
                        key[len + 1] = 0;
                        
                        constants++;
                        pStorage[constants] = pWord;
                        wildcard[constants] = variables;
                        variables = 0;
                    }
                    else
                    {
                        variables++;
                    }
                }
                else
                {
                    variables++;
                }
            }
            
            //Deal with tail.
            //wildcard[constants - 1 + 1] = variables;
            wildcard[0] = variables;
            
            if (!constants)
            {
                continue;
            }
            
            if (pParam->clusterSketchSize)
            {
                hash = str2hash(key, pParam->clusterSketchSize,
                                pParam->clusterSketchSeed);
                if (pParam->pClusterSketch[hash] < pParam->support)
                {
                    continue;
                }
            }
            
            //Put this cluster into clustertable.
            pElem = add_elem(key, pParam->ppClusterTable,
                             pParam->clusterTableSize, pParam->clusterTableSeed,
                             pParam);
            
            if (pElem->count == 1)
            {
                clusterCount++;
                create_cluster_instance(pElem, constants, wildcard, pStorage,
                                        pParam);
            }
            
            adjust_cluster_instance(pElem, constants, wildcard, pParam);
            
        }
        
        fclose(pFile);
    }
    
    return clusterCount;
}

wordnumber_t create_cluster_candidates(struct Parameters *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int wildcard[MAXWORDS + 1];
    int len, wordcount, i, constants, variables;
    struct Elem *pWord, *pElem;
    struct Elem *pStorage[MAXWORDS + 1];
    wordnumber_t clusterCount;
    
    for (j = 0; j < pParam->clusterTableSize; j++)
    {
        pParam->ppClusterTable[j] = 0;
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            *key = 0;
            constants = 0;
            variables = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    
                    constants++;
                    pStorage[constants] = pWord;
                    wildcard[constants] = variables;
                    variables = 0;
                }
                else
                {
                    variables++;
                }
            }
            
            //Deal with tail.
            //wildcard[constants - 1 + 1] = variables;
            wildcard[0] = variables;
            
            if (!constants)
            {
                continue;
            }
            
            if (pParam->clusterSketchSize)
            {
                hash = str2hash(key, pParam->clusterSketchSize,
                                pParam->clusterSketchSeed);
                if (pParam->pClusterSketch[hash] < pParam->support)
                {
                    continue;
                }
            }
            
            //Put this cluster into clustertable.
            pElem = add_elem(key, pParam->ppClusterTable,
                             pParam->clusterTableSize, pParam->clusterTableSeed,
                             pParam);
            
            if (pElem->count == 1)
            {
                clusterCount++;
                create_cluster_instance(pElem, constants, wildcard, pStorage,
                                        pParam);
            }
            
            adjust_cluster_instance(pElem, constants, wildcard, pParam);
            
        }
        
        fclose(pFile);
    }
    
    return clusterCount;
}

wordnumber_t find_outliers(struct Parameters *pParam)
{
    FILE *pOutliers;
    FILE *pFile;
    struct InputFile *pFilePtr;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char key[MAXKEYLEN];
    char words[MAXWORDS][MAXWORDLEN];
    int len, wordcount, i;
    struct Elem *pWord, *pElem;
    wordnumber_t outlierNum;
    
    outlierNum = 0;
    
    if (!(pOutliers = fopen(pParam->pOutlier, "w")))
    {
        sprintf(logStr, "Can't open outliers file %s", pParam->pOutlier);
        log_msg(logStr, LOG_ERR, pParam);
        exit(1);
    }
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            *key = 0;
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                }
            }
            
            if (*key == 0 && wordcount)
            {
                fprintf(pOutliers, "%s\n", line);
                outlierNum++;
                continue;
            }
            
            pElem = find_elem(key, pParam->ppClusterTable,
                              pParam->clusterTableSize,
                              pParam->clusterTableSeed);
            
            if (!pElem || (pElem->count < pParam->support))
            {
                fprintf(pOutliers, "%s\n", line);
                outlierNum++;
            }
        }
    }
    
    return outlierNum;
}


double cal_word_dep(struct Elem *word1, struct Elem *word2,
                    struct Parameters *pParam)
{
    double dependency;
    
    //how many times word1 appears in log files.
    wordnumber_t word1Total;
    
    //how many times word2 appears with word1.
    wordnumber_t word2NumInWord1;
    
    
    word1Total = pParam->wordDepMatrix[word1->number *
                                       pParam->wordDepMatrixBreadth +
                                       word1->number];
    
    word2NumInWord1 = pParam->wordDepMatrix[word1->number *
                                            pParam->wordDepMatrixBreadth +
                                            word2->number];
    
    dependency = (double) word2NumInWord1 / word1Total;
    
    return dependency;
}

/* Redundant function. Parameters are words, instead of the {struct Elem}
 pointer. */
double cal_word_dep_number_version(wordnumber_t word1num, wordnumber_t word2num,
                                   struct Parameters *pParam)
{
    double dependency;
    
    //how many times word1 appears in log files.
    wordnumber_t word1Total;
    
    //how many times word2 appears with word1.
    wordnumber_t word2NumInWord1;
    
    
    word1Total = pParam->wordDepMatrix[word1num * pParam->wordDepMatrixBreadth +
                                       word1num];
    
    word2NumInWord1 = pParam->wordDepMatrix[word1num *
                                            pParam->wordDepMatrixBreadth +
                                            word2num];
    
    dependency = (double) word2NumInWord1 / word1Total;
    
    return dependency;
}


int is_word_repeated(wordnumber_t *storage, wordnumber_t wordNumber,
                     int serial)
{
    int i;
    
    for (i = 1; i < serial; i++)
    {
        if (storage[i] == wordNumber)
        {
            return 1;
        }
    }
    
    return 0;
}

void update_word_dep_matrix(wordnumber_t *storage, int serial,
                            struct Parameters *pParam)
{
    int i, j;
    //unsigned long long coor;
    
    for (i = 1; i <= serial; i++)
    {
        for (j = 1; j <= serial; j++)
        {
            //coor = storage[i] * pParam->wordDepMatrixBreadth + storage[j];
            pParam->wordDepMatrix[storage[i] * pParam->wordDepMatrixBreadth +
                                  storage[j]]++;
        }
    }
}

/* This is a redundant function, which works similarly as function
 create_cluster_candidates_word_dep(), but with consideration of '--wordfilter'
 option. Since this function has a coding style with overlaping IFs, it could
 be read while comparing function create_cluster_candidates_word_dep() to see
 the differences. */

/* This redundant function can be intergated into its original function.
 However, for the sake of performance and readability of the original function,
 this function is separated as an alone function. */

/* In program, if '--wfilter' option is not used, this function will not be
 called. */

/* When making changes to this funciton, don't forget to also change its
 original function. */
wordnumber_t create_cluster_candidates_word_dep_with_filter(struct Parameters
                                                            *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int wildcard[MAXWORDS + 1];
    int len, wordcount, i, constants, variables;
    struct Elem *pWord, *pElem;
    struct Elem *pStorage[MAXWORDS + 1];
    wordnumber_t clusterCount;
    char newWord[MAXWORDLEN];
    
    //wordDep
    //wordnumber_t wordNumberStorage[MAXWORDS + 1];
    wordnumber_t p, q;
    int distinctConstants;
    
    *newWord = 0;
    for (j = 0; j < pParam->clusterTableSize; j++)
    {
        pParam->ppClusterTable[j] = 0;
    }
    
    for (p = 0; p < pParam->wordDepMatrixBreadth; p++)
    {
        for (q = 0; q < pParam->wordDepMatrixBreadth; q++)
        {
            pParam->wordDepMatrix[p * pParam->wordDepMatrixBreadth + q] = 0;
        }
    }
    
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            *key = 0;
            constants = 0;
            variables = 0;
            
            //wordDep
            distinctConstants = 0;
            
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    
                    constants++;
                    pStorage[constants] = pWord;
                    wildcard[constants] = variables;
                    variables = 0;
                    
                    //wordDep
                    distinctConstants++;
                    //findRepeated..
                    if (is_word_repeated(pParam->wordNumStr, pWord->number,
                                         distinctConstants))
                    {
                        distinctConstants--;
                    }
                    else
                    {
                        pParam->wordNumStr[distinctConstants] = pWord->number;
                    }
                    
                }
                else if (is_word_filtered(words[i], pParam))
                {
                    strcpy(newWord, word_search_replace(words[i], pParam));
                    pWord = find_elem(newWord, pParam->ppWordTable,
                                      pParam->wordTableSize,
                                      pParam->wordTableSeed);
                    if (words[i][0] != 0 && pWord)
                    {
                        strcat(key, newWord);
                        len = (int) strlen(key);
                        key[len] = CLUSTERSEP;
                        key[len + 1] = 0;
                        
                        constants++;
                        pStorage[constants] = pWord;
                        wildcard[constants] = variables;
                        variables = 0;
                        
                        //wordDep
                        distinctConstants++;
                        //findRepeated..
                        if (is_word_repeated(pParam->wordNumStr,
                                             pWord->number,
                                             distinctConstants))
                        {
                            distinctConstants--;
                        }
                        else
                        {
                            pParam->wordNumStr[distinctConstants] =
                            pWord->number;
                        }
                    }
                    else
                    {
                        variables++;
                    }
                }
                else
                {
                    variables++;
                }
            }
            
            //Deal with tail.
            //wildcard[constants - 1 + 1] = variables;
            wildcard[0] = variables;
            
            if (!constants)
            {
                continue;
            }
            
            //wordDep
            //update wordDep matrix
            update_word_dep_matrix(pParam->wordNumStr, distinctConstants,
                                   pParam);
            
            if (pParam->clusterSketchSize)
            {
                hash = str2hash(key, pParam->clusterSketchSize,
                                pParam->clusterSketchSeed);
                if (pParam->pClusterSketch[hash] < pParam->support)
                {
                    continue;
                }
            }
            
            //Put this cluster into clustertable.
            pElem = add_elem(key, pParam->ppClusterTable,
                             pParam->clusterTableSize, pParam->clusterTableSeed,
                             pParam);
            
            if (pElem->count == 1)
            {
                clusterCount++;
                create_cluster_instance(pElem, constants, wildcard, pStorage,
                                        pParam);
            }
            
            adjust_cluster_instance(pElem, constants, wildcard, pParam);
            
        }
        
        fclose(pFile);
    }
    
    return clusterCount;
}

wordnumber_t create_cluster_candidates_word_dep(struct Parameters *pParam)
{
    FILE *pFile;
    struct InputFile *pFilePtr;
    tableindex_t j, hash;
    char logStr[MAXLOGMSGLEN];
    char line[MAXLINELEN];
    char words[MAXWORDS][MAXWORDLEN];
    char key[MAXKEYLEN];
    int wildcard[MAXWORDS + 1];
    int len, wordcount, i, constants, variables;
    struct Elem *pWord, *pElem;
    struct Elem *pStorage[MAXWORDS + 1];
    wordnumber_t clusterCount;
    
    //wordDep
    //wordnumber_t wordNumberStorage[MAXWORDS + 1];
    wordnumber_t p, q;
    int distinctConstants;
    
    
    for (j = 0; j < pParam->clusterTableSize; j++)
    {
        pParam->ppClusterTable[j] = 0;
    }
    
    for (p = 0; p < pParam->wordDepMatrixBreadth; p++)
    {
        for (q = 0; q < pParam->wordDepMatrixBreadth; q++)
        {
            pParam->wordDepMatrix[p * pParam->wordDepMatrixBreadth + q] = 0;
        }
    }
    
    
    for (pFilePtr = pParam->pInputFiles; pFilePtr; pFilePtr = pFilePtr->pNext)
    {
        if (!(pFile = fopen(pFilePtr->pName, "r")))
        {
            sprintf(logStr, "Can't open inputfile %s", pFilePtr->pName);
            log_msg(logStr, LOG_ERR, pParam);
            continue;
        }
        
        while (fgets(line, MAXLINELEN, pFile))
        {
            len = (int) strlen(line);
            if (line[len - 1] == '\n')
            {
                line[len - 1] = 0;
            }
            
            wordcount = find_words(line, words, pParam);
            
            *key = 0;
            constants = 0;
            variables = 0;
            
            //wordDep
            distinctConstants = 0;
            
            
            for (i = 0; i < wordcount; i++)
            {
                pWord = find_elem(words[i], pParam->ppWordTable,
                                  pParam->wordTableSize, pParam->wordTableSeed);
                if (words[i][0] != 0 && pWord)
                {
                    strcat(key, words[i]);
                    len = (int) strlen(key);
                    key[len] = CLUSTERSEP;
                    key[len + 1] = 0;
                    
                    constants++;
                    pStorage[constants] = pWord;
                    wildcard[constants] = variables;
                    variables = 0;
                    
                    //wordDep
                    distinctConstants++;
                    //findRepeated..
                    if (is_word_repeated(pParam->wordNumStr, pWord->number,
                                         distinctConstants))
                    {
                        distinctConstants--;
                    }
                    else
                    {
                        pParam->wordNumStr[distinctConstants] = pWord->number;
                    }
                }
                else
                {
                    variables++;
                }
            }
            
            //Deal with tail.
            //wildcard[constants - 1 + 1] = variables;
            wildcard[0] = variables;
            
            if (!constants)
            {
                continue;
            }
            
            //wordDep
            //update wordDep matrix
            update_word_dep_matrix(pParam->wordNumStr, distinctConstants,
                                   pParam);
            
            if (pParam->clusterSketchSize)
            {
                hash = str2hash(key, pParam->clusterSketchSize,
                                pParam->clusterSketchSeed);
                if (pParam->pClusterSketch[hash] < pParam->support)
                {
                    continue;
                }
            }
            
            //Put this cluster into clustertable.
            pElem = add_elem(key, pParam->ppClusterTable,
                             pParam->clusterTableSize, pParam->clusterTableSeed,
                             pParam);
            
            if (pElem->count == 1)
            {
                clusterCount++;
                create_cluster_instance(pElem, constants, wildcard, pStorage,
                                        pParam);
            }
            
            adjust_cluster_instance(pElem, constants, wildcard, pParam);
            
        }
        
        fclose(pFile);
    }
    
    return clusterCount;
}

void print_cluster_to_string(struct Cluster *pCluster,
                             struct Parameters *pParam)
{
    int i;
    //To avoid warning(returing local varialbe in stack), changed local variable
    //to outside variable(pParam->clusterDescription).
    //char clusterDescription[MAXLOGMSGLEN];
    char strTmp[MAXLOGMSGLEN];
    
    *pParam->clusterDescription = 0;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        if (pCluster->fullWildcard[i * 2 + 1])
        {
            sprintf(strTmp, "*{%d,%d} ", pCluster->fullWildcard[i * 2],
                    pCluster->fullWildcard[i * 2 + 1]);
            strcat(pParam->clusterDescription, strTmp);
        }
        sprintf(strTmp, "%s ", pCluster->ppWord[i]->pKey);
        strcat(pParam->clusterDescription, strTmp);
    }
    
    if (pCluster->fullWildcard[1])
    {
        sprintf(strTmp, "*{%d,%d}", pCluster->fullWildcard[0],
                pCluster->fullWildcard[1]);
        strcat(pParam->clusterDescription, strTmp);
    }
    //return clusterDescription;
}


void print_cluster(struct Cluster* pCluster)
{
    char digit[MAXDIGITBIT];
    int i;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        if (pCluster->fullWildcard[i * 2 + 1])
        {
            printf("*{%d,%d} ", pCluster->fullWildcard[i * 2],
                   pCluster->fullWildcard[i * 2 + 1]);
        }
        printf("%s ", pCluster->ppWord[i]->pKey);
    }
    
    if (pCluster->fullWildcard[1])
    {
        printf("*{%d,%d}", pCluster->fullWildcard[0],
               pCluster->fullWildcard[1]);
    }
    
    printf("\n");
    
    str_format_int_grouped(digit, pCluster->count);
    printf("Support : %s\n\n", digit);
}

void print_clusters_default_0(struct Parameters *pParam)
{
    int i, j, k;
    struct Cluster *pCluster;
    struct Elem **ppSortedArray;
    
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            pParam->clusterNum);
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6018, LOG_ERR, pParam);
        exit(1);
    }
    
    j = 0;
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            ppSortedArray[j] = pCluster->pElem;
            j++;
            pCluster = pCluster->pNext;
        }
    }
    
    sort_elements(ppSortedArray, pParam->clusterNum, pParam);
    
    for (k = 0; k < pParam->clusterNum; k++)
    {
        print_cluster(ppSortedArray[k]->pCluster);
    }
    
    free((void *) ppSortedArray);
}


void print_clusters_constant_1(struct Parameters *pParam)
{
    int i;
    struct Cluster *pCluster;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            print_cluster(pCluster);
            pCluster = pCluster->pNext;
        }
    }
}

void print_cluster_with_token(struct ClusterWithToken *pClusterWithToken,
                              struct Parameters *pParam)
{
    char digit[MAXDIGITBIT];
    struct Token *pToken;
    int i;
    
    for (i = 1; i <= pClusterWithToken->constants; i++)
    {
        if (pClusterWithToken->fullWildcard[i * 2 + 1])
        {
            printf("*{%d,%d} ", pClusterWithToken->fullWildcard[i * 2],
                   pClusterWithToken->fullWildcard[i * 2 + 1]);
        }
        
        if (pClusterWithToken->ppToken[i] != 0)
        {
            if (pParam->bDetailedTokenFlag == 0)
            {
                /* This solution will not mark a token, if it is the only word.
                 */
                if (pClusterWithToken->ppToken[i]->pNext != 0)
                {
                    printf("(");
                    pToken = pClusterWithToken->ppToken[i];
                    while (pToken)
                    {
                        printf("%s", pToken->pWord->pKey);
                        if (pToken->pNext)
                        {
                            printf("|");
                        }
                        pToken = pToken->pNext;
                    }
                    printf(") ");
                }
                else
                {
                    printf("%s ", pClusterWithToken->ppToken[i]->pWord->pKey);
                }
            }
            else
            {
                /* This solution marks a token with (), no matter how many words
                 it contains. */
                printf("(");
                pToken = pClusterWithToken->ppToken[i];
                while (pToken)
                {
                    printf("%s", pToken->pWord->pKey);
                    if (pToken->pNext)
                    {
                        printf("|");
                    }
                    pToken = pToken->pNext;
                }
                printf(") ");
            }
            
        }
        else
        {
            printf("%s ", pClusterWithToken->ppWord[i]->pKey);
        }
    }
    
    if (pClusterWithToken->fullWildcard[1])
    {
        printf("*{%d,%d}", pClusterWithToken->fullWildcard[0],
               pClusterWithToken->fullWildcard[1]);
    }
    
    printf("\n");
    
    str_format_int_grouped(digit, pClusterWithToken->count);
    printf("Support : %s\n\n", digit);
}

void print_clusters_if_join_cluster_default_0(struct Parameters *pParam)
{
    int i, j, k, c, u, b;
    struct Cluster *pCluster;
    struct ClusterWithToken *pClusterWithToken;
    struct Elem **ppSortedArray;
    
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            pParam->clusterNum);
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6019, LOG_ERR, pParam);
        exit(1);
    }
    
    j = 0;
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            ppSortedArray[j] = pCluster->pElem;
            j++;
            pCluster = pCluster->pNext;
        }
    }
    
    sort_elements(ppSortedArray, pParam->clusterNum, pParam);
    
    if (pParam->clusterNum - pParam->joinedClusterInputNum)
    {
        printf(">>>>>>The %lu clusters that are not joined:\n\n",
               pParam->clusterNum - pParam->joinedClusterInputNum);
    }
    
    for (k = 0; k < pParam->clusterNum; k++)
    {
        /* For clusters in pClusterFamily[], only print those who were not
         marked as bIsJoined. Those who were joined, will be printed later, by
         accessing pClusterWithTokenFamily[]. */
        if (ppSortedArray[k]->pCluster->bIsJoined == 0)
        {
            print_cluster(ppSortedArray[k]->pCluster);
        }
        
    }
    
    free((void *) ppSortedArray);
    
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            pParam->joinedClusterOutputNum);
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6019, LOG_ERR, pParam);
        exit(1);
    }
    
    u = 0;
    for (c = 1; c <= pParam->biggestConstants; c++)
    {
        pClusterWithToken = pParam->pClusterWithTokenFamily[c];
        while (pClusterWithToken)
        {
            ppSortedArray[u] = pClusterWithToken->pElem;
            u++;
            pClusterWithToken = pClusterWithToken->pNext;
        }
    }
    
    sort_elements(ppSortedArray, pParam->joinedClusterOutputNum, pParam);
    
    if (pParam->joinedClusterOutputNum)
    {
        printf(">>>>>>The %lu joined clusters:\n\n",
               pParam->joinedClusterOutputNum);
    }
    
    for (b = 0; b < pParam->joinedClusterOutputNum; b++)
    {
        print_cluster_with_token((struct ClusterWithToken *)
                                 ppSortedArray[b]->pCluster, pParam);
    }
    
    free((void *) ppSortedArray);
}

void __print_clusters_if_join_cluster_default_0(struct Parameters *pParam)
{
    int i, j, k;
    struct Cluster *pCluster;
    struct ClusterWithToken *pClusterWithToken, *ptr;
    struct Elem **ppSortedArray;
    wordnumber_t toBeSortedNum;
    
    toBeSortedNum = (pParam->clusterNum - pParam->joinedClusterInputNum) +
    pParam->joinedClusterOutputNum;
    ppSortedArray = (struct Elem **) malloc(sizeof(struct Elem *) *
                                            toBeSortedNum);
    
    if (!ppSortedArray)
    {
        log_msg(MALLOC_ERR_6020, LOG_ERR, pParam);
        exit(1);
    }
    
    j = 0;
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            if (pCluster->bIsJoined == 0)
            {
                ppSortedArray[j] = pCluster->pElem;
                j++;
            }
            pCluster = pCluster->pNext;
        }
        
        pClusterWithToken = pParam->pClusterWithTokenFamily[i];
        while (pClusterWithToken)
        {
            ppSortedArray[j] = pClusterWithToken->pElem;
            j++;
            pClusterWithToken = pClusterWithToken->pNext;
        }
    }
    
    sort_elements(ppSortedArray, toBeSortedNum, pParam);
    
    for (k = 0; k < toBeSortedNum; k++)
    {
        /* For clusters in pClusterFamily[], only print those who were not
         marked as bIsJoined. Those who were joined, will be printed later, by
         accessing pClusterWithTokenFamily[]. */
        if (ppSortedArray[k]->pCluster->bIsJoined == 1)
        {
            ptr = (struct ClusterWithToken *) ppSortedArray[k]->pCluster;
            print_cluster_with_token(ptr, pParam);
        }
        else
        {
            print_cluster(ppSortedArray[k]->pCluster);
        }
    }
    
    free((void *) ppSortedArray);
}


void print_clusters_if_join_cluster_constant_1(struct Parameters *pParam)
{
    int i, j;
    struct Cluster *pCluster;
    struct ClusterWithToken *pClusterWithToken;
    
    if (pParam->clusterNum - pParam->joinedClusterInputNum)
    {
        printf(">>>>>>The %lu clusters that are not joined:\n\n",
               pParam->clusterNum - pParam->joinedClusterInputNum);
    }
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        /* For clusters in pClusterFamily[], only print those who were not
         marked as bIsJoined. Those who were joined, will be printed later, by
         accessing pClusterWithTokenFamily[]. */
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            if (pCluster->bIsJoined == 0)
            {
                print_cluster(pCluster);
                
            }
            pCluster = pCluster->pNext;
        }
    }
    
    if (pParam->joinedClusterOutputNum)
    {
        printf(">>>>>>The %lu joined clusters:\n\n",
               pParam->joinedClusterOutputNum);
    }
    
    for (j = 1;  j <= pParam->biggestConstants; j++)
    {
        pClusterWithToken = pParam->pClusterWithTokenFamily[j];
        while (pClusterWithToken)
        {
            print_cluster_with_token(pClusterWithToken, pParam);
            pClusterWithToken = pClusterWithToken->pNext;
        }
    }
}

void __print_clusters_if_join_cluster_constant_1(struct Parameters *pParam)
{
    int i;
    struct Cluster *pCluster;
    struct ClusterWithToken *pClusterWithToken;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        /* For clusters in pClusterFamily[], only print those who were not
         marked as bIsJoined. Those who were joined, will be printed later, by
         accessing pClusterWithTokenFamily[]. */
        pCluster = pParam->pClusterFamily[i];
        while (pCluster)
        {
            if (pCluster->bIsJoined == 0)
            {
                print_cluster(pCluster);
                
            }
            pCluster = pCluster->pNext;
        }
        
        pClusterWithToken = pParam->pClusterWithTokenFamily[i];
        while (pClusterWithToken)
        {
            print_cluster_with_token(pClusterWithToken, pParam);
            pClusterWithToken = pClusterWithToken->pNext;
        }
        
    }
}


wordnumber_t find_clusters_from_candidates(struct Parameters *pParam)
{
    int clusterNum;
    struct Cluster *ptr, *pNext, *pPrev;
    int i;
    
    clusterNum = 0;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        ptr = pParam->pClusterFamily[i];
        pPrev = 0;
        while (ptr)
        {
            if (ptr->count >= pParam->support)
            {
                clusterNum++;
                //print_cluster(ptr);
                pPrev = ptr;
                ptr = ptr->pNext;
            }
            else
            {
                /* Delete this cluster candidate. Only from pClusterFamily[],
                 but not from cluster hash table. */
                if (pPrev)
                {
                    pPrev->pNext = ptr->pNext;
                }
                else
                {
                    pParam->pClusterFamily[i] = ptr->pNext;
                }
                pNext = ptr->pNext;
                free((void *) ptr->ppWord);
                free((void *) ptr);
                ptr = pNext;
            }
        }
    }
    
    return clusterNum;
}

/* If the default token, which is "token", is already among frequent words,
 generate random string to replace "token". */
void set_token(struct Parameters *pParam)
{
    while (find_elem(pParam->token, pParam->ppWordTable, pParam->wordTableSize,
                     pParam->wordTableSeed))
    {
        gen_random_string(pParam->token, TOKENLEN - 1);
    }
}

double cal_word_weight_function_1(struct Cluster *pCluster, int serial,
                                  struct Parameters *pParam)
{
    double sum;
    int i;
    double result;
    
    sum = 0;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        sum += cal_word_dep(pCluster->ppWord[i], pCluster->ppWord[serial],
                            pParam);
    }
    
    result = sum / pCluster->constants;
    
    return result;
}

void get_unique_frequent_words_out_of_cluster(struct Cluster *pCluster,
                                              struct Parameters *pParam)
{
    int i;
    int distinctConstants;
    
    distinctConstants = 0;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        distinctConstants++;
        if (is_word_repeated(pParam->wordNumStr,
                             pCluster->ppWord[i]->number,
                             distinctConstants))
        {
            distinctConstants--;
        }
        else
        {
            pParam->wordNumStr[i] = pCluster->ppWord[i]->number;
        }
    }
    pParam->wordNumStr[0] = distinctConstants;
    
    pParam->pCurrentCluster = pCluster;
}

double cal_word_weight_function_2(struct Cluster *pCluster, int serial,
                                  struct Parameters *pParam)
{
    double sum;
    int i;
    double result;
    
    sum = 0;
    
    if (pCluster != pParam->pCurrentCluster)
    {
        //get all unique frequent words
        get_unique_frequent_words_out_of_cluster(pCluster, pParam);
    }
    
    if (pParam->wordNumStr[0] < 1)
    {
        i = 0; //debugpoint;
    }
    
    if (pParam->wordNumStr[0] == 1)
    {
        i = 0; //debug breakpoint
        return 1;
    }
    
    for (i = 1; i <= pParam->wordNumStr[0]; i++)
    {
        sum += cal_word_dep_number_version(pParam->wordNumStr[i],
                                           pCluster->ppWord[serial]->number,
                                           pParam);
    }
    
    result = (double) (sum - 1) / (pParam->wordNumStr[0] - 1);
    
    return result;
}


double cal_word_weight(struct Cluster *pCluster, int serial,
                       struct Parameters *pParam)
{
    switch (pParam->wordWeightFunction)
    {
        case 1:
            return cal_word_weight_function_1(pCluster, serial, pParam);
            break;
        case 2:
            return cal_word_weight_function_2(pCluster, serial, pParam);
            break;
        default:
            log_msg("failed calculate word weight. Funciton: cal_word_weight()",
                    LOG_ERR, pParam);
            exit(1);
            break;
    }
    
    return 0;
}

struct ClusterWithToken *create_cluster_with_token_instance
(struct Cluster *pCluster, struct Elem *pElem, struct Parameters *pParam)
{
    struct ClusterWithToken *ptr;
    int i;
    
    ptr = (struct ClusterWithToken *) malloc(sizeof(struct ClusterWithToken));
    if (!ptr)
    {
        log_msg(MALLOC_ERR_6010, LOG_ERR, pParam);
        exit(1);
    }
    
    ptr->ppWord = (struct Elem **) malloc((pCluster->constants + 1) *
                                          sizeof(struct Elem *));
    if (!ptr->ppWord)
    {
        log_msg(MALLOC_ERR_6010, LOG_ERR, pParam);
        exit(1);
    }
    
    ptr->ppToken = (struct Token **) malloc((pCluster->constants + 1) *
                                            sizeof(struct Token *));
    if (!ptr->ppToken)
    {
        log_msg(MALLOC_ERR_6010, LOG_ERR, pParam);
        exit(1);
    }
    
    //Initialization..
    ptr->ppWord[0] = 0; //reserved..
    ptr->ppToken[0] = 0; //reserved..
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        ptr->ppWord[i] = pCluster->ppWord[i];
        ptr->fullWildcard[i * 2] = pCluster->fullWildcard[i * 2];
        ptr->fullWildcard[i * 2 + 1] = pCluster->fullWildcard[i * 2 + 1];
        ptr->ppToken[i] = 0;
    }
    
    ptr->fullWildcard[0] = pCluster->fullWildcard[0];
    ptr->fullWildcard[1] = pCluster->fullWildcard[1];
    
    ptr->constants = pCluster->constants;
    ptr->count = 0;
    ptr->bIsJoined = pCluster->bIsJoined;
    ptr->pLastNode = pCluster->pLastNode;
    
    //Build bidirectional link.
    //Type converted to (struct Cluster *) here. Should not cause a probelm.
    pElem->pCluster = (struct Cluster *) ptr;
    ptr->pElem = pElem;
    
    //Find a organized palce to store the ptrs.
    if (pParam->pClusterWithTokenFamily[ptr->constants])
    {
        ptr->pNext = pParam->pClusterWithTokenFamily[ptr->constants];
        pParam->pClusterWithTokenFamily[ptr->constants] = ptr;
    }
    else
    {
        ptr->pNext = 0;
        pParam->pClusterWithTokenFamily[ptr->constants] = ptr;
    }
    
    return ptr;
}

int check_if_token_key_is_exist(struct ClusterWithToken *ptr, int serial,
                                struct Elem *pElem)
{
    struct Token *pToken;
    
    pToken = ptr->ppToken[serial];
    while (pToken)
    {
        if (pToken->pWord == pElem)
        {
            return 1;
        }
        pToken = pToken->pNext;
    }
    
    return 0;
}

void adjust_cluster_with_token_instance(struct Cluster *pCluster,
                                        struct Elem *pElem,
                                        struct Parameters *pParam)
{
    struct ClusterWithToken *ptr;
    struct Token *ptrToken;
    int i;
    
    ptr = (struct ClusterWithToken *) pElem->pCluster;
    
    ptr->count += pCluster->count;
    
    for (i = 0; i <= ptr->constants; i++)
    {
        if (pCluster->fullWildcard[i * 2] < ptr->fullWildcard[i * 2])
        {
            ptr->fullWildcard[i * 2] = pCluster->fullWildcard[i * 2];
        }
        
        if (pCluster->fullWildcard[i * 2 + 1] > ptr->fullWildcard[i * 2 + 1])
        {
            ptr->fullWildcard[i * 2 + 1] = pCluster->fullWildcard[i * 2 + 1];
        }
    }
    
    for (i = 1; i <= ptr->constants; i++)
    {
        if (pParam->tokenMarker[i] == 1)
        {
            //debug here..20160224
            
            if (check_if_token_key_is_exist(ptr, i, pCluster->ppWord[i]))
            {
                //Repeated word will not be added as a new token.
                continue;
            }
            
            ptrToken = (struct Token *) malloc(sizeof(struct Token));
            if (!ptrToken)
            {
                log_msg(MALLOC_ERR_6011, LOG_ERR, pParam);
                exit(1);
            }
            ptrToken->pWord = pCluster->ppWord[i];
            
            if (ptr->ppToken[i])
            {
                ptrToken->pNext = ptr->ppToken[i];
                ptr->ppToken[i] = ptrToken;
            }
            else
            {
                ptrToken->pNext = 0;
                ptr->ppToken[i] = ptrToken;
            }
        }
    }
    
}

void join_cluster_with_token(struct Cluster *pCluster,
                             struct Parameters *pParam)
{
    char key[MAXKEYLEN];
    int i, len;
    struct Elem *pElem;
    
    pParam->joinedClusterInputNum++;
    
    *key = 0;
    
    for (i = 1; i <= pCluster->constants; i++)
    {
        if (pParam->tokenMarker[i] == 0)
        {
            strcat(key, pCluster->ppWord[i]->pKey);
        }
        else
        {
            strcat(key, pParam->token);
        }
        len = (int) strlen(key);
        key[len] = CLUSTERSEP;
        key[len + 1] = 0;
    }
    
    pElem = add_elem(key, pParam->ppClusterTable, pParam->clusterTableSize,
                     pParam->clusterTableSeed, pParam);
    
    if (pElem->count == 1)
    {
        pParam->joinedClusterOutputNum++;
        //create cluster_with_token instance
        create_cluster_with_token_instance(pCluster, pElem, pParam);
    }
    
    
    //adjust this instance
    adjust_cluster_with_token_instance(pCluster, pElem, pParam);
}

void check_cluster_for_join_cluster(struct Cluster* pCluster,
                                    struct Parameters *pParam)
{
    int i;
    
    for (i = 0; i <= pCluster->constants; i++)
    {
        pParam->tokenMarker[i] = 0;
    }
    
    for (i = 1; i <= pCluster->constants ; i++)
    {
        if (cal_word_weight(pCluster, i, pParam) < pParam->wordWeightThreshold)
        {
            /* tokenMarker[0] means this cluster has token. We should keep on
             to see which constant(s) is/are token(s). */
            pParam->tokenMarker[0] = 1;
            
            pParam->tokenMarker[i] = 1;
        }
    }
    
    if (pParam->tokenMarker[0] == 1)
    {
        pCluster->bIsJoined = 1;
        join_cluster_with_token(pCluster, pParam);
    }
}

void join_cluster(struct Parameters *pParam)
{
    int i;
    struct Cluster *pCluster;
    struct ClusterWithToken *pClusterWithToken;
    
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pCluster = pParam->pClusterFamily[i];
        
        while (pCluster)
        {
            check_cluster_for_join_cluster(pCluster, pParam);
            pCluster = pCluster->pNext;
        }
    }
    
    //additional work. Equal the counters in Elem and ClusterWithToken
    for (i = 1; i <= pParam->biggestConstants; i++)
    {
        pClusterWithToken = pParam->pClusterWithTokenFamily[i];
        
        while (pClusterWithToken)
        {
            pClusterWithToken->pElem->count = pClusterWithToken->count;
            pClusterWithToken = pClusterWithToken->pNext;
        }
    }
}

void generate_seeds(struct Parameters *pParam)
{
    pParam->wordTableSeed = rand();
    pParam->wordSketchSeed = rand();
    pParam->clusterSketchSeed =rand();
    pParam->clusterTableSeed = rand();
    pParam->prefixSketchSeed =rand();
}

wordnumber_t step_1_create_vocabulary(struct Parameters *pParam)
{
    wordnumber_t totalWordNum;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    log_msg("Creating vocabulary...", LOG_NOTICE, pParam);
    pParam->ppWordTable = (struct Elem **) malloc(sizeof(struct Elem *) *
                                                  pParam->wordTableSize);
    if (!pParam->ppWordTable)
    {
        log_msg(MALLOC_ERR_6015, LOG_ERR, pParam);
        exit(1);
    }
    
    if (!pParam->pWordFilter)
    {
        totalWordNum = create_vocabulary(pParam);
    }
    else
    {
        totalWordNum = create_vocabulary_with_wfilter(pParam);
    }
    
    str_format_int_grouped(digit, totalWordNum);
    sprintf(logStr, "%s words were inserted into the vocabulary.", digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    return totalWordNum;
}

void step_1_create_word_sketch(struct Parameters *pParam)
{
    tableindex_t effect;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    log_msg("Creating the word sketch...", LOG_NOTICE, pParam);
    pParam->pWordSketch = (unsigned long *) malloc(sizeof(unsigned long) *
                                                   pParam->wordSketchSize);
    if (!pParam->pWordSketch)
    {
        log_msg(MALLOC_ERR_6014, LOG_ERR, pParam);
        exit(1);
    }
    
    if (!pParam->pWordFilter)
    {
        effect = create_word_sketch(pParam);
    }
    else
    {
        effect = create_word_sketch_with_wfilter(pParam);
    }
    
    
    str_format_int_grouped(digit, effect);
    sprintf(logStr, "%s slots in the word sketch >= support threshhold", digit);
    log_msg(logStr, LOG_INFO, pParam);
}

void free_and_clean_step_0(struct Parameters *pParam)
{
    free_inputfiles(pParam);
    free_syslog_facility(pParam);
    free_delim(pParam);
    free_filter(pParam);
    free_template(pParam);
    free_outlier(pParam);
    free_wfilter(pParam);
    free_wsearch(pParam);
    free_wreplace(pParam);
    if (pParam->bSyslogFlag == 1)
    {
        closelog();
    }
}

void free_and_clean_step_1(struct Parameters *pParam)
{
    free_word_table(pParam);
    free_word_sketch(pParam);
}

void free_and_clean_step_2(struct Parameters *pParam)
{
    free_cluster_table(pParam);
    free_cluster_sketch(pParam);
    free_cluster_instances(pParam);
    if (pParam->wordWeightThreshold)
    {
        free((void *) pParam->wordDepMatrix);
    }
}

void free_and_clean_step_3(struct Parameters *pParam)
{
    if (pParam->wordWeightThreshold)
    {
        free_cluster_with_token_instances(pParam);
    }
}

void step_2_create_cluster_candidate_sketch(struct Parameters *pParam)
{
    tableindex_t effect;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    log_msg("Creating the cluster sketch...", LOG_NOTICE, pParam);
    pParam->pClusterSketch = (unsigned long *)
    malloc(sizeof(unsigned long) * pParam->clusterSketchSize);
    if (!pParam->pClusterSketch)
    {
        log_msg(MALLOC_ERR_6016, LOG_ERR, pParam);
        exit(1);
    }
    
    if (!pParam->pWordFilter)
    {
        effect = create_cluster_candidate_sketch(pParam);
    }
    else
    {
        effect = create_cluster_candidate_sketch_with_wfilter(pParam);
    }
    
    str_format_int_grouped(digit, effect);
    sprintf(logStr, "%s slots in the cluster sketch >= support threshhold.",
            digit);
    log_msg(logStr, LOG_INFO, pParam);
}

void step_2_find_cluster_candidates(struct Parameters *pParam)
{
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    int i;
    
    log_msg("Finding cluster candidates...", LOG_NOTICE, pParam);
    if (!pParam->clusterTableSize)
    {
        pParam->clusterTableSize = 100 * pParam->freWordNum;
    }
    pParam->ppClusterTable = (struct Elem **) malloc(sizeof(struct Elem *) *
                                                     pParam->clusterTableSize);
    if (!pParam->ppClusterTable)
    {
        log_msg(MALLOC_ERR_6017, LOG_ERR, pParam);
        exit(1);
    }
    
    if (pParam->wordWeightThreshold)
    {
        pParam->wordDepMatrixBreadth = pParam->freWordNum + 1;
        
        pParam->wordDepMatrix = (unsigned long *)
        malloc(sizeof(unsigned long) * pParam->wordDepMatrixBreadth *
               pParam->wordDepMatrixBreadth);
        if (!pParam->wordDepMatrix)
        {
            log_msg(MALLOC_ERR_6017, LOG_ERR, pParam);
            exit(1);
        }
        
        for (i = 0; i < pParam->wordDepMatrixBreadth *
             pParam->wordDepMatrixBreadth; i++)
        {
            pParam->wordDepMatrix[i] = 0;
        }
        
        if (!pParam->pWordFilter)
        {
            pParam->clusterCandiNum =
            create_cluster_candidates_word_dep(pParam);
        }
        else
        {
            pParam->clusterCandiNum =
            create_cluster_candidates_word_dep_with_filter(pParam);
        }
    }
    else
    {
        if (!pParam->pWordFilter)
        {
            pParam->clusterCandiNum = create_cluster_candidates(pParam);
        }
        else
        {
            pParam->clusterCandiNum =
            create_cluster_candidates_with_wfilter(pParam);
        }
        
    }
    
    
    str_format_int_grouped(digit, pParam->clusterCandiNum);
    sprintf(logStr, "%s cluster candidates were found.", digit);
    log_msg(logStr, LOG_INFO, pParam);
}

void step_2_aggregate_support(struct Parameters *pParam)
{
    struct TrieNode *pRoot;
    
    log_msg("Aggregate cluster candidates...", LOG_NOTICE, pParam);
    pParam->prefixSketchSize = pParam->freWordNum * 3;
    pParam->wildcardHash = pParam->freWordNum * 3;
    
    pRoot = build_prefix_trie(pParam);
    
    aggregate_candidates(pParam);
    
    //debug purpose...
    //log_msg("Re-finding clusters...", LOG_INFO, &param);
    //clusterNum = find_clusters_from_candidates(&param);
    //str_format_int_grouped(digit, clusterNum);
    //sprintf(logStr, "%s cluster were found.", digit);
    //log_msg(logStr, LOG_INFO, &param);
    
    //2016-04-12 commented out free_trie_nodes(pRoot, pParam);
    //This function faces "segmentation 11" error when handling 
    //large trie nodes. 
    //(Or this is because the characteristic of specific event log
    //files that generate some weird cluster candidates, therefore
    //generating some weird trie nodes that are hard to free.)
    //Commenting out this function is not a problem.
    //System will take this issue and helps in freeing memory, 
    //when the process is done running.
    
    //free_trie_nodes(pRoot, pParam);
}

void print_clusters_default0(struct Parameters *pParam)
{
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    if (pParam->wordWeightThreshold)
    {
        //print_clusters_if_join_cluster_default_0(pParam);
        __print_clusters_if_join_cluster_default_0(pParam);
        
        str_format_int_grouped(digit, pParam->clusterNum -
                               pParam->joinedClusterInputNum +
                               pParam->joinedClusterOutputNum);
    }
    else
    {
        print_clusters_default_0(pParam);
        
        str_format_int_grouped(digit, pParam->clusterNum);
    }
    
    sprintf(logStr, "Total number of clusters: %s", digit);
    log_msg(logStr, LOG_INFO, pParam);
}

void print_clusters_constant1(struct Parameters *pParam)
{
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    if (pParam->wordWeightThreshold)
    {
        //print_clusters_if_join_cluster_constant_1(pParam);
        __print_clusters_if_join_cluster_constant_1(pParam);
        
        str_format_int_grouped(digit, pParam->clusterNum -
                               pParam->joinedClusterInputNum +
                               pParam->joinedClusterOutputNum);
    }
    else
    {
        print_clusters_constant_1(pParam);
        
        str_format_int_grouped(digit, pParam->clusterNum);
    }
    
    sprintf(logStr, "Total number of clusters: %s", digit);
    log_msg(logStr, LOG_INFO, pParam);
    
}

void step_3_print_clusters(struct Parameters *pParam)
{
    printf("\n");
    
    switch (pParam->outputMode)
    {
        case 0:
            //Default printing configuration. Clusters are sorted by support.
            print_clusters_default0(pParam);
            break;
        case 1:
            print_clusters_constant1(pParam);
            break;
        default:
            break;
    }
    
    printf("\n");
}

void step_3_join_clusters(struct Parameters *pParam)
{
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    
    log_msg("Joining clusters...", LOG_NOTICE, pParam);
    
    set_token(pParam);
    
    join_cluster(pParam);
    
    str_format_int_grouped(digit, pParam->joinedClusterInputNum);
    sprintf(logStr, "%s clusters contain frequent words under word weight"
            "threshold.", digit);
    log_msg(logStr, LOG_INFO, pParam);
    
    str_format_int_grouped(digit, pParam->joinedClusterOutputNum);
    sprintf(logStr, "Those clusters were joined into %s clusters.", digit);
    log_msg(logStr, LOG_INFO, pParam);
}

int cal_total_pass_over_data_set_times(struct Parameters *pParam)
{
    int times;
    
    /* Build vocabulary, find cluster candidates. */
    times = 2;
    
    if (pParam->wordSketchSize) { times++; }
    if (pParam->clusterSketchSize) { times++; }
    if (pParam->pOutlier) { times++; }
    
    return times;
}

int parse_options(int argc, char **argv, struct Parameters *pParam)
{
    extern char *optarg;
    extern int optind;
    int c;
    char logStr[MAXLOGMSGLEN];
    
    static struct option long_options[] =
    {
        {"aggrsup",     no_argument,       0,   'a'},
        {"byteoffset",  required_argument, 0,   'b'},
        {"csize",       required_argument, 0,   'c'},
        {"debug",       optional_argument, 0,  1007},
        {"detailtoken", no_argument,       0,  1012},
        {"help",        no_argument,       0,   'h'},
        {"initseed",    required_argument, 0,   'i'},
        {"lfilter",     required_argument, 0,   'f'},
        {"input",       required_argument, 0,  1001},
        {"outliers",    required_argument, 0,   'o'},
        {"outputmode",  optional_argument, 0,  1011},
        {"rsupport",    required_argument, 0,  1005},
        {"separator",   required_argument, 0,   'd'},
        {"support",     required_argument, 0,   's'},
        {"syslog",      optional_argument, 0,  1002},
        {"template",    required_argument, 0,   't'},
        {"version",     no_argument,       0,  1006},
        {"weightf",     required_argument, 0,  1004},
        {"wfilter",     required_argument, 0,  1008},
        {"wreplace",    required_argument, 0,  1010},
        {"wsearch",     required_argument, 0,  1009},
        {"wsize",       required_argument, 0,   'v'},
        {"wtablesize",  required_argument, 0,   'w'},
        {"wweight",     required_argument, 0,  1003},
        {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int optionIndex = 0;
    
    while ((c = getopt_long(argc, argv, "s:i:w:d:b:f:t:v:c:ao:h",
                            long_options, &optionIndex)) != -1)
    {
        switch (c)
        {
            case 0:
                break;
            case 'a':
                pParam->bAggrsupFlag = 1;
                break;
            case 's':
                if (optarg[strlen(optarg) - 1] == '%')
                {
                    pParam->pctSupport = atof(optarg);
                }
                else
                {
                    pParam->support = labs(atol(optarg));
                }
                break;
            case 'i':
                pParam->initSeed = abs(atoi(optarg));
                break;
            case 'w':
                pParam->wordTableSize = labs(atol(optarg));
                break;
            case 1001:
                glob_filenames(optarg, pParam);
                break;
            case 1002:
                pParam->bSyslogFlag = 1;
                if (optarg)
                {
                    free_syslog_facility(pParam);
                    pParam->pSyslogFacility = (char *) malloc(strlen(optarg) +
                                                              1);
                    if (!pParam->pSyslogFacility)
                    {
                        log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                        exit(1);
                    }
                    strcpy(pParam->pSyslogFacility, optarg);
                    string_lowercase(pParam->pSyslogFacility);
                }
                break;
            case 'd':
                pParam->pDelim = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pDelim)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pDelim, optarg);
                break;
            case 'b':
                pParam->byteOffset = atoi(optarg);
                break;
            case 'f':
                pParam->pFilter = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pFilter)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pFilter, optarg);
                break;
            case 't':
                build_template_chain(optarg, pParam);
                break;
            case 'v':
                pParam->wordSketchSize = labs(atol(optarg));
                break;
            case 'c':
                pParam->clusterSketchSize = labs(atol(optarg));
                break;
            case 1003:
                pParam->wordWeightThreshold = atof(optarg);
                break;
            case 1004:
                pParam->wordWeightFunction = atoi(optarg);
                break;
            case 1005:
                pParam->pctSupport = atof(optarg);
                break;
            case 'o':
                pParam->pOutlier = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pOutlier)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pOutlier, optarg);
                break;
            case 1006:
                printf("%s", VERSIONINFO);
                printf("\n");
                exit(0);
                break;
            case 'h':
                printf("%s", USAGEINFO);
                printf("%s", HELPINFO);
                printf("\n");
                exit(0);
                break;
            case 1007:
                pParam->debug = 1;
                if (optarg)
                {
                    pParam->debug = atoi(optarg);
                }
                break;
            case 1008:
                pParam->pWordFilter = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pWordFilter)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pWordFilter, optarg);
                break;
            case 1009:
                pParam->pWordSearch = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pWordSearch)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pWordSearch, optarg);
                break;
            case 1010:
                pParam->pWordReplace = (char *) malloc(strlen(optarg) + 1);
                if (!pParam->pWordReplace)
                {
                    log_msg(MALLOC_ERR_6006, LOG_ERR, pParam);
                    exit(1);
                }
                strcpy(pParam->pWordReplace, optarg);
                break;
            case 1011:
                pParam->outputMode = 1;
                if (optarg)
                {
                    pParam->outputMode = atoi(optarg);
                }
                break;
            case 1012:
                pParam->bDetailedTokenFlag = 1;
                break;
            case '?':
                /* getopt_long already printed an error message. */
                break;
            default:
                abort ();
        }
    }
    
    if (optind < argc)
    {
        //printf ("non-option ARGV-elements: ");
        while (optind < argc)
        {
            strcat(logStr, argv[optind++]);
            strcat(logStr, " ");
        }
        sprintf(logStr, "Non-option elements: %s.", logStr);
        log_msg(logStr, LOG_ERR, pParam);
        return 0;
    }
    
    return 1;
}

int main(int argc, char **argv)
{
    struct Parameters param;
    char logStr[MAXLOGMSGLEN];
    char digit[MAXDIGITBIT];
    wordnumber_t totalWordNum, outlierNum;
    
    /* ######## #### ## Step0 Preparation ## #### ######## */
    
    /* Step0.A Initialise parameters */
    if (!init_input_parameters(&param))
    {
        log_msg("Parameter initialization failed.", LOG_ERR, &param);
        exit(1);
    }
    
    /* Step0.B Parse command line options */
    if (!parse_options(argc, argv, &param))
    {
        log_msg("Option parse failed.", LOG_ERR, &param);
        print_usage();
        exit(1);
    }
    
    /* Step0.C Check validation of parameters */
    /* Some parameters were changed by command line. Check their validation. */
    if (!validate_parameters(&param))
    {
        log_msg("Parameters validation failed.", LOG_ERR, &param);
        print_usage();
        exit(1);
    }
    
    /* Step0.D Set syslog utility */
    /* Tag: Optional */
    if (param.bSyslogFlag == 1)
    {
        setlogmask(LOG_UPTO (param.syslogThreshold));
        openlog("logclusterc", LOG_CONS | LOG_PID | LOG_NDELAY,
                param.syslogFacilityNum);
    }
    
    /* Step0.E Generate seeds */
    /* Seeds are used to construct hash tables. */
    srand(param.initSeed);
    generate_seeds(&param);
    
    /* Step0.F Get times of pass over the data set */
    param.dataPassTimes = cal_total_pass_over_data_set_times(&param);
    
    /* Step0.G All is ready. Do the work. */
    log_msg("Starting...", LOG_NOTICE, &param);
    
    /* ######## #### ## Step1 Frequent Words ## #### ######## */
    
    /*Step1.A Create word sketch*/
    /*Tag: Optional, One pass over the data set*/
    /*Very useful in mining process of large log files, e.g. more than 1GB. It
     significantly optimizes memeory consumption.*/
    if (param.wordSketchSize)
    {
        step_1_create_word_sketch(&param);
        param.totalLineNum = param.linecount * param.dataPassTimes;
        str_format_int_grouped(param.totalLineNumDigit, param.totalLineNum);
    }
    
    /*Step1.B Create vocabulary*/
    /*Tag: One pass over the data set*/
    totalWordNum = step_1_create_vocabulary(&param);
    if (!param.totalLineNum)
    {
        param.totalLineNum = param.linecount * param.dataPassTimes;
        str_format_int_grouped(param.totalLineNumDigit, param.totalLineNum);
    }
    
    /*Step1.C Finding frequent words*/
    /*It also santizes word table, moving words under support out of table.*/
    log_msg("Finding frequent words from vocabulary...", LOG_NOTICE, &param);
    
    param.freWordNum = find_frequent_words(&param, totalWordNum);
    
    /*Step1.D Debug_1 mode: print frequent words*/
    /*Tag: Optional*/
    if (param.debug == 1)
    {
        debug_1_print_frequent_words(&param);
    }
    
    /*Step1.E Check frequent word numbers*/
    if (!param.freWordNum)
    {
        free_and_clean_step_0(&param);
        free_and_clean_step_1(&param);
        return 0;
    }
    
    /* ######## #### ## Step2 Cluster Candidates ## #### ######## */
    
    /*Step2.A Create cluster candidate sketch*/
    /*Tag: Optional, One pass over the data set*/
    if (param.clusterSketchSize)
    {
        step_2_create_cluster_candidate_sketch(&param);
    }
    
    /*Step2.B Finding cluster candidates*/
    /*Tag: One pass over the data set*/
    step_2_find_cluster_candidates(&param);
    
    /*Step2.C Aggregate support*/
    /*Tag: Optional*/
    if (param.bAggrsupFlag)
    {
        step_2_aggregate_support(&param);
        str_format_int_grouped(digit, param.trieNodeNum);
        sprintf(logStr, "%s nodes in the prefix tree.", digit);
        log_msg(logStr, LOG_NOTICE, &param);
    }
    
    /*Step2.D Debug_1 mode: print cluster candidates*/
    /*Tag: Optional*/
    if (param.debug == 1)
    {
        debug_1_print_cluster_candidates(&param);
    }
    
    /* ######## #### ## Step3 Clusters & Outliers ## #### ######## */
    
    /*Step3.A Find clusters*/
    log_msg("Finding clusters...", LOG_NOTICE, &param);
    
    param.clusterNum = find_clusters_from_candidates(&param);
    
    str_format_int_grouped(digit, param.clusterNum);
    sprintf(logStr, "%s cluster were found.", digit);
    log_msg(logStr, LOG_NOTICE, &param);
    
    /*Step3.B Join clusters*/
    /*Tag: Optional*/
    if (param.wordWeightThreshold)
    {
        step_3_join_clusters(&param);
    }
    
    /*Step3.C Print clusters*/
    if (param.clusterNum)
    {
        step_3_print_clusters(&param);
    }
    
    /*Step3.D Find outliers*/
    /*Tag: Optional, One pass over the data set*/
    if (param.pOutlier)
    {
        log_msg("Finding outliers...", LOG_NOTICE, &param);
        
        outlierNum = find_outliers(&param);
        
        str_format_int_grouped(digit, outlierNum);
        sprintf(logStr, "%s outliers were outputed into file %s.", digit,
                param.pOutlier);
        log_msg(logStr, LOG_NOTICE, &param);
    }
    
    /* ######## #### ## Step4 Ending ## #### ######## */
    
    /*Step4.A Free and clean*/
    free_and_clean_step_0(&param);
    free_and_clean_step_1(&param);
    free_and_clean_step_2(&param);
    free_and_clean_step_3(&param);
    
    return 0;
}

