# C-based Implementation of LogCluster Algorithm
LogCluster is a density-based data clustering algorithm for event logs, introduced by Risto Vaarandi and Mauno Pihelgas in 2015.
 
A detialed discussion of the LogCluster algorithm can be found in the paper (http://ristov.github.io/publications/cnsm15-logcluster-web.pdf) published at CNSM 2015.

The C-based implementation of LogCluster algorithm is called LogClusterC.

LogClusterC borrows lots of source code from another open source data mining tool SLCT: http://ristov.github.io/slct/ .

The information of LogCluster algorithm and its prototype implementation in Perl: http://ristov.github.io/logcluster/ .

The history versions of LogCluster in Perl: https://github.com/ristov/logcluster/releases .

All the functions in LogCluster Perl version 0.03 are supported in LogClusterC version 0.03. The command line syntax is mutual. Given the same command line input, their outputs will be the same. **(Except if you use word_class option, there will be a bug leading to possible mismatching in outputs. This bug will be fixed soon. All the other options are good.)**

The corresponding thesis and experiment data (plain text output files containing performance parameters) are stored in another Github repository: https://github.com/zhugehq/thesis-project-logclusterc-experiment-data .