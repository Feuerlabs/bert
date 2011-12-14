-ifndef(_BERT_HRL_).
-define(_BERT_HRL_, true).

-define(BERT_PORT, 9999).

-define(PROT_ERR_UNDESIGNATED,          0).
-define(PROT_ERR_UNABLE_TO_READ_HEADER, 1).
-define(PROT_ERR__UNABLE_TO_READ_DATA,   2).

-define(SERV_ERR_UNDESIGNATED,          0).
-define(SERV_ERR_NO_SUCH_MODULE,        1).
-define(SERV_ERR_NO_SUCH_FUNCTION,      2).

-record(bert, { term }).
-record(bert_time, { mega, sec, usec }).
-record(bert_regex, { source, options }).

-endif.
