%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
-ifndef(_BERT_HRL_).
-define(_BERT_HRL_, true).

-define(BERT_PORT,                      9999).
-define(BERT_PEER_DICT_KEY,             bert_exec_rpc_caller_peername).

-define(PROT_ERR_UNDESIGNATED,          0).
-define(PROT_ERR_UNABLE_TO_READ_HEADER, 1).
-define(PROT_ERR_UNABLE_TO_READ_DATA,   2).

-define(SERV_ERR_UNDESIGNATED,          0).
-define(SERV_ERR_NO_SUCH_MODULE,        1).
-define(SERV_ERR_NO_SUCH_FUNCTION,      2).

-record(bert, { term }).
-record(bert_time, { mega, sec, usec }).
-record(bert_regex, { source, options }).

-endif.
