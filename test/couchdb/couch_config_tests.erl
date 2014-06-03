% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_config_tests).

-include("../../src/couchdb/couch_db.hrl").
-include("couchdb_tests.hrl").

-define(CONFIG_DEFAULT,
        filename:join([?BUILDDIR, "etc", "couchdb", "default_dev.ini"])).
-define(CONFIG_FIXTURE_1,
        filename:join([?FIXTURESDIR, "couch_config_tests_1.ini"])).
-define(CONFIG_FIXTURE_2,
        filename:join([?FIXTURESDIR, "couch_config_tests_2.ini"])).
-define(CONFIG_FIXTURE_TEMP,
    begin
        FileName = filename:join([?TEMPDIR, "couch_config_temp.ini"]),
        {ok, Fd} = file:open(FileName, write),
        ok = file:truncate(Fd),
        ok = file:close(Fd),
        FileName
    end).


setup() ->
    setup(?CONFIG_CHAIN).
setup({temporary, Chain}) ->
    setup(Chain);
setup({persistent, Chain}) ->
    setup(lists:append(Chain, [?CONFIG_FIXTURE_TEMP]));
setup(Chain) ->
    {ok, Pid} = couch_config:start_link(Chain),
    Pid.

teardown(Pid) ->
    couch_config:stop(),
    erlang:monitor(process, Pid),
    receive
        {'DOWN', _, _, Pid, _} ->
            ok
    after 1000 ->
        throw({timeout_error, config_stop})
    end.
teardown(_, Pid) ->
    teardown(Pid).


couch_config_test_() ->
    {
        "CouchDB config tests",
        [
            couch_config_get_tests(),
            couch_config_set_tests(),
            couch_config_del_tests(),
            config_override_tests(),
            config_persistent_changes_tests()
        ]
    }.

couch_config_get_tests() ->
    {
        "Config get tests",
        {
            foreach,
            fun setup/0, fun teardown/1,
            [
                should_load_all_configs(),
                should_locate_daemons_section(),
                should_locate_mrview_handler(),
                should_return_undefined_atom_on_missed_section(),
                should_return_undefined_atom_on_missed_option(),
                should_return_custom_default_value_on_missed_option(),
                should_only_return_default_on_missed_option(),
                should_get_binary_option()
            ]
        }
    }.

couch_config_set_tests() ->
    {
        "Config set tests",
        {
            foreach,
            fun setup/0, fun teardown/1,
            [
                should_update_option(),
                should_create_new_section(),
                should_set_binary_option()
            ]
        }
    }.

couch_config_del_tests() ->
    {
        "Config deletion tests",
        {
            foreach,
            fun setup/0, fun teardown/1,
            [
                should_return_undefined_atom_after_option_deletion(),
                should_be_ok_on_deleting_unknown_options(),
                should_delete_binary_option()
            ]
        }
    }.

config_override_tests() ->
    {
        "Configs overide tests",
        {
            foreachx,
            fun setup/1, fun teardown/2,
            [
                {{temporary, [?CONFIG_DEFAULT]},
                 fun should_ensure_in_defaults/2},
                {{temporary, [?CONFIG_DEFAULT, ?CONFIG_FIXTURE_1]},
                 fun should_override_options/2},
                {{temporary, [?CONFIG_DEFAULT, ?CONFIG_FIXTURE_2]},
                 fun should_create_new_sections_on_override/2},
                {{temporary, [?CONFIG_DEFAULT, ?CONFIG_FIXTURE_1,
                              ?CONFIG_FIXTURE_2]},
                 fun should_win_last_in_chain/2}
            ]
        }
    }.

config_persistent_changes_tests() ->
    {
        "Config persistent changes",
        {
            foreachx,
            fun setup/1, fun teardown/2,
            [
                {{persistent, [?CONFIG_DEFAULT]},
                 fun should_write_changes/2},
                {{temporary, [?CONFIG_DEFAULT]},
                 fun should_ensure_that_default_wasnt_modified/2},
                {{temporary, [?CONFIG_FIXTURE_TEMP]},
                 fun should_ensure_that_written_to_last_config_in_chain/2}
            ]
        }
    }.


should_load_all_configs() ->
    ?_assert(length(couch_config:all()) > 0).

should_locate_daemons_section() ->
    ?_assert(length(couch_config:get("daemons")) > 0).

should_locate_mrview_handler() ->
    ?_assertEqual("{couch_mrview_http, handle_view_req}",
                  couch_config:get("httpd_design_handlers", "_view")).

should_return_undefined_atom_on_missed_section() ->
    ?_assertEqual(undefined,
                  couch_config:get("foo", "bar")).

should_return_undefined_atom_on_missed_option() ->
    ?_assertEqual(undefined,
                  couch_config:get("httpd", "foo")).

should_return_custom_default_value_on_missed_option() ->
    ?_assertEqual("bar",
                  couch_config:get("httpd", "foo", "bar")).

should_only_return_default_on_missed_option() ->
    ?_assertEqual("0",
                  couch_config:get("httpd", "port", "bar")).

should_get_binary_option() ->
    ?_assertEqual(<<"baz">>,
                  couch_config:get(<<"foo">>, <<"bar">>, <<"baz">>)).

should_update_option() ->
    ?_assertEqual("severe",
        begin
            ok = couch_config:set("log", "level", "severe", false),
            couch_config:get("log", "level")
        end).

should_create_new_section() ->
    ?_assertEqual("bang",
        begin
            undefined = couch_config:get("new_section", "bizzle"),
            ok = couch_config:set("new_section", "bizzle", "bang", false),
            couch_config:get("new_section", "bizzle")
        end).

should_set_binary_option() ->
    ?_assertEqual(<<"baz">>,
        begin
            ok = couch_config:set(<<"foo">>, <<"bar">>, <<"baz">>, false),
            couch_config:get(<<"foo">>, <<"bar">>)
        end).

should_return_undefined_atom_after_option_deletion() ->
    ?_assertEqual(undefined,
        begin
            ok = couch_config:delete("log", "level", false),
            couch_config:get("log", "level")
        end).

should_be_ok_on_deleting_unknown_options() ->
    ?_assertEqual(ok,
        begin
            couch_config:delete("zoo", "boo", false)
        end).

should_delete_binary_option() ->
    ?_assertEqual(undefined,
        begin
            ok = couch_config:set(<<"foo">>, <<"bar">>, <<"baz">>, false),
            ok = couch_config:delete(<<"foo">>, <<"bar">>, false),
            couch_config:get(<<"foo">>, <<"bar">>)
        end).

should_ensure_in_defaults(_, _) ->
    ?_assert(
        begin
            ?assertEqual("100",
                         couch_config:get("couchdb", "max_dbs_open")),
            ?assertEqual("5984",
                         couch_config:get("httpd", "port")),
            ?assertEqual(undefined,
                         couch_config:get("fizbang", "unicode")),
            true
        end).

should_override_options(_, _) ->
    ?_assert(
        begin
            ?assertEqual("10",
                         couch_config:get("couchdb", "max_dbs_open")),
            ?assertEqual("4895",
                         couch_config:get("httpd", "port")),
            true
        end).

should_create_new_sections_on_override(_, _) ->
    ?_assert(
        begin
            ?assertEqual("80",
                         couch_config:get("httpd", "port")),
            ?assertEqual("normalized",
                         couch_config:get("fizbang", "unicode")),
            true
        end).

should_win_last_in_chain(_, _) ->
    ?_assert(
        begin
            ?assertEqual("80",
                         couch_config:get("httpd", "port")),
            true
        end).

should_write_changes(_, _) ->
    ?_assert(
        begin
            ?assertEqual("5984",
                         couch_config:get("httpd", "port")),
            ?assertEqual(ok,
                         couch_config:set("httpd", "port", "8080")),
            ?assertEqual("8080",
                         couch_config:get("httpd", "port")),
            ?assertEqual(ok,
                         couch_config:delete("httpd", "bind_address", "8080")),
            ?assertEqual(undefined,
                         couch_config:get("httpd", "bind_address")),
            true
        end).

should_ensure_that_default_wasnt_modified(_, _) ->
    ?_assert(
        begin
            ?assertEqual("5984",
                         couch_config:get("httpd", "port")),
            ?assertEqual("127.0.0.1",
                         couch_config:get("httpd", "bind_address")),
            true
        end).

should_ensure_that_written_to_last_config_in_chain(_, _) ->
    ?_assert(
        begin
            ?assertEqual("8080",
                         couch_config:get("httpd", "port")),
            ?assertEqual(undefined,
                         couch_config:get("httpd", "bind_address")),
            true
        end).
