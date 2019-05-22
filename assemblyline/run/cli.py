#!/usr/bin/env python
# coding=utf-8

# Suppress all warnings
import warnings

from assemblyline.common.yara import YaraParser
from assemblyline.remote.datatypes.hash import Hash

warnings.filterwarnings("ignore")

import cmd
import inspect
import sys
import multiprocessing
import os
import re
import signal
import time
import uuid
import shutil

from pprint import pprint

from assemblyline.common import forge, log as al_log
from assemblyline.common.backupmanager import DistributedBackup
from assemblyline.common.security import get_totp_token

config = forge.get_config()
config.logging.log_to_console = False
al_log.init_logging('cli')

RESET_COLOUR = '\033[0m'
YELLOW_COLOUR = '\033[93m'
PROCESSES_COUNT = 50
COUNT_INCREMENT = 500
DATASTORE = None
t_count = 0
t_last = time.time()


def init():
    global DATASTORE
    DATASTORE = forge.get_datastore()
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# noinspection PyProtectedMember
def bucket_delete(bucket_name, key):
    try:
        DATASTORE._delete_bucket_item(DATASTORE.get_bucket(bucket_name), key)
    except Exception as e:
        print(e)
        return "DELETE", bucket_name, key, False

    return "deleted", bucket_name, key, True


# noinspection PyProtectedMember
def update_signature_status(status, key, datastore=None):
    try:
        global DATASTORE
        if not DATASTORE:
            DATASTORE = datastore
        data = DATASTORE._get_bucket_item(DATASTORE.get_bucket('signature'), key)
        data['meta']['al_status'] = status
        data = DATASTORE.sanitize('signature', data, key)
        DATASTORE._save_bucket_item(DATASTORE.get_bucket('signature'), key, data)
    except Exception as e:
        print(e)


def submission_delete_tree(key):
    try:
        with forge.get_filestore() as f_transport:
            DATASTORE.delete_submission_tree(key, transport=f_transport)
    except Exception as e:
        print(e)
        return "DELETE", "submission", key, False

    return "deleted", "submission", key, True


def action_done(args):
    global t_count, t_last, COUNT_INCREMENT
    action, bucket, key, success = args
    if success:
        t_count += 1
        if t_count % COUNT_INCREMENT == 0:
            new_t = time.time()
            print("[%s] %s %s so far (%s at %s keys/sec)" % \
                  (bucket, t_count, action, new_t - t_last, int(COUNT_INCREMENT / (new_t - t_last))))
            t_last = new_t
    else:
        print("!!ERROR!! [%s] %s ==> %s" % (bucket, action, key))


def _reindex_template(bucket_name, keys_function, get_function, save_function, bucket=None, filter_out=None):
        if not filter_out:
            filter_out = []

        print("\n%s:" % bucket_name.upper())
        print("\t[x] Listing keys...")
        keys = keys_function()

        print("\t[-] Re-indexing...")
        for key in keys:
            skip = False
            for f in filter_out:
                if f in key:
                    skip = True
            if skip:
                continue
            if bucket:
                value = get_function(bucket, key)
                save_function(bucket, key, value)
            else:
                value = get_function(key)
                save_function(key, value)

        print("\t[x] Indexed!")


# noinspection PyMethodMayBeStatic,PyProtectedMember,PyBroadException
class ALCommandLineInterface(cmd.Cmd):  # pylint:disable=R0904

    def __init__(self, show_prompt=True):
        cmd.Cmd.__init__(self)
        self.prompt = ""
        self.intro = ""
        self.datastore = forge.get_datastore()
        self.config = forge.get_config()
        if show_prompt:
            self._update_context()

    def _update_context(self):
        self.prompt = '(al_cli) $ '
        self.intro = 'AL 4.0 - Console. (type help).'

    def _parse_args(self, s, platform='this'):
        """Multi-platform variant of shlex.split() for command-line splitting.
        For use with subprocess, for argv injection etc. Using fast REGEX.

        platform: 'this' = auto from current platform;
                  1 = POSIX;
                  0 = Windows/CMD
                  (other values reserved)
        """
        if platform == 'this':
            platform = (sys.platform != 'win32')
        if platform == 1:
            cmd_lex = r'''"((?:\\["\\]|[^"])*)"|'([^']*)'|(\\.)|(&&?|\|\|?|\d?\>|[<])|([^\s'"\\&|<>]+)|(\s+)|(.)'''
        elif platform == 0:
            cmd_lex = r'''"((?:""|\\["\\]|[^"])*)"?()|(\\\\(?=\\*")|\\")|(&&?|\|\|?|\d?>|[<])|([^\s"&|<>]+)|(\s+)|(.)'''
        else:
            raise AssertionError('unkown platform %r' % platform)

        args = []
        accu = None  # collects pieces of one arg
        for qs, qss, esc, pipe, word, white, fail in re.findall(cmd_lex, s):
            if word:
                pass  # most frequent
            elif esc:
                word = esc[1]
            elif white or pipe:
                if accu is not None:
                    args.append(accu)
                if pipe:
                    args.append(pipe)
                accu = None
                continue
            elif fail:
                raise ValueError("invalid or incomplete shell string")
            elif qs:
                word = qs.replace('\\"', '"').replace('\\\\', '\\')
                if platform == 0:
                    word = word.replace('""', '"')
            else:
                word = qss  # may be even empty; must be last

            accu = (accu or '') + word

        if accu is not None:
            args.append(accu)

        return args

    def _print_error(self, msg):
        stack_func = None
        stack = inspect.stack()
        for item in stack:
            if 'cli.py' in item[1] and '_print_error' not in item[3]:
                stack_func = item[3]
                break

        if msg:
            print("ERROR: " + msg + "\n")

        if stack_func:
            function_doc = inspect.getdoc(getattr(self, stack_func))
            if function_doc:
                print("Function help:\n\n" + function_doc + "\n")

    #
    # Exit actions
    #
    def do_exit(self, arg):
        """Quits the CLI"""
        arg = arg or 0
        sys.exit(int(arg))

    def do_quit(self, arg):
        """Quits the CLI"""
        self.do_exit(arg)

    #
    # Backup actions
    #
    def do_backup(self, args):
        """
        Backup the database content to a set of json files

        Usage:
            backup <destination_folder>
                   <destination_folder> <bucket_name> [follow] [force] <query>

        Parameters:
            <destination_folder> Path to the destination folder [required]

            <bucket_name>        Name of the bucket to backup [required in backup by query]

            follow               Follow IDs to backup more then the specified bucket
                                 [optional, only used in backup by query]

            force                Automatically perform backup without asking for confirmation
                                 [optional, only used in backup by query]

            <query>              Query that the data need to match
                                 [optional, only used in backup by query]

        Examples:
            # Create a backup of the system buckets
            backup /tmp/backup_folder

            # Created a backup of all alerts
            backup /tmp/alerts_backup alert "*:*"
        """
        args = self._parse_args(args)

        follow = False
        if 'follow' in args:
            follow = True
            args.remove('follow')

        force = False
        if 'force' in args:
            force = True
            args.remove('force')

        if len(args) == 1:
            dest = args[0]
            system_backup = True
            bucket = None
            follow = False
            query = None
        elif len(args) == 3:
            dest, bucket, query = args
            system_backup = False
        else:
            self._print_error("Wrong number of arguments for backup command.")
            return

        if system_backup:
            backup_manager = DistributedBackup(dest, worker_count=5)
            backup_manager.backup(["blob", "node", "signature", "user", "workflow"])
        else:
            data = self.datastore._search_bucket(self.datastore.get_bucket(bucket), query, start=0, rows=1)
            total = data['total']
            if not total:
                print("\nNothing in '%s' matches the query:\n\n  %s\n" % (bucket.upper(), query))
                return
            else:
                print("\nNumber of items matching this query: %s\n" % data["total"])

            if not force:
                print("This is an exemple of the data that will be backuped:\n")
                print(data['items'][0], "\n")
                if self.prompt:
                    cont = input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"
                else:
                    print("You are not in interactive mode therefor the backup was not executed. "
                          "Add 'force' to your commandline to execute the backup.")
                    cont = False

                if not cont:
                    print("\n**ABORTED**\n")
                    return

            if follow:
                total *= 100

            try:
                if not os.path.exists(dest):
                    os.makedirs(dest)
            except Exception:
                print("Cannot make %s folder. Make sure you can write to this folder. " \
                      "Maybe you should write your backups in /tmp ?" % dest)
                return

            backup_manager = DistributedBackup(dest, worker_count=max(1, min(total / 1000, 50)))

            try:
                backup_manager.backup([bucket], follow_keys=follow, query=query)
            except KeyboardInterrupt:
                backup_manager.terminate()
                raise

    def do_restore(self, args):
        """
        Restore a backup created by the backup command

        Usage:
            restore <backup_directory>

        Parameters:
            <backup_directory> Path to the backup folder [required]

        Examples:
            restore /tmp/backup_folder
        """
        args = self._parse_args(args)

        if len(args) not in [1]:
            self._print_error("Wrong number of arguments for restore command.")
            return

        path = args[0]
        if not path:
            self._print_error("You must specify an input folder.")
            return

        workers = len([x for x in os.listdir(path) if '.part' in x])

        # Make sure that all the backup parts are there
        bak_files = os.listdir(path)
        for part_num in range(workers):
            suffix_check = ".part%d" % part_num
            if not any(suffix_check in x for x in bak_files):
                self._print_error("%d files exist, but no file ending with %s found. " % (workers, suffix_check))
                return

        backup_manager = DistributedBackup(path, worker_count=workers)

        try:
            backup_manager.restore()
        except KeyboardInterrupt:
            backup_manager.terminate()
            raise

    #
    # Delete actions
    #
    def do_delete(self, args):
        """
        Delete all data from a bucket that match a given query

        Usage:
            delete <bucket> [full] [force] <query>

        Parameters:
            <bucket>  Name of the bucket to delete from
            full      Follow IDs and remap classification
                      [Optional: Only work while deleting submissions]
            force     Automatically perform deletion without asking for confirmation [optional]
            <query>   Query to run to find the data to delete

        Examples:
            # Delete all submission for "user" with all associated results
            delete submission full "submission.submitter:user"
        """
        valid_buckets = list(self.datastore.ds.get_models().keys())
        args = self._parse_args(args)

        if 'full' in args:
            full = True
            args.remove('full')
        else:
            full = False

        if 'force' in args:
            force = True
            args.remove('force')
        else:
            force = False

        if len(args) != 2:
            self._print_error("Wrong number of arguments for delete command.")
            return

        bucket, query = args

        if bucket not in valid_buckets:
            bucket_list = '\n'.join(valid_buckets)
            self._print_error(f"\nInvalid bucket specified: {bucket}\n\nValid buckets are:\n{bucket_list}")
            return
        else:
            collection = getattr(self.datastore, bucket)

        pool = None
        try:
            cont = force
            test_data = collection.search(query, offset=0, rows=1)
            if not test_data["total"]:
                print("Nothing matches the query.")
                return

            if not force:
                print(f"\nNumber of items matching this query: {test_data['total']}\n\n")
                print("This is an example of the data that will be deleted:\n")
                print(test_data['items'][0], "\n")
                if self.prompt:
                    cont = input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"

                    if not cont:
                        print("\n**ABORTED**\n")
                        return
                else:
                    print("You are not in interactive mode therefor the delete was not executed. "
                          "Add 'force' to your commandline to execute the delete.")
                    return

            if cont:
                if full and bucket == 'submission':
                    pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
                    for data in collection.stream_search(query, fl="id", item_buffer_size=COUNT_INCREMENT):
                        pool.apply_async(submission_delete_tree, (data.id,), callback=action_done)
                else:
                    collection.delete_matching(query)

        except KeyboardInterrupt as e:
            print("Interrupting jobs...")
            if pool is not None:
                pool.terminate()
                pool.join()

        except Exception as e:
            print("Something when wrong, retry!\n\n %s\n" % e)
        else:
            if pool is not None:
                pool.close()
                pool.join()
            collection.commit()
            print(f"Data of bucket '{bucket}' matching query '{query}' has been deleted.")


    def do_service(self, args):
        """
        Perform operation on the different services on the system

        Usage:
            service list
                    show    <name>
                    disable <name>
                    enable  <name>
                    remove  <name>

        Actions:
            list      List all services on the system
            disable   Disable the service in the system
            enable    Enable the service in the system
            remove    Remove the service from the system
            show      Show the service description

        Parameters:
            <name>   Name of the service to perform the action on

        Examples:
            # Show service 'Sync'
            service show Sync
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for service command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for service command.")
            return

        if action_type == 'list':
            for key in self.datastore.list_service_keys():
                print(key)
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_service(item_id))
        elif action_type == 'disable' and item_id:
            item = self.datastore.get_service(item_id)
            if item:
                item['enabled'] = False
                self.datastore.save_service(item_id, item)
                print("%s was disabled" % item_id)
            else:
                print("%s does not exist" % item_id)
        elif action_type == 'enable' and item_id:
            item = self.datastore.get_service(item_id)
            if item:
                item['enabled'] = True
                self.datastore.save_service(item_id, item)
                print("%s was enabled" % item_id)
            else:
                print("%s does not exist" % item_id)
        elif action_type == 'remove' and item_id:
            self.datastore.delete_service(item_id)
            print("Service '%s' removed.")
        else:
            self._print_error("Invalid command parameters")

    def do_signature(self, args):
        """
        Perform operation on a signature in the system

        Usage:
            signature change_status by_id    [force] <status_value> <id>
                      change_status by_query [force] <status_value> <query>
                      remove        <id>
                      show          <id>

        Actions:
            change_status  Change the status of a signature
            remove         Remove the signature from the system
            show           Show the signature description

        Parameters:
            <id>           ID of the signature to perform the action on
            <query>        Query to match the signature
            <status_value> New status value for the signature
            force          Automatically perform status change without asking for confirmation [optional]
            by_id          Use an ID to choose the signature
            by_query       Use a search query to choose the signatures

        Examples:
            # Change the status of all STAGING signatures to DEPLOYED
            signature change_status by_query DEPLOYED "meta.al_status:STAGING"
        """
        valid_actions = ['show', 'change_status', 'remove']
        args = self._parse_args(args)

        if 'force' in args:
            force = True
            args.remove('force')
        else:
            force = False

        if len(args) == 2:
            action_type, item_id = args
            id_type = status = None
        elif len(args) == 4:
            action_type, id_type, status, item_id = args
        else:
            self._print_error("Wrong number of arguments for signature command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for signature command.")
            return

        if action_type == 'show' and item_id:
            pprint(self.datastore.get_signature(item_id))
        elif action_type == 'change_status' and item_id and id_type and status:
            if status not in YaraParser.STATUSES:
                self._print_error("\nInvalid status for action 'change_status' of signature command."
                                  "\n\nValid statuses are:\n%s" % "\n".join(YaraParser.STATUSES))
                return

            if id_type == 'by_id':
                update_signature_status(status, item_id, datastore=self.datastore)
                print("Signature '%s' was changed to status %s." % (item_id, status))
            elif id_type == 'by_query':
                pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
                try:
                    cont = force
                    test_data = self.datastore._search_bucket(self.datastore.get_bucket("signature"),
                                                              item_id, start=0, rows=1)
                    if not test_data["total"]:
                        print("Nothing matches the query.")
                        return

                    if not force:
                        print("\nNumber of items matching this query: %s\n\n" % test_data["total"])
                        print("This is an exemple of the signatures that will change status:\n")
                        print(test_data['items'][0], "\n")
                        if self.prompt:
                            cont = input("Are your sure you want to continue? (y/N) ")
                            cont = cont == "y"

                            if not cont:
                                print("\n**ABORTED**\n")
                                return
                        else:
                            print("You are not in interactive mode therefor the status change was not executed. "
                                  "Add 'force' to your commandline to execute the status change.")
                            return

                    if cont:
                        for data in self.datastore.stream_search("signature", item_id, fl="_yz_rk",
                                                                 item_buffer_size=COUNT_INCREMENT):
                            pool.apply_async(update_signature_status, (status, data["_yz_rk"]))
                except KeyboardInterrupt as e:
                    print("Interrupting jobs...")
                    pool.terminate()
                    pool.join()
                    raise e
                except Exception as e:
                    print("Something when wrong, retry!\n\n %s\n" % e)
                else:
                    pool.close()
                    pool.join()
                    print("Signatures matching query '%s' were changed to status '%s'." % (item_id, status))
            else:
                self._print_error("Invalid action parameters for action 'change_status' of signature command.")

        elif action_type == 'remove' and item_id:
            self.datastore.delete_signature(item_id)
            print("Signature '%s' removed.")
        else:
            self._print_error("Invalid command parameters")

    def do_user(self, args):
        """
        Perform operation on a user in the system

        Usage:
            user list
                 show        <uname>
                 disable     <uname>
                 enable      <uname>
                 set_admin   <uname>
                 unset_admin <uname>
                 remove      <uname>
                 unset_otp   <uname>
                 show_otp    <uname>

        Actions:
            list         List all the users
            show         Describe a user
            disable      Disable a user
            enable       Enable a user
            set_admin    Make a user admin
            unset_admin  Remove admin priviledges to a user
            remove       Remove a user
            unset_otp    Remove OTP Secret Token
            show_otp     Show current OTP Token

        Parameters:
            <uname>      Username of the user to perform the action on


        Examples:
            # Disable user 'user'
            user disable user
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove',
                         'set_admin', 'unset_admin', 'unset_otp', 'show_otp']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for user command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for user command.")
            return

        if action_type == 'list':
            for key in [x for x in self.datastore.list_user_keys() if '_options' not in x and '_avatar' not in x]:
                print(key)
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_user(item_id))
        elif action_type == 'disable' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item['is_active'] = False
                self.datastore.save_user(item_id, item)
                print("%s was disabled" % item_id)
            else:
                print("%s does not exist" % item_id)
        elif action_type == 'enable' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item['is_active'] = True
                self.datastore.save_user(item_id, item)
                print("%s was enabled" % item_id)
            else:
                print("%s does not exist" % item_id)
        elif action_type == 'set_admin' and item_id:
                item = self.datastore.get_user(item_id)
                if item:
                    item['is_admin'] = True
                    self.datastore.save_user(item_id, item)
                    print("%s was added admin priviledges" % item_id)
                else:
                    print("%s does not exist" % item_id)
        elif action_type == 'unset_admin' and item_id:
                item = self.datastore.get_user(item_id)
                if item:
                    item['is_admin'] = False
                    self.datastore.save_user(item_id, item)
                    print("%s was removed admin priviledges" % item_id)
                else:
                    print("%s does not exist" % item_id)
        elif action_type == 'remove' and item_id:
            self.datastore.delete_user(item_id)
            print("User '%s' removed.")
        elif action_type == 'unset_otp' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item.pop('otp_sk', None)
                self.datastore.save_user(item_id, item)
                print("%s OTP secret key was removed" % item_id)
            else:
                print("%s does not exist" % item_id)
        elif action_type == 'show_otp' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                secret_key = item.get('otp_sk', None)
                if secret_key:
                    while True:
                        print('\r%s OTP Token:   %06d   %s%s' % (item_id, get_totp_token(secret_key),
                                                                 "â–ˆ" * int(time.time() % 30),
                                                                 "â–‘" * (29 - int(time.time() % 30)))),
                        sys.__stdout__.flush()

                        time.sleep(1)
                else:
                    print("2FA not enabled for user %s" % item_id)
            else:
                print("%s does not exist" % item_id)
        else:
            self._print_error("Invalid command parameters")

    #
    # Index actions
    #
    def do_index(self, args):
        """
        Perform operations on the search index

        Usage:
            index commit   [<bucket>]
                  reindex  [<bucket>]

                  reset

        Actions:
            commit       Force SOLR to commit the index
            reindex      Read all keys and reindex them (Really slow)
            reset        Delete and recreate all search indexes

        Parameters:
            <bucket>     Bucket to do the opration on [optional]


        Examples:
            # Force commit on file bucket
            index commit file
            # Force commit on all bucket
            index commit
        """
        _reindex_map = {
            "alert": [self.datastore.list_alert_debug_keys, self.datastore.get_alert, self.datastore.save_alert,
                      None, None],
            "error": [self.datastore.list_error_debug_keys, self.datastore._get_bucket_item,
                      self.datastore._save_bucket_item, self.datastore.errors, None],
            "file": [self.datastore.list_file_debug_keys, self.datastore._get_bucket_item,
                     self.datastore._save_bucket_item, self.datastore.files, None],
            "filescore": [self.datastore.list_filescore_debug_keys, self.datastore._get_bucket_item,
                          self.datastore._save_bucket_item, self.datastore.filescores, None],
            "node": [self.datastore.list_node_debug_keys, self.datastore.get_node, self.datastore.save_node,
                     None, None],
            "result": [self.datastore.list_result_debug_keys, self.datastore._get_bucket_item,
                       self.datastore._save_bucket_item, self.datastore.results, None],
            "signature": [self.datastore.list_signature_debug_keys, self.datastore.get_signature,
                          self.datastore.save_signature, None, None],
            "submission": [self.datastore.list_submission_debug_keys, self.datastore.get_submission,
                           self.datastore.save_submission, None, ["_tree", "_summary"]],
            "user": [self.datastore.list_user_debug_keys, self.datastore.get_user, self.datastore.save_user,
                     None, None],
            "workflow": [self.datastore.list_workflow_debug_keys, self.datastore.get_workflow,
                         self.datastore.save_workflow, None, None]
        }

        valid_buckets = sorted(self.datastore.INDEXED_BUCKET_LIST + self.datastore.ADMIN_INDEXED_BUCKET_LIST)
        valid_actions = ['commit', 'reindex', 'reset']

        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            bucket = None
        elif len(args) == 2:
            action_type, bucket = args
        else:
            self._print_error("Wrong number of arguments for index command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: %s\n\n"
                              "Valid actions are:\n%s" % (action_type, "\n".join(valid_actions)))
            return

        if bucket and bucket not in valid_buckets:
            self._print_error("\nInvalid bucket specified: %s\n\n"
                              "Valid buckets are:\n%s" % (bucket, "\n".join(valid_buckets)))
            return

        if action_type == 'reindex':
            if bucket:
                reindex_args = _reindex_map[bucket]
                _reindex_template(bucket, reindex_args[0], reindex_args[1],
                                  reindex_args[2], reindex_args[3], reindex_args[4])
            else:
                for bucket in valid_buckets:
                    reindex_args = _reindex_map[bucket]
                    _reindex_template(bucket, reindex_args[0], reindex_args[1],
                                      reindex_args[2], reindex_args[3], reindex_args[4])
        elif action_type == 'commit':
            if bucket:
                self.datastore.commit_index(bucket)
                print("Index %s was commited." % bucket.upper())
            else:
                print("Forcing commit procedure for all indexes...")
                for bucket in valid_buckets:
                    print("    Index %s was commited." % bucket.upper())
                    self.datastore.commit_index(bucket)
                print("All indexes commited.")
        elif action_type == 'reset':
            print("Recreating indexes:")

            indexes = [
                {'n_val': 0, 'name': 'filescore', 'schema': 'filescore'},
                {'n_val': 0, 'name': 'node', 'schema': 'node'},
                {'n_val': 0, 'name': 'signature', 'schema': 'signature'},
                {'n_val': 0, 'name': 'user', 'schema': 'user'},
                {'n_val': 0, 'name': 'file', 'schema': 'file'},
                {'n_val': 0, 'name': 'submission', 'schema': 'submission'},
                {'n_val': 0, 'name': 'error', 'schema': 'error'},
                {'n_val': 0, 'name': 'result', 'schema': 'result'},
                {'n_val': 0, 'name': 'alert', 'schema': 'alert'},
            ]

            print("\tDisabling bucket association:")
            for index in indexes:
                bucket = self.datastore.client.bucket(index['name'], bucket_type="data")
                props = self.datastore.client.get_bucket_props(bucket)
                index['n_val'] = props['n_val']
                self.datastore.client.set_bucket_props(bucket, {"search_index": "_dont_index_",
                                                                "dvv_enabled": False,
                                                                "last_write_wins": True,
                                                                "allow_mult": False})
                print("\t\t%s" % index['name'].upper())

            print("\tDeleting indexes:")
            for index in indexes:
                try:
                    self.datastore.client.delete_search_index(index['name'])
                except Exception:
                    pass
                print("\t\t%s" % index['name'].upper())

            print("\tCreating indexes:")
            for index in indexes:
                self.datastore.client.create_search_index(index['name'], schema=index['schema'], n_val=index['n_val'])
                print("\t\t%s" % index['name'].upper())

            print("\tAssociating bucket to index:")
            for index in indexes:
                bucket = self.datastore.client.bucket(index['name'], bucket_type="data")
                self.datastore.client.set_bucket_props(bucket, {"search_index": index['name']})
                print("\t\t%s" % index['name'].upper())

            print("All indexes successfully recreated!")

    #
    # Wipe actions
    #
    def do_wipe(self, args):
        """
        Wipe all data from one or many buckets

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            wipe bucket <bucket_name>
                 non_system
                 submission_data

        Actions:
            bucket           Single bucket wipe mode
            non_system       Delete all data from:
                                 alert
                                 emptyresult
                                 error
                                 file
                                 filescore
                                 result
                                 submission
                                 workflow
            submission_data  Delete all data from:
                                 emptyresult
                                 error
                                 file
                                 filescore
                                 result
                                 submission

        Parameters:
            <bucket_name>  Name of the bucket to wipe

        Examples:
            # Wipe all files
            wipe bucket file
        """
        args = self._parse_args(args)
        valid_actions = ['bucket', 'non_system', 'submission_data']

        if len(args) == 1:
            action_type = args[0]
            bucket = None
        elif len(args) == 2:
            action_type, bucket = args
        else:
            self._print_error("Wrong number of arguments for wipe command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: %s\n\n"
                              "Valid actions are:\n%s" % (action_type, "\n".join(valid_actions)))
            return

        if action_type == 'bucket':
            if bucket not in self.wipe_map.keys():
                self._print_error("\nInvalid bucket: %s\n\n"
                                  "Valid buckets are:\n%s" % (bucket, "\n".join(self.wipe_map.keys())))
                return

            self.wipe_map[bucket]()
            print("Done wipping %s." % bucket)
        elif action_type == 'non_system':
            for bucket in ['alert', 'emptyresult', 'error', 'file', 'filescore', 'result', 'submission', 'workflow']:
                self.wipe_map[bucket]()
                print("Done wipping %s." % bucket)
        elif action_type == 'submission_data':
            for bucket in ['emptyresult', 'error', 'file', 'filescore', 'result', 'submission']:
                self.wipe_map[bucket]()
                print("Done wipping %s." % bucket)
        else:
            self._print_error("Invalid command parameters")

    def do_data_reset(self, args):
        """
        Completely resets the database. Does a backup of the system data, wipe every buckets then
        restores the backup.

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            data_reset [full]

        Parameters:
            full   Does not just wipe the system bucket, also wipe all submissions and results

        Examples:
            # Reset the database
            data_reset full
        """
        args = self._parse_args(args)

        if 'full' in args:
            full = True
        else:
            full = False

        backup_file = "/tmp/al_backup_%s" % str(uuid.uuid4())
        self.do_backup(backup_file)
        seed = self.datastore.get_blob('seed')

        for bucket in ['blob', 'node', 'signature', 'user', 'workflow']:
            self.wipe_map[bucket]()

        if full:
            for bucket in ['alert', 'emptyresult', 'error', 'file', 'filescore', 'result', 'submission']:
                self.wipe_map[bucket]()

        self.do_index("commit")
        self.datastore.save_blob('seed', seed)
        self.do_restore(backup_file)
        shutil.rmtree(backup_file)

    def do_ui(self, args):
        """
        Perform UI related operations

        Usage:
            ui clear_sessions [username]
               rekey          [length]

        Parameters:
            clear_sessions     Removes all active sessions
            username           User to clear the sessions for
                               [optional, only use in clear_sessions]
            rekey              Create a new password encryption public/private key
            length             Length of the new public/private key
                               [optional, only use in rekey]

        Examples:
            # Clear sessions for user bob
            ui clear_sessions bob

            # Create a new key pair for encrypting passwords
            ui rekey
        """
        valid_func = ['clear_sessions', 'rekey']
        args = self._parse_args(args)

        if len(args) not in [1, 2]:
            self._print_error("Wrong number of arguments for restore command.")
            return

        func = args[0]
        if func not in valid_func:
            self._print_error("Invalid action '%s' for ui command." % func)
            return

        if func == 'clear_sessions':
            username = None
            if len(args) == 2:
                username = args[1]

            flsk_sess = Hash(
                "flask_sessions",
                host=config.core.redis.nonpersistent.host,
                port=config.core.redis.nonpersistent.port,
                db=config.core.redis.nonpersistent.db
            )

            if not username:
                flsk_sess.delete()
                print("All sessions where cleared.")
            else:
                for k, v in flsk_sess.items().iteritems():
                    if v.get('username', None) == username:
                        print("Removing session: %s" % k)
                        flsk_sess.pop(k)

                print("All sessions for user '%s' removed." % username)


def print_banner():
    from assemblyline.common import banner
    print(banner.BANNER)


def shell_main():
    cli = ALCommandLineInterface(len(sys.argv) == 1)

    if len(sys.argv) != 1:
        cli.onecmd(" ".join([{True: '"%s"' % x, False: x}[" " in x] for x in sys.argv[1:]]))
    else:
        print_banner()
        cli.cmdloop()


if __name__ == '__main__':
    try:
        shell_main()
    except KeyboardInterrupt:
        exit()