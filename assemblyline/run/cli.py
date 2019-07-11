#!/usr/bin/env python
# coding=utf-8

import cmd
import inspect
import sys
import multiprocessing
import os
import re
import signal
import time
import shutil
import warnings

from pprint import pformat

from assemblyline.common import forge, log as al_log
from assemblyline.common.backupmanager import DistributedBackup
from assemblyline.common.security import get_totp_token, generate_random_secret
from assemblyline.common.uid import get_random_id
from assemblyline.common.yara import YaraParser
from assemblyline.remote.datatypes.hash import Hash

warnings.filterwarnings("ignore")

config = forge.get_config()
config.logging.log_to_console = False
al_log.init_logging('cli')

PROCESSES_COUNT = 50
COUNT_INCREMENT = 500
DATASTORE = None
t_count = 0
t_last = time.time()


class NullLogger(object):
    @staticmethod
    def info(msg):
        pass

    @staticmethod
    def warning(msg):
        pass

    @staticmethod
    def warn(msg):
        pass

    @staticmethod
    def error(msg):
        pass

    @staticmethod
    def exception(msg):
        pass


class PrintLogger(object):
    @staticmethod
    def info(msg):
        print(msg)

    @staticmethod
    def warning(msg):
        print(f"[W] {msg}")

    @staticmethod
    def warn(msg):
        print(f"[W] {msg}")

    @staticmethod
    def error(msg):
        print(f"[E] {msg}")

    @staticmethod
    def exception(msg):
        print(f"[EX] {msg}")


def init():
    global DATASTORE
    DATASTORE = forge.get_datastore()
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def submission_delete_tree(key, logger):
    try:
        with forge.get_filestore() as f_transport:
            DATASTORE.delete_submission_tree(key, transport=f_transport)
    except Exception as e:
        logger.error(e)
        return "DELETE", "submission", key, False, isinstance(logger, PrintLogger)

    return "deleted", "submission", key, True, isinstance(logger, PrintLogger)


def action_done(args):
    global t_count, t_last, COUNT_INCREMENT
    action, bucket, key, success, do_print = args
    if success:
        t_count += 1
        if t_count % COUNT_INCREMENT == 0:
            new_t = time.time()
            if do_print:
                print("[%s] %s %s so far (%s at %s keys/sec)" % \
                      (bucket, t_count, action, new_t - t_last, int(COUNT_INCREMENT / (new_t - t_last))))
            t_last = new_t
    elif do_print:
        print("!!ERROR!! [%s] %s ==> %s" % (bucket, action, key))


# noinspection PyMethodMayBeStatic,PyProtectedMember,PyBroadException
class ALCommandLineInterface(cmd.Cmd):  # pylint:disable=R0904

    def __init__(self, show_prompt=True, logger_class=PrintLogger):
        cmd.Cmd.__init__(self)
        self.logger = logger_class()
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
            self.logger.error(msg + "\n")

        if stack_func:
            function_doc = inspect.getdoc(getattr(self, stack_func))
            if function_doc:
                self.logger.info("Function help:\n\n" + function_doc + "\n")

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

        if os.path.exists(dest):
            self.logger.error("Use a different backup directory, this one already exists.")
            return

        try:
            os.makedirs(dest, exist_ok=True)
        except Exception:
            self.logger.error("Cannot make %s folder. Make sure you can write to this folder. "
                              "Maybe you should write your backups in /tmp ?" % dest)
            return

        if system_backup:
            system_buckets = [
                'heuristic',
                'service',
                'service_delta',
                'signature',
                'tc_signature',
                'user',
                'user_avatar',
                'user_favorites',
                'user_settings',
                'vm',
                'workflow'
            ]

            backup_manager = DistributedBackup(dest, worker_count=5, logger=self.logger)

            try:
                backup_manager.backup(system_buckets)
            except KeyboardInterrupt:
                backup_manager.cleanup()
                raise
        else:
            data = self.datastore.get_collection(bucket).search(query, offset=0, rows=1)
            total = data['total']
            if not total:
                self.logger.info("\nNothing in '%s' matches the query:\n\n  %s\n" % (bucket.upper(), query))
                return
            else:
                self.logger.info("\nNumber of items matching this query: %s\n" % data["total"])

            if not force:
                self.logger.info("This is an exemple of the data that will be backuped:\n")
                self.logger.info(f"{data['items'][0]}\n")
                if self.prompt:
                    cont = input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"
                else:
                    self.logger.warn("You are not in interactive mode therefor the backup was not executed. "
                          "Add 'force' to your commandline to execute the backup.")
                    cont = False

                if not cont:
                    self.logger.warn("\n**ABORTED**\n")
                    return

            if follow:
                total *= 100

            worker_count = int(max(2, min(total / 1000, multiprocessing.cpu_count() * 2)))
            backup_manager = DistributedBackup(dest, worker_count=worker_count, logger=self.logger)

            try:
                backup_manager.backup([bucket], follow_keys=follow, query=query)
            except KeyboardInterrupt:
                backup_manager.cleanup()
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

        backup_manager = DistributedBackup(path, worker_count=workers, logger=self.logger)

        try:
            backup_manager.restore()
        except KeyboardInterrupt:
            backup_manager.cleanup()
            raise

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
            collection = self.datastore.get_collection(bucket)

        pool = None
        try:
            cont = force
            test_data = collection.search(query, offset=0, rows=1)
            if not test_data["total"]:
                self.logger.info("Nothing matches the query.")
                return

            if not force:
                self.logger.info(f"\nNumber of items matching this query: {test_data['total']}\n\n")
                self.logger.info("This is an example of the data that will be deleted:\n")
                self.logger.info(f"{test_data['items'][0]}\n")
                if self.prompt:
                    cont = input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"

                    if not cont:
                        self.logger.warn("\n**ABORTED**\n")
                        return
                else:
                    self.logger.warn("You are not in interactive mode therefor the delete was not executed. "
                          "Add 'force' to your commandline to execute the delete.")
                    return

            if cont:
                if full and bucket == 'submission':
                    pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
                    for data in collection.stream_search(query, fl="id", item_buffer_size=COUNT_INCREMENT):
                        pool.apply_async(submission_delete_tree, (data.id, self.logger), callback=action_done)
                else:
                    collection.delete_matching(query)

        except KeyboardInterrupt:
            self.logger.warn("Interrupting jobs...")
            if pool is not None:
                pool.terminate()
                pool.join()

        except Exception as e:
            self.logger.exception("Something when wrong, retry!\n\n %s\n" % e)
        else:
            if pool is not None:
                pool.close()
                pool.join()
            collection.commit()
            self.logger.info(f"Data of bucket '{bucket}' matching query '{query}' has been deleted.")

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

        collection = self.datastore.get_collection('service_delta')

        if action_type == 'list':
            for key in collection.keys():
                self.logger.info(key)
        elif action_type == 'show' and item_id:
            self.logger.info(pformat(self.datastore.get_service_with_delta(item_id, as_obj=False)))
        elif action_type == 'disable' and item_id:
            item = collection.get(item_id)
            if item:
                item.enabled = False
                collection.save(item_id, item)
                self.logger.info(f"{item_id} was disabled")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'enable' and item_id:
            item = collection.get(item_id)
            if item:
                item.enabled = True
                collection.save(item_id, item)
                self.logger.info(f"{item_id} was enabled")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'remove' and item_id:
            collection.delete(item_id)
            service = self.datastore.get_collection('service')
            service.delete_matching(f"name:{item_id}")
            self.logger.info(f"Service '{item_id}' removed.")
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

        signatures = self.datastore.get_collection('signature')

        if action_type == 'show' and item_id:
            self.logger.info(pformat(signatures.get(item_id, as_obj=False)))
        elif action_type == 'change_status' and item_id and id_type and status:
            if status not in YaraParser.STATUSES:
                statuses = "\n".join(YaraParser.STATUSES)
                self._print_error(f"\nInvalid status for action 'change_status' of signature command."
                                  f"\n\nValid statuses are:\n{statuses}")
                return

            if id_type == 'by_id':
                signature = signatures.get(item_id)
                signature.meta.al_status = status
                signatures.save(item_id, signature)
                self.logger.info(f"Signature '{item_id}' was changed to status {status}.")
            elif id_type == 'by_query':
                try:
                    cont = force
                    test_data = signatures.search(item_id, offset=0, rows=1)
                    if not test_data["total"]:
                        self.logger.info("Nothing matches the query.")
                        return

                    if not force:
                        self.logger.info(f'\nNumber of items matching this query: {test_data["total"]}\n\n')
                        self.logger.info("This is an exemple of the signatures that will change status:\n")
                        self.logger.info(f"{test_data['items'][0]}\n")
                        if self.prompt:
                            cont = input("Are your sure you want to continue? (y/N) ")
                            cont = cont == "y"

                            if not cont:
                                self.logger.warn("\n**ABORTED**\n")
                                return
                        else:
                            self.logger.warn("You are not in interactive mode therefor the status change was not executed. "
                                             "Add 'force' to your commandline to execute the status change.")
                            return

                    if cont:
                        updated = signatures.update_by_query(item_id,
                                                             [(signatures.UPDATE_SET, 'meta.al_status', status)])
                        self.logger.info(f"Signatures matching query '{item_id}' were changed to status '{status}'. [{updated}]")

                except KeyboardInterrupt:
                    self.logger.warn("Interrupting jobs...")
                except Exception as e:
                    self.logger.error(f"Something when wrong, retry!\n\n {e}\n")
            else:
                self._print_error("Invalid action parameters for action 'change_status' of signature command.")

        elif action_type == 'remove' and item_id:
            signatures.delete(item_id)
            self.logger.info(f"Signature '{item_id}' removed.")
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
                 set_otp     <uname>
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
            set_otp      Generate a new random OTP secret key for user
            unset_otp    Remove OTP Secret Token
            show_otp     Show current OTP Token

        Parameters:
            <uname>      Username of the user to perform the action on


        Examples:
            # Disable user 'user'
            user disable user
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove',
                         'set_admin', 'unset_admin', 'set_otp', 'unset_otp', 'show_otp']
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

        users = self.datastore.get_collection('user')

        if action_type == 'list':
            for key in users.keys():
                self.logger.info(key)
        elif action_type == 'show' and item_id:
            self.logger.info(pformat(users.get(item_id, as_obj=False)))
        elif action_type == 'disable' and item_id:
            item = users.get(item_id)
            if item:
                item.is_active = False
                users.save(item_id, item)
                self.logger.info(f"{item_id} was disabled")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'enable' and item_id:
            item = users.get(item_id)
            if item:
                item.is_active = True
                users.save(item_id, item)
                self.logger.info(f"{item_id} was enabled")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'set_admin' and item_id:
            item = users.get(item_id)
            if item:
                item.is_admin = True
                users.save(item_id, item)
                self.logger.info(f"{item_id} was added admin priviledges")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'unset_admin' and item_id:
            item = users.get(item_id)
            if item:
                item.is_admin = False
                users.save(item_id, item)
                self.logger.info(f"{item_id} was removed admin priviledges")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'remove' and item_id:
            users.delete(item_id)
            self.logger.info(f"User '{item_id}' removed.")
        elif action_type == 'unset_otp' and item_id:
            item = users.get(item_id, as_obj=False)
            if item:
                item.pop('otp_sk', None)
                users.save(item_id, item)
                self.logger.info(f"{item_id} OTP secret key was removed")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'set_otp' and item_id:
            item = users.get(item_id)
            if item:
                item.otp_sk = generate_random_secret()
                users.save(item_id, item)
                self.logger.info(f"{item_id} OTP secret key is now: {item.otp_sk}")
            else:
                self.logger.warn(f"{item_id} does not exist")
        elif action_type == 'show_otp' and item_id:
            item = users.get(item_id)
            if item:
                if item.otp_sk:
                    while True:
                        self.logger.info('\r%s OTP Token:   %06d   %s%s' % (item_id, get_totp_token(item.otp_sk),
                                                                 "█" * int(time.time() % 30),
                                                                 "░" * (29 - int(time.time() % 30)))),
                        sys.__stdout__.flush()

                        time.sleep(1)
                else:
                    self.logger.warn(f"2FA not enabled for user {item_id}")
            else:
                self.logger.warn(f"{item_id} does not exist")
        else:
            self._print_error("Invalid command parameters")

    def do_index(self, args):
        """
        Perform operations on the search index

        Usage:
            index commit   [<bucket>]
                  reindex  [<bucket>]

        Actions:
            commit       Force SOLR to commit the index
            reindex      Force a reindex of all the database (this can be really slow)

        Parameters:
            <bucket>     Bucket to do the operation on [optional]


        Examples:
            # Force commit on file bucket
            index commit file
            # Force commit on all bucket
            index commit
        """

        valid_buckets = list(self.datastore.ds.get_models().keys())
        valid_actions = ['commit', 'reindex']

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
                collection = self.datastore.get_collection(bucket)
                self.logger.info(f"Reindexing {bucket.upper()} ...")
                collection.reindex()
                self.logger.info("    Done!")
            else:
                for bucket in valid_buckets:
                    collection = self.datastore.get_collection(bucket)
                    self.logger.info(f"Reindexing {bucket} ...")
                    collection.reindex()
                    self.logger.info("    Done!")
        elif action_type == 'commit':
            if bucket:
                collection = self.datastore.get_collection(bucket)
                collection.commit()
                self.logger.info(f"Index {bucket.upper()} was commited.")
            else:
                self.logger.info("Forcing commit procedure for all indexes...")
                for bucket in valid_buckets:
                    collection = self.datastore.get_collection(bucket)
                    collection.commit()
                    self.logger.info(f"    Index {bucket.upper()} was commited.")
                self.logger.info("All indexes commited.")

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
        valid_buckets = list(self.datastore.ds.get_models().keys())

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
            if bucket not in valid_buckets:
                self._print_error("\nInvalid bucket: %s\n\n"
                                  "Valid buckets are:\n%s" % (bucket, "\n".join(valid_buckets)))
                return

            self.datastore.get_collection(bucket).wipe()
            self.logger.info(f"Done wipping {bucket.upper()}.")
        elif action_type == 'non_system':
            non_system_buckets = [
                'alert', 'cached_file', 'emptyresult', 'error', 'file', 'filescore', 'result',
                'submission', 'submission_tree', 'submission_tags', 'workflow'
            ]
            for bucket in non_system_buckets:
                self.datastore.get_collection(bucket).wipe()
                self.logger.info(f"Done wipping {bucket.upper()}.")
        elif action_type == 'submission_data':
            submission_data_buckets = ['emptyresult', 'error', 'file', 'filescore', 'result',
                                       'submission', 'submission_tree', 'submission_tags']
            for bucket in submission_data_buckets:
                self.datastore.get_collection(bucket).wipe()
                self.logger.info(f"Done wipping {bucket.upper()}.")
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

        backup_file = f"/tmp/al_backup_{get_random_id()}"
        self.do_backup(backup_file)

        system_buckets = [
            'heuristic',
            'service',
            'service_delta',
            'signature',
            'tc_signature',
            'user',
            'user_avatar',
            'user_favorites',
            'user_settings',
            'vm',
            'workflow'
        ]
        if full:
            data_buckets = [
                'alert',
                'cached_file',
                'emptyresult',
                'error',
                'file',
                'filescore',
                'result',
                'submission',
                'submission_tree',
                'submission_tags'
            ]
            system_buckets += data_buckets

        self.logger.info("\nWiping all buckets:")
        for bucket in sorted(system_buckets):
            self.datastore.get_collection(bucket).wipe()
            self.logger.info(f"    {bucket.upper()} wiped.")

        self.do_restore(backup_file)
        self.do_index("commit")
        shutil.rmtree(backup_file)
        self.logger.info("\nData reset completed.\n")

    def do_ui(self, args):
        """
        Perform UI related operations

        Usage:
            ui show_sessions [username]
            ui clear_sessions [username]

        actions:
            show_sessions      show all active sessions
            clear_sessions     Removes all active sessions

        Parameters:
            username           User use to filter sessions
                               [optional]

        Examples:
            # Clear sessions for user bob
            ui clear_sessions bob

            # Show all current sessions
            ui show_sessions
        """
        valid_func = ['clear_sessions', 'show_sessions']
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
                self.logger.info("All sessions where cleared.")
            else:
                for k, v in flsk_sess.items().items():
                    if v.get('username', None) == username:
                        self.logger.info(f"Removing session: {v}")
                        flsk_sess.pop(k)

                self.logger.info(f"All sessions for user '{username}' removed.")
        if func == 'show_sessions':
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
                for k, v in flsk_sess.items().items():
                    self.logger.info(f"{v.get('username', None)} => {v}")
            else:
                self.logger.info(f'Showing sessions for user {username}:')
                for k, v in flsk_sess.items().items():
                    if v.get('username', None) == username:
                        self.logger.info(f"    {v}")


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
