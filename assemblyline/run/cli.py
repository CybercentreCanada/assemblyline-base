#!/usr/bin/env python
# coding=utf-8

import cmd
import inspect
import io
import os
import multiprocessing
import re
import time
import signal
import shutil
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from tempfile import gettempdir

import yaml
import datemath

from assemblyline.common import forge, log as al_log
from assemblyline.common.backupmanager import DistributedBackup
from assemblyline.common.cleanup_filestore import cleanup_filestore
from assemblyline.common.security import get_totp_token, generate_random_secret
from assemblyline.common.uid import get_random_id
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.common.dict_utils import flatten
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.filestore import create_transport
from assemblyline.odm.models.signature import RULE_STATUSES
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
    def info(msg, *args, **kwargs):
        pass

    @staticmethod
    def warning(msg, *args, **kwargs):
        pass

    @staticmethod
    def warn(msg, *args, **kwargs):
        pass

    @staticmethod
    def error(msg, *args, **kwargs):
        pass

    @staticmethod
    def exception(msg, *args, **kwargs):
        pass


class IndentedPrintLogger():
    @staticmethod
    def info(msg, end=None):
        print(f"    {msg}", end=end)

    @staticmethod
    def warning(msg, end=None):
        print(f"    [W] {msg}", end=end)

    @staticmethod
    def warn(msg, end=None):
        print(f"    [W] {msg}", end=end)

    @staticmethod
    def error(msg, end=None):
        print(f"    [E] {msg}", end=end)

    @staticmethod
    def exception(msg, end=None):
        print(f"    [EX] {msg}", end=end)


class PrintLogger(object):
    @staticmethod
    def info(msg, end=None):
        print(msg, end=end)

    @staticmethod
    def warning(msg, end=None):
        print(f"[W] {msg}", end=end)

    @staticmethod
    def warn(msg, end=None):
        print(f"[W] {msg}", end=end)

    @staticmethod
    def error(msg, end=None):
        print(f"[E] {msg}", end=end)

    @staticmethod
    def exception(msg, end=None):
        print(f"[EX] {msg}", end=end)


def init():
    global DATASTORE
    DATASTORE = forge.get_datastore(archive_access=True)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def submission_delete_tree(key, logger):
    try:
        with forge.get_filestore() as f_transport:
            # noinspection PyUnresolvedReferences
            DATASTORE.delete_submission_tree(key, transport=f_transport)
    except Exception as e:
        logger.error(e)
        return "DELETE", "submission", key, False, isinstance(logger, PrintLogger)

    return "deleted", "submission", key, True, isinstance(logger, PrintLogger)


def action_done(args):
    global t_count, t_last, COUNT_INCREMENT
    action, index, key, success, do_print = args
    if success:
        t_count += 1
        if t_count % COUNT_INCREMENT == 0:
            new_t = time.time()
            if do_print:
                print(f"[{index}] {t_count} {action} so far ({new_t - t_last}"
                      f" at {int(COUNT_INCREMENT / (new_t - t_last))} keys/sec)")
            t_last = new_t
    elif do_print:
        print(f"!!ERROR!! [{index}] {action} ==> {key}")


# noinspection PyMethodMayBeStatic,PyProtectedMember,PyBroadException
class ALCommandLineInterface(cmd.Cmd):  # pylint:disable=R0904

    def __init__(self, show_prompt=True, logger_class=PrintLogger):
        cmd.Cmd.__init__(self)
        self.logger = logger_class()
        self.prompt = ""
        self.intro = ""
        self.datastore = forge.get_datastore(archive_access=True)
        self.config = forge.get_config()
        if show_prompt:
            self._update_context()
        self._platform = sys.platform
        self._cmd_lex = None

    def _update_context(self):
        self.prompt = '(al_cli) $ '
        self.intro = 'AL 4.0 - Console. (type help).'

    def _compile_cmd_lex(self):
        """Compiles regular expression for for command-line splitting.
        For use with subprocess, for argv injection etc. Using fast REGEX.

        self._platform: auto from current platform;
                        'win32' = Windows/CMD
                        'linux', etc. = POSIX
        """

        if self._platform != 'win32':
            self._cmd_lex = re.compile(r'''"
            ((?:\\["\\]|[^"])*)"|       # quoted string
            '([^']*)'|                  # quoted single string
            (\\.)|                      # escaped string
            (&&?|\|\|?|\d?>|[<])|      # pipes and other command continuation
            ([^\s'"\\&|<>]+)|           # words
            (\s+)|                      # whitespace
            (.)                         # fail
            ''', re.VERBOSE)
        else:
            self._cmd_lex = re.compile(r'''
            "((?:""|\\["\\]|[^"])*)"|   # quoted string
            (\\\\(?=\\*")|\\")|         # escaped string
            (&&?|\|\|?|\d?>|[<])|       # pipes and other command continuation
            ([^\s"&|<>]+)|              # words
            (\s+)|                      # whitespace
            (.)                         # fail
            ''', re.VERBOSE)

    def _parse_args(self, s):
        """Multi-platform variant of shlex.split() for command-line splitting.
        For use with subprocess, for argv injection etc. Using fast compiled class REGEX.
        """
        if self._cmd_lex is None:
            self._compile_cmd_lex()

        args = []
        accu = None  # collects pieces of one arg
        for qs, qss, esc, pipe, word, white, fail in self._cmd_lex.findall(s):
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
                if self._platform == "win32":
                    word = word.replace('""', '"')
            else:
                word = qss  # may be even empty; must be last

            accu = (accu or '') + word

        if accu is not None:
            args.append(accu)

        return args

    def _get_completion_list(self, text, line, collection_name,
                             valid_actions=None, terminal_actions=None, multiple_actions=None):
        """
        Helper for command completion for subcommands that take no arguments, take one argument,
        or multiple arguments of the same type.
        """
        if terminal_actions is None:
            terminal_actions = []
        if valid_actions is None:
            valid_actions = []
        if multiple_actions is None:
            multiple_actions = []

        args = self._parse_args(line)
        if text == '':
            # Because _parse_args strips trailing spaces
            args.append(text)

        if len(args) == 2:
            return [i for i in valid_actions if i.startswith(text)]
        elif len(args) >= 3:
            if args[1] in terminal_actions:
                return []
            collection = self.datastore.get_collection(collection_name)
            if collection:
                if len(args) == 3:
                    return [i for i in collection.keys() if i.startswith(text)]
                if args[1] in multiple_actions:
                    return [i for i in collection.keys() if i.startswith(text) and i not in args[2:-1]]
        return []

    def _print_error(self, msg):
        stack_func = None
        stack = inspect.stack()
        for item in stack:
            if 'cli.py' in item[1] and '_print_error' not in item[3]:
                stack_func = item[3]
                break

        if msg:
            self.logger.error(f"{msg}\n")

        if stack_func:
            function_doc = inspect.getdoc(getattr(self, stack_func))
            if function_doc:
                self.logger.info(f"Function help:\n\n{function_doc}\n")

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
                   <destination_folder> <index_name> [follow] [force] <query>

        Parameters:
            <destination_folder> Path to the destination folder [required]

            <index_name>         Name of the index to backup [required in backup by query]

            follow               Follow IDs to backup more then the specified index
                                 [optional, only used in backup by query]

            force                Automatically perform backup without asking for confirmation
                                 [optional, only used in backup by query]

            <query>              Query that the data need to match
                                 [optional, only used in backup by query]

        Examples:
            # Create a backup of the system indices
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
            index = None
            follow = False
            query = None
        elif len(args) == 3:
            dest, index, query = args
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
            temp_dir = gettempdir()
            self.logger.error(f"Cannot make {dest!s} folder. Make sure you can write to this folder.\n"
                              f"Maybe you should write your backups in {temp_dir} ?")
            return

        if system_backup:
            system_indices = [
                'heuristic',
                'service',
                'service_delta',
                'signature',
                'user',
                'user_avatar',
                'user_favorites',
                'user_settings',
                'workflow'
            ]

            backup_manager = DistributedBackup(dest, worker_count=5, logger=self.logger)

            try:
                backup_manager.backup(system_indices)
            except KeyboardInterrupt:
                backup_manager.cleanup()
                raise
        else:
            data = self.datastore.get_collection(index).search(query, offset=0, rows=1)
            total = data['total']
            if not total:
                self.logger.info(f"\nNothing in '{index.upper()}' matches the query:\n\n  {query}\n")
                try:
                    os.rmdir(dest)
                except Exception:
                    self.logger.error(f"Cannot remove backup destination folder '{dest}'.")
                return
            else:
                self.logger.info(f"\nNumber of items matching this query: {data['total']}\n")

            if not force:
                self.logger.info("This is an example of the data that will be backed up:\n")
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
                    try:
                        os.rmdir(dest)
                    except Exception:
                        self.logger.error(f"Cannot remove backup destination folder '{dest}'.")
                    return

            if follow:
                total *= 100

            worker_count = int(max(2, min(total / 1000, multiprocessing.cpu_count() * 2)))
            backup_manager = DistributedBackup(dest, worker_count=worker_count, logger=self.logger)

            try:
                backup_manager.backup([index], follow_keys=follow, query=query)
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
            suffix_check = f".part{part_num:d}"
            if not any(suffix_check in x for x in bak_files):
                self._print_error(f"{workers:d} files exist, but no file ending with {suffix_check} found. ")
                return

        backup_manager = DistributedBackup(path, worker_count=workers, logger=self.logger)

        try:
            backup_manager.restore()
        except KeyboardInterrupt:
            backup_manager.cleanup()
            raise

    def do_delete(self, args):
        """
        Delete all data from a index that match a given query

        Usage:
            delete <index> [full] [force] <query>

        Parameters:
            <index>   Name of the index to delete from
            full      Follow IDs and remap classification
                      [Optional: Only work while deleting submissions]
            force     Automatically perform deletion without asking for confirmation [optional]
            <query>   Query to run to find the data to delete

        Examples:
            # Delete all submission for "user" with all associated results
            delete submission full "params.submitter:user"
        """
        valid_indices = list(self.datastore.ds.get_models().keys())
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

        index, query = args

        if index not in valid_indices:
            index_list = '\n'.join(valid_indices)
            self._print_error(f"\nInvalid index specified: {index}\n\nValid indices are:\n{index_list}")
            return
        else:
            collection = self.datastore.get_collection(index)

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
                    self.logger.warn("You are not in interactive mode, therefore the delete was not executed. "
                                     "Add 'force' to your commandline to execute the delete.")
                    return

            if cont:
                if full and index == 'submission':
                    pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
                    for data in collection.stream_search(query, fl="id", item_buffer_size=COUNT_INCREMENT):
                        pool.apply_async(submission_delete_tree, (data.id, self.logger), callback=action_done)
                else:
                    collection.delete_by_query(query)

        except KeyboardInterrupt:
            self.logger.warn("Interrupting jobs...")
            if pool is not None:
                pool.terminate()
                pool.join()

        except Exception as e:
            self.logger.exception(f"Something went wrong, retry!\n\n {e}\n")
        else:
            if pool is not None:
                pool.close()
                pool.join()
            collection.commit()
            self.logger.info(f"Data of index '{index}' matching query '{query}' has been deleted.")

    def do_service(self, args):
        """
        Perform operation on the different services on the system

        Usage:
            service list
                    cleanup
                    show    <name>
                    disable <name>
                    enable  <name>
                    remove  <name>

        Actions:
            list      List all services on the system
            cleanup   Remove services incompatible with your version
                      and fix all service deltas
            disable   Disable the service in the system
            enable    Enable the service in the system
            remove    Remove the service from the system
            show      Show the service description

        Parameters:
            <name>   Name of the service to perform the action on

        Examples:
            # Show service 'Extract'
            service show Extract
        """
        valid_actions = ['list', 'cleanup', 'show', 'disable', 'enable', 'remove']
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
            return
        elif action_type == 'cleanup':
            self.logger.info("Validating services deltas...")
            versions = set()
            for key in collection.keys():
                self.logger.info(f"\t{key}")
                svc_data = collection.get(key)
                versions.add(f"{key}_{svc_data.version}")
                collection.save(key, svc_data)

            self.logger.info("Validating installed services...")
            system_version = f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}."
            to_del = []
            svc_col = self.datastore.get_collection('service')
            for key in svc_col.keys():
                svc_data = svc_col.get(key)
                if not svc_data.version.startswith(system_version) and key not in versions:
                    to_del.append(key)
                else:
                    svc_col.get(key, svc_data)

            self.logger.info("Removing services not matching your system...")
            for svc_vers in to_del:
                self.logger.info(f"\t{svc_vers}")
                svc_col.delete(svc_vers)
            self.logger.info("Done!")
            return

        if item_id:
            item = collection.get(item_id)
            if item is None:
                self.logger.warn(f"{item_id} does not exist")
                return
        else:
            self._print_error("Invalid command parameters")
            return

        if action_type == 'show':
            output = io.StringIO()
            yaml.safe_dump(self.datastore.get_service_with_delta(item_id, as_obj=False), output)
            self.logger.info(output.getvalue())
        elif action_type == 'disable':
            item.enabled = False
            collection.save(item_id, item)
            self.logger.info(f"{item_id} was disabled")
        elif action_type == 'enable':
            item.enabled = True
            collection.save(item_id, item)
            self.logger.info(f"{item_id} was enabled")
        elif action_type == 'remove':
            collection.delete(item_id)
            service = self.datastore.get_collection('service')
            service.delete_by_query(f"name:{item_id}")
            self.logger.info(f"Service '{item_id}' removed.")

    def complete_service(self, text, line, begidx, endidx):
        """
        Command completion for the 'service' command
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove']
        terminal_actions = ['list']
        multiple_actions = []

        return self._get_completion_list(text, line, 'service_delta', valid_actions, terminal_actions, multiple_actions)

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
            output = io.StringIO()
            yaml.safe_dump(signatures.get(item_id, as_obj=False), output)
            self.logger.info(output.getvalue())
        elif action_type == 'change_status' and item_id and id_type and status:
            if status not in RULE_STATUSES:
                statuses = "\n".join(RULE_STATUSES)
                self._print_error(f"\nInvalid status for action 'change_status' of signature command."
                                  f"\n\nValid statuses are:\n{statuses}")
                return

            if id_type == 'by_id':
                signature = signatures.get(item_id)
                signature.status = status
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
                        self.logger.info("This is an example of the signatures that will change status:\n")
                        self.logger.info(f"{test_data['items'][0]}\n")
                        if self.prompt:
                            cont = input("Are your sure you want to continue? (y/N) ")
                            cont = cont == "y"

                            if not cont:
                                self.logger.warn("\n**ABORTED**\n")
                                return
                        else:
                            self.logger.warn("You are not in interactive mode, "
                                             "therefore the status change was not executed. "
                                             "Add 'force' to your commandline to execute the status change.")
                            return

                    if cont:
                        updated = signatures.update_by_query(item_id,
                                                             [(signatures.UPDATE_SET, 'status', status)])
                        self.logger.info(f"Signatures matching query '{item_id}' were changed "
                                         f"to status '{status}'. [{updated}]")

                except KeyboardInterrupt:
                    self.logger.warn("Interrupting jobs...")
                except Exception as e:
                    self.logger.error(f"Something went wrong, retry!\n\n {e}\n")
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
            set_admin    Grant a user admin privileges
            unset_admin  Revoke a user's admin privileges
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
            return
        if item_id:
            item = users.get(item_id)
            if item is None:
                self.logger.warn(f"{item_id} does not exist")
                return
        else:
            self._print_error("Invalid command parameters")
            return

        if action_type == 'show':
            output = io.StringIO()
            yaml.safe_dump(item.as_primitives(), output)
            self.logger.info(output.getvalue())
        elif action_type == 'disable':
            item.is_active = False
            users.save(item_id, item)
            self.logger.info(f"{item_id} was disabled")
        elif action_type == 'enable':
            item.is_active = True
            users.save(item_id, item)
            self.logger.info(f"{item_id} was enabled")
        elif action_type == 'set_admin':
            if 'admin' not in item.type:
                item.type.append('admin')
                users.save(item_id, item)
            self.logger.info(f"Granted admin privileges to {item_id}")
        elif action_type == 'unset_admin':
            if 'admin' in item.type:
                item.type.remove('admin')
                users.save(item_id, item)
            self.logger.info(f"Admin privileges revoked for {item_id}")
        elif action_type == 'remove':
            users.delete(item_id)
            self.logger.info(f"User '{item_id}' removed.")
        elif action_type == 'unset_otp':
            item.otp_sk = None
            users.save(item_id, item)
            self.logger.info(f"{item_id} OTP secret key was removed")
        elif action_type == 'set_otp':
            item.otp_sk = generate_random_secret()
            users.save(item_id, item)
            self.logger.info(f"{item_id} OTP secret key is now: {item.otp_sk}")
        elif action_type == 'show_otp':
            if item.otp_sk:
                try:
                    while True:
                        self.logger.info('\r{!s} OTP Token:   {:06d}   {:░<30}'.format(
                            item_id,
                            get_totp_token(item.otp_sk),
                            "█" * int(time.time() % 30)),
                            end=''
                        ),
                        sys.__stdout__.flush()
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.logger.info('')
            else:
                self.logger.warn(f"2FA not enabled for user {item_id}")

    def complete_user(self, text, line, begidx, endidx):
        """
        Command completion for the 'user' command
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove',
                         'set_admin', 'unset_admin', 'set_otp', 'unset_otp', 'show_otp']
        terminal_actions = ['list']
        multiple_actions = []

        return self._get_completion_list(text, line, 'user', valid_actions, terminal_actions, multiple_actions)

    def do_index(self, args):
        """
        Perform operations on the database index.

        ** Do not use these operations unless you absolutely have to as they may slow down
           considerably your system and some of these operations may result in dataloss if
           something went wrong in the middle of it.

        Usage:
            index commit               [<safe>] [<index>]
                  reindex              [<safe>] [<index>]
                  fix_ilm              [<safe>] [<index>]
                  fix_replicas         [<safe>] [<index>]
                  fix_shards           [<safe>] [<index>]
                  restore_old_archive  [<safe>] [<index>]

        Actions:
            commit               Force datastore to commit the specified index
            reindex              Force a reindex of the sepcified index
                                    ** This operation is really slow because it re-index all documents
            fix_ilm              Fix ILM on specified indices
                                    ** This operation can be really slow when going from an ILM setup to a hot
                                       archive only setup because it will copy the archive to hot index
            fix_replicas         Fix replica count on specified indices
            fix_shards           Fix sharding on specified indices
                                    ** This operation can be slow and will prevent data from being written
                                       the cluster while it is hapenning.
            restore_old_archive  Restaure all documents from the old archiving method into the hot index

        Parameters:
            <safe>       Does not validate the model [optional]
            <index>      index to do the operation on [optional]


        Examples:
            # Force commit on file index
            index commit file
            # Force commit on all index
            index commit
        """

        valid_indices = list(self.datastore.ds.get_models().keys())
        valid_actions = ['commit', 'reindex', 'fix_shards', 'fix_ilm', 'fix_replicas', 'restore_old_archive']

        args = self._parse_args(args)

        safe = False
        if 'safe' in args:
            safe = True
            args.remove('safe')

        if len(args) == 1:
            action_type = args[0]
            index = None
        elif len(args) == 2:
            action_type, index = args
        else:
            self._print_error("Wrong number of arguments for index command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: {}\n\n"
                              "Valid actions are:\n{}".format(action_type, "\n".join(valid_actions)))
            return

        if index and index not in valid_indices:
            self._print_error("\nInvalid index specified: {}\n\n"
                              "Valid indices are:\n{}".format(index, "\n".join(valid_indices)))
            return

        if safe:
            self.datastore.stop_model_validation()

        try:
            if action_type == 'reindex':
                if index:
                    collection = self.datastore.get_collection(index)
                    self.logger.info(f"Reindexing {index.upper()} ...")
                    collection.reindex()
                    self.logger.info("    Done!")
                else:
                    for index in valid_indices:
                        collection = self.datastore.get_collection(index)
                        self.logger.info(f"Reindexing {index} ...")
                        collection.reindex()
                        self.logger.info("    Done!")
            elif action_type == 'commit':
                if index:
                    collection = self.datastore.get_collection(index)
                    collection.commit()
                    self.logger.info(f"Index {index.upper()} was committed.")
                else:
                    self.logger.info("Forcing commit procedure for all indexes...")
                    for index in valid_indices:
                        collection = self.datastore.get_collection(index)
                        collection.commit()
                        self.logger.info(f"    Index {index.upper()} was commited.")
                    self.logger.info("All indexes committed.")
            elif action_type == 'fix_shards':
                indices = []
                if index:
                    self.logger.info(f"Fixing shards on index {index.upper()}...")
                    indices.append(index)
                else:
                    self.logger.info("Fixing shards on all indices...")
                    indices = valid_indices

                for index in indices:
                    collection = self.datastore.get_collection(index)
                    collection.fix_shards(logger=IndentedPrintLogger()
                                          if isinstance(self.logger, PrintLogger) else self.logger)
                    self.logger.info(f"    Index {index.upper()} shards configuration updated.")

                self.logger.info("Completed!")
            elif action_type == 'fix_ilm':
                indices = []
                if index:
                    self.logger.info(f"Fixing ILM on index {index.upper()}...")
                    indices.append(index)
                else:
                    self.logger.info("Fixing ILM on all indices...")
                    indices = valid_indices

                for index in indices:
                    collection = self.datastore.get_collection(index)
                    collection.fix_ilm()
                    self.logger.info(f"    Index {index.upper()} ILM configuration updated.")
            elif action_type == 'fix_replicas':
                indices = []
                if index:
                    self.logger.info(f"Fixing replicas on index {index.upper()}...")
                    indices.append(index)
                else:
                    self.logger.info("Fixing replicas on all indices...")
                    indices = valid_indices

                for index in indices:
                    collection = self.datastore.get_collection(index)
                    collection.fix_replicas()
                    self.logger.info(f"    Index {index.upper()} replicas configuration updated.")

                self.logger.info("Completed!")
            elif action_type == 'restore_old_archive':
                indices = []
                if index:
                    self.logger.info(f"Restoring old archive documents on index {index.upper()}...")
                    indices.append(index)
                else:
                    self.logger.info("Restoring old archive documents on all indices...")
                    indices.extend(['alert', 'error', 'file', 'result', 'submission'])

                for index in indices:
                    collection = self.datastore.get_collection(index)
                    count = collection.restore_old_archive()
                    self.logger.info(f"    {count} document(s) were restored into index {index.upper()}.")

                self.logger.info("Completed!")
        finally:
            self.datastore.start_model_validation()

    def do_wipe(self, args):
        """
        Wipe all data from one or many indices

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            wipe index <index_name>
                 non_system
                 submission_data

        Actions:
            index           Single index wipe mode
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
            <index_name>  Name of the index to wipe

        Examples:
            # Wipe all files
            wipe index file
        """
        args = self._parse_args(args)
        valid_actions = ['index', 'non_system', 'submission_data']
        valid_indices = list(self.datastore.ds.get_models().keys())

        if len(args) == 1:
            action_type = args[0]
            index = None
        elif len(args) == 2:
            action_type, index = args
        else:
            self._print_error("Wrong number of arguments for wipe command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: {}\n\n"
                              "Valid actions are:\n{}".format(action_type, "\n".join(valid_actions)))
            return

        if action_type == 'index':
            if index not in valid_indices:
                self._print_error("\nInvalid index: {}\n\n"
                                  "Valid indices are:\n{}".format(index, "\n".join(valid_indices)))
                return

            self.datastore.get_collection(index).wipe()
            self.logger.info(f"Done wiping {index.upper()}.")
        elif action_type == 'non_system':
            non_system_indices = [
                'alert', 'cached_file', 'emptyresult', 'error', 'file', 'filescore', 'result',
                'submission', 'submission_tree', 'submission_summary', 'workflow'
            ]
            for index in non_system_indices:
                self.datastore.get_collection(index).wipe()
                self.logger.info(f"Done wipping {index.upper()}.")
        elif action_type == 'submission_data':
            submission_data_indices = ['emptyresult', 'error', 'file', 'filescore', 'result',
                                       'submission', 'submission_tree', 'submission_summary']
            for index in submission_data_indices:
                self.datastore.get_collection(index).wipe()
                self.logger.info(f"Done wipping {index.upper()}.")
        else:
            self._print_error("Invalid command parameters")

    def do_data_reset(self, args):
        """
        Completely resets the database. Does a backup of the system data, wipe every indices then
        restores the backup.

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            data_reset [full]

        Parameters:
            full   Does not just wipe the system index, also wipe all submissions and results

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

        system_indices = [
            'heuristic',
            'service',
            'service_delta',
            'signature',
            'user',
            'user_avatar',
            'user_favorites',
            'user_settings',
            'workflow'
        ]
        if full:
            data_indices = [
                'alert',
                'cached_file',
                'emptyresult',
                'error',
                'file',
                'filescore',
                'result',
                'submission',
                'submission_tree',
                'submission_summary'
            ]
            system_indices += data_indices

        self.logger.info("\nWiping all indices:")
        for index in sorted(system_indices):
            self.datastore.get_collection(index).wipe()
            self.logger.info(f"    {index.upper()} wiped.")

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
            self._print_error(f"Invalid action '{func}' for ui command.")
            return

        if func == 'clear_sessions':
            username = None
            if len(args) == 2:
                username = args[1]

            flsk_sess = Hash(
                "flask_sessions",
                host=config.core.redis.nonpersistent.host,
                port=config.core.redis.nonpersistent.port
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
                port=config.core.redis.nonpersistent.port
            )

            if not username:
                for k, v in flsk_sess.items().items():
                    self.logger.info(f"{v.get('username', None)} => {v}")
            else:
                self.logger.info(f'Showing sessions for user {username}:')
                for k, v in flsk_sess.items().items():
                    if v.get('username', None) == username:
                        self.logger.info(f"    {v}")

    def do_filestore(self, args):
        """
        Perform filestore related operations

        Usage:
            filestore gc

        actions:
            gc      Try to find and erase filestore entries that shouldn't be there

        """
        valid_func = ['gc']
        args = self._parse_args(args)

        if len(args) != 1:
            self._print_error("Wrong number of arguments for filestore command.")
            return

        func = args[0]
        if func not in valid_func:
            self._print_error(f"Invalid action '{func}' for filestore command.")
            return

        if func == 'gc':
            transports = []
            transports += self.config.filestore.storage
            transports += self.config.filestore.cache

            for transport_url in set(transports):
                info = cleanup_filestore(transport_url=transport_url)
                transport = create_transport(transport_url)
                self.logger.info(str(transport) + ' ' + info)

    def do_expiry(self, args):
        """
        Operations related to the data expiry system.

        Usage:
            expiry fix [index]

        actions:
            fix      Try to correct corrupted expiry values on the given index or "all".

        """
        valid_func = ['fix']
        args = self._parse_args(args)

        if len(args) != 2:
            self._print_error("Wrong number of arguments for expiry command.")
            return

        func = args[0]
        if func not in valid_func:
            self._print_error(f"Invalid action '{func}' for expiry command.")
            return

        # Do nothing if expiry isn't as expected for these collections
        ignore_indices = [
            'cached_file'
        ]

        # Delete entries where expiry isn't as expected for these collections
        cache_indices = [
            'filescore',
            'submission_tree',
            'submission_summary',
            'emptyresult',
        ]

        # Fix the expiry key where it isn't as expected for these collections
        read_date_keys = {
            'submission': 'times.submitted',
            'file': 'seen.last',
            'result': 'created',
            'alert': 'reporting_ts',
            'error': 'created',
        }

        # For future proof reasons, log any tables with expiry not included in lists of index names
        active_indices = cache_indices + list(read_date_keys.keys())
        covered_indices = ignore_indices + active_indices
        for name, definition in self.datastore.ds.get_models().items():
            if hasattr(definition, 'expiry_ts'):
                if name not in covered_indices:
                    self.logger.warning(f"Datastore index {name} not handled by script.")

        # See which index they are asking for
        index_name: str = args[1]
        if index_name == 'all':
            index_names = active_indices
        else:
            if index_name not in active_indices:
                self._print_error(f"index '{index_name}' does nothing with this command.")
                return
            index_names = [index_name]

        if func == 'fix':
            # Check if there is a max dtl set
            max_dtl = self.config.submission.max_dtl
            if not max_dtl:
                self._print_error("System without a max_dtl configured do nothing with this command.")
                return

            # Our search query will always be for documents missing expiry, or
            # documents where expiry is outside of configured bounds
            query = f"(NOT _exists_:expiry_ts) OR expiry_ts: [now+{max_dtl}d TO *]"

            for name in index_names:
                # For each collection we have a date key to update with, do a stream search
                # and update each document with a new expiry
                if name in read_date_keys:
                    date_key = read_date_keys[name]
                    collection = self.datastore.get_collection(name)
                    pool = ThreadPoolExecutor(50)

                    def update(keys):
                        keys = flatten(keys)
                        if keys.get(date_key):
                            base_date = self.datastore.ds.to_pydatemath(keys[date_key])
                        else:
                            base_date = 'now'
                        new_expiry = epoch_to_iso(datemath.dm(f'{base_date}+{max_dtl}d').float_timestamp)
                        collection.update(keys['id'], [(collection.UPDATE_SET, 'expiry_ts', new_expiry)])

                    futures = []
                    for keys in collection.stream_search(query, as_obj=False, fl='id,'+date_key):
                        futures.append(pool.submit(update, keys))

                    for future in as_completed(futures):
                        future.result()

                # For each collection where we don't, but have a cache storage
                # character, just delete any suspicious entries
                if name in cache_indices:
                    collection = self.datastore.get_collection(name)
                    collection.delete_by_query(query)


def print_banner():
    from assemblyline.common import banner
    print(banner.BANNER)


def shell_main():
    cli = ALCommandLineInterface(len(sys.argv) == 1)

    if len(sys.argv) != 1:
        cli.onecmd(" ".join([{True: f'"{x}"', False: x}[" " in x] for x in sys.argv[1:]]))
    else:
        print_banner()
        cli.cmdloop()


if __name__ == '__main__':
    try:
        shell_main()
    except KeyboardInterrupt:
        exit()
