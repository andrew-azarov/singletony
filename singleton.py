#! /usr/bin/env python

import sys
import os
import tempfile
import logging
import errno
import unittest


def pid_exists(pid):
    """Check whether pid exists in the current process table."""
    # http://stackoverflow.com/a/23409343/2010538
    # http://stackoverflow.com/a/28065945/2010538
    if os.name != 'nt':
        import errno
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except OSError as e:
            return e.errno == errno.EPERM
        else:
            return True
    else:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        HANDLE = ctypes.c_void_p
        DWORD = ctypes.c_ulong
        LPDWORD = ctypes.POINTER(DWORD)

        class ExitCodeProcess(ctypes.Structure):
            _fields_ = [('hProcess', HANDLE),
                        ('lpExitCode', LPDWORD)]

        PROCESS_QUERY_INFORMATION = 0x1000
        process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
        if not process:
            return False

        ec = ExitCodeProcess()
        out = kernel32.GetExitCodeProcess(process, ctypes.byref(ec))
        if not out:
            err = kernel32.GetLastError()
            if kernel32.GetLastError() == 5:
                # Access is denied.
                logger.warning("Access is denied to get pid info.")
            kernel32.CloseHandle(process)
            return False
        elif bool(ec.lpExitCode):
            # print ec.lpExitCode.contents
            # There is an exit code, it quit
            kernel32.CloseHandle(process)
            return False
        # No exit code, it's running.
        kernel32.CloseHandle(process)
        return True


class SingleInstanceException(BaseException):
    pass


class SingleInstance:

    """
    If you want to prevent your script from running in parallel just instantiate
    SingleInstance() class. If is there another instance already running it will
    throw a `SingleInstanceException`.

    >>> import tendosingleton
    ... me = SingleInstance()

    This option is very useful if you have scripts executed by crontab at small
    amounts of time.

    Remember that this works by creating a lock file with a filename based on the
    full path to the script file.

    Providing a flavor_id will augment the filename with the provided flavor_id,
    allowing you to create multiple singleton instances from the same file. This
    is particularly useful if you want specific functions to have their own
    singleton instances.
    """

    def __init__(self, flavor_id=""):
        basename = os.path.splitext(os.path.abspath(sys.argv[0]))[0].replace(
            "/", "-").replace(":", "").replace("\\", "-") + '-{}'.format(flavor_id) + '.lock'
        self.lockfile = os.path.normpath(
            tempfile.gettempdir() + '/' + basename)
        self.pid = str(os.getpid())
        self.fd = None
        logger.debug("SingleInstance lockfile: " + self.lockfile)
        oldPid = None
        try:
            self.fd = os.open(self.lockfile, os.O_CREAT |
                              os.O_EXCL | os.O_RDWR)
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # It's ok, we just log it as info but the pid file is
                # non existent
                logger.info(e)
            elif e.errno == errno.EPERM:
                logger.error(
                    "Another instance is already running, quitting.")
                raise SingleInstanceException(
                    "Another instance is already running, quitting.")
            else:
                logger.exception("Something went wrong")
                # Anything else is horribly wrong, we need to raise to the
                # upper level so the following code in this try clause
                # won't execute.
                raise
        else:
            # By this moment the file should be locked or we should exit so
            # there should realistically be no error here, or it can raise
            oldPid = os.read(self.fd, 1024).strip()
            if oldPid and oldPid != self.pid and pid_exists(oldPid):
                # Some OS actually recycle pids within same range so we
                # have to check whether oldPid is not the new one so this
                # won't fire up (*BSD).
                # If not and it is still running we'd rather actually exit
                # right here.
                try:
                    os.close(self.fd)
                except OSError as e:
                    # We shouldn't raise here anything. Because we don't
                    # actually care
                    logger.exception("Interesting state")
                logger.error(
                    "Another instance is already running, quitting.")
                raise SingleInstanceException(
                    "Another instance is already running, quitting.")
            # Barring any OS/Hardware issue this musn't throw anything. But
            # even if it throws we should raise it because it means we
            # shouldn't run and some serious problem is already happening. So
            # no, I'm not going to escape this one in try/except.
            os.ftruncate(self.fd, 0)  # Erase
            os.lseek(self.fd, 0, 0)  # Rewind
            os.write(self.fd, self.pid)  # Write PID

    def __del__(self):
        # If we are not initialized don't run the clause
        if self.fd:
            try:
                os.close(self.fd)
                os.unlink(self.lockfile)
            except:
                logger.exception("Unknown issue on exit")
                raise


def f(name):
    tmp = logger.level
    logger.setLevel(logging.CRITICAL)  # we do not want to see the warning
    try:
        me2 = SingleInstance(flavor_id=name)  # noqa
    except SingleInstanceException:
        sys.exit(-1)
    logger.setLevel(tmp)
    pass


class testSingleton(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestingClass, self).__init__(*args, **kwargs)
        from multiprocessing import Process

    def test_1(self):
        me = SingleInstance(flavor_id="test-1")
        del me  # now the lock should be removed
        assert True

    def test_2(self):
        p = Process(target=f, args=("test-2",))
        p.start()
        p.join()
        # the called function should succeed
        assert p.exitcode == 0, "%s != 0" % p.exitcode

    def test_3(self):
        me = SingleInstance(flavor_id="test-3")  # noqa -- me should still kept
        p = Process(target=f, args=("test-3",))
        p.start()
        p.join()
        # the called function should fail because we already have another
        # instance running
        assert p.exitcode != 0, "%s != 0 (2nd execution)" % p.exitcode
        # note, we return -1 but this translates to 255 meanwhile we'll
        # consider that anything different from 0 is good
        p = Process(target=f, args=("test-3",))
        p.start()
        p.join()
        # the called function should fail because we already have another
        # instance running
        assert p.exitcode != 0, "%s != 0 (3rd execution)" % p.exitcode

logger = logging.getLogger("tendosingleton")
logger.addHandler(logging.StreamHandler())

if __name__ == "__main__":
    logger.setLevel(logging.DEBUG)
    unittest.main()
