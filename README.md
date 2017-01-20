# singletony
Based on tendo.singleton

This module provides a Singlet() class which atomically creates a lock file containing PID of the running process to prevent parallel execution of the same program.

In case there is any other instance running already a `SingletException` will be thrown.

The class will throw `IOError` and `OSError` in case there are hardware or OS level corruption.

    >>> from singletony import Singlet
    ... me = Singlet(filename="test.lock", path="/tmp")

    
This is helpful for both daemons and simple crontab scripts. Works on *NIX and Windows OS's.

By default this creates a lock file with a filename based on the program name.
In case you want to remove the file or finish the lock beforehand just delete the instance.
