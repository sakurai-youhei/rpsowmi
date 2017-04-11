Remote PowerShell over WMI
--------------------------

Remote PowerShell over WMI (RPSoWMI) enables you to run PowerShell code with support of STDIN, STDOUT, STDERR and return code on remote host through Windows Management Instrumentation (WMI).

Communication with your PowerShell code is done through 2 named pipes (one for outbound and another for inbound) being created on **executor's** machine, that means your access rights must be enough privileged not only for creation of new process on remote machine but also for access to the named pipes on executor's machine from remote machine.

How to use RPSoWMI::

  from rpsowmi import RemotePowerShellOverWmi as RPSoWMI
  from wmi import WMI  # https://pypi.python.org/pypi/WMI/

  rps = RPSoWMI(WMI())
  r = rps.execute("Write-Host 'Hello, world'")
  print(r.stdout)  # Just showing 'Hello, world'.

For more details, read pydoc of rpsowmi.RemotePowerShellOverWmi.

**Known problems**

* Known problem: Line separators (CR, LF and CRLF) are unified to `\n` (LF) somewhere in communication between RPSoWMI and your PowerShell code being executed on remote machine.

**Versions History**

* v2017.4.11: Initial release while leaving one limitation that max length of your PowerShell code has to be up to around 1,400 characters.

|Build status|

.. |Build status| image:: https://img.shields.io/appveyor/ci/sakurai_youhei/rpsowmi/master.svg?label=Build%20and%20test%20on%20Python%203.4%20to%203.6
   :target: https://ci.appveyor.com/project/sakurai_youhei/rpsowmi/branch/master
