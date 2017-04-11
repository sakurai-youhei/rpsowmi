'''
Created on 2017/04/06

@author: sakurai
'''

import _winapi  # TODO(X): It might be better to use ctypes.windll instead
from base64 import encodebytes
from collections import defaultdict
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from enum import IntEnum
from logging import getLogger
from multiprocessing.connection import BUFSIZE
from multiprocessing.connection import PipeConnection
from threading import Timer
from uuid import uuid4
from xml.dom.minidom import parseString


VERSION = (2017, 4, 11)
VERSION_TEXT = ".".join(map(str, VERSION))

__version__ = VERSION_TEXT
__license__ = "MIT"
__author__ = "Youhei Sakurai"
__email__ = "sakurai.youhei@gmail.com"
__all__ = ["RemotePowerShellOverWmi"]

RPSOWMI_PS1 = """\
trap [Exception] {{
    Add-Content "{LOGFILE}" -value $error[0].exception
    exit {CODE_ON_EXC}
}}
Function Write-Log {{
    Param ([string]$Message)
    $Stamp = (Get-Date).toString("yyyy-MM-dd HH:mm:ss")
    echo "$Stamp $Message" >> "{LOGFILE}"
}}

Write-Log "* NPIPE_HOST: {NPIPE_HOST}"
Write-Log "* NPIPE_IN: {NPIPE_IN}"
Write-Log "* NPIPE_OUT: {NPIPE_OUT}"
Write-Log "* LOGFILE: {LOGFILE}"
Write-Log "* EXEC: {EXEC}"
Write-Log "* TIMEOUT: {TIMEOUT}"
Write-Log "* ENCODING: {ENCODING}"
Write-Log "* CODE_ON_EXC: {CODE_ON_EXC}"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.CreateNoWindow = $true
$psi.LoadUserProfile = $false
$psi.UseShellExecute = $false
$psi.StandardOutputEncoding = {ENCODING}
$psi.StandardErrorEncoding = {ENCODING}
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.FileName = "{EXEC}"
$psi.Arguments = "{ARGS}"

Write-Log "[{NPIPE_IN}] Opening"
$npipe_in = New-Object System.IO.Pipes.NamedPipeClientStream(
    "{NPIPE_HOST}", "{NPIPE_IN}", [System.IO.Pipes.PipeDirection]::In)
$npipe_in.Connect({TIMEOUT})

Write-Log "[{NPIPE_OUT}] Opening"
$npipe_out = New-Object System.IO.Pipes.NamedPipeClientStream(
    "{NPIPE_HOST}", "{NPIPE_OUT}", [System.IO.Pipes.PipeDirection]::Out)
$npipe_out.Connect({TIMEOUT})

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
$proc.EnableRaisingEvents = $true

$stdout = New-Object -TypeName System.Text.StringBuilder
$stderr = New-Object -TypeName System.Text.StringBuilder
$action = {{
    $line = $Event.SourceEventArgs.Data
    if (-not [String]::IsNullOrEmpty($line)) {{
        $Event.MessageData.AppendLine($line)
    }}
}}
$evt_stdout = Register-ObjectEvent `
    -InputObject $proc `
    -EventName OutputDataReceived `
    -Action $action `
    -MessageData $stdout
$evt_stderr = Register-ObjectEvent `
    -InputObject $proc `
    -EventName ErrorDataReceived `
    -Action $action `
    -MessageData $stderr

Write-Log "Starting {EXEC}"
$proc.Start()
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()

$reader = New-Object System.IO.StreamReader($npipe_in, {ENCODING})
$proc_stdin = New-Object System.IO.StreamWriter(
    $proc.StandardInput.BaseStream, {ENCODING})
$proc_stdin.Write($reader.ReadToEnd())
$proc_stdin.Flush()
$proc.StandardInput.Close()
$reader.Close()
Write-Log "[{NPIPE_IN}] Closed"

Write-Log ("Waiting for exit of {EXEC} pid=" + $proc.Id)
if ($proc.WaitForExit({TIMEOUT}) -eq $False) {{
    $proc.Kill()
    $npipe_out.Close()
    throw ("Timeout fired, {TIMEOUT} ms - {EXEC} pid=" + $proc.Id)
}}
Write-Log ("{EXEC} exited with " + $proc.ExitCode)

$proc.CancelOutputRead()
$proc.CancelErrorRead()
Unregister-Event -SourceIdentifier $evt_stdout.Name
Unregister-Event -SourceIdentifier $evt_stderr.Name

$xml = [XML]@'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Result [
    <!ELEMENT output (#PCDATA)>
    <!ATTLIST output id ID #IMPLIED>
]>
<Result>
    <output id="code"/>
    <output id="stdout"/>
    <output id="stderr"/>
</Result>
'@
$xml.SelectSingleNode("/Result/output[@id='code']").InnerText = $proc.ExitCode
$xml.SelectSingleNode("/Result/output[@id='stdout']").InnerText = $stdout
$xml.SelectSingleNode("/Result/output[@id='stderr']").InnerText = $stderr

$writer = New-Object System.IO.StreamWriter($npipe_out, {ENCODING})
$xml.WriteContentTo((New-Object system.xml.XmlTextWriter($writer)))
$writer.Close()
Write-Log "[{NPIPE_OUT}] Closed"
"""  # Curly brackets must be {{ and }} on the inside of above PS code.

ResultSet = namedtuple("ResultSet", ["pid", "code", "stdout", "stderr"])
ReturnValues = defaultdict(lambda: (
    "Other, see "
    "WMI Error Constants - "
    "https://msdn.microsoft.com/en-us/library/aa394559.aspx"
    ", WbemErrorEnum - "
    "https://msdn.microsoft.com/en-us/library/aa393978.aspx"
    " or System Error Codes - "
    "https://msdn.microsoft.com/en-us/library/ms681381.aspx"
    "."
))
ReturnValues[0] = "Successful completion"
ReturnValues[2] = "Access denied"
ReturnValues[3] = "Insufficient privilege"
ReturnValues[8] = "Unknown failure"
ReturnValues[9] = "Path not found"
ReturnValues[21] = "Invalid parameter"


class ShowWindow(IntEnum):
    """https://msdn.microsoft.com/en-us/library/aa394375.aspx"""
    SW_HIDE = 0
    SW_NORMAL = 1
    SW_SHOWMINIMIZED = 2
    SW_SHOWMAXIMIZED = 3
    SW_SHOWNOACTIVATE = 4
    SW_SHOW = 5
    SW_MINIMIZE = 6
    SW_SHOWMINNOACTIVE = 7
    SW_SHOWNA = 8
    SW_RESTORE = 9
    SW_SHOWDEFAULT = 10
    SW_FORCEMINIMIZE = 11


class dwOpenMode(IntEnum):
    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_ACCESS_INBOUND = 0x00000001
    PIPE_ACCESS_OUTBOUND = 0x00000002
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    FILE_FLAG_OVERLAPPED = 0x40000000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    ACCESS_SYSTEM_SECURITY = 0x01000000


class dwPipeMode(IntEnum):
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_TYPE_MESSAGE = 0x00000004
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_READMODE_MESSAGE = 0x00000002
    PIPE_WAIT = 0x00000000
    PIPE_NOWAIT = 0x00000001
    PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008


class nMaxInstances(IntEnum):
    PIPE_UNLIMITED_INSTANCES = 255


class nDefaultTimeOut(IntEnum):
    NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
    NMPWAIT_WAIT_FOREVER = 0xffffffff


class TimeoutTimer(Timer):
    def __init__(self, interval, function, args=None, kwargs=None):
        Timer.__init__(self, interval, function, args=args, kwargs=kwargs)
        self.setDaemon(True)

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.cancel()


def PipeServerConnection(address, readable, writable,
                         timeout=nDefaultTimeOut.NMPWAIT_WAIT_FOREVER):
    open_mode = (
        0x00000000
        | dwOpenMode.FILE_FLAG_OVERLAPPED
        | dwOpenMode.FILE_FLAG_FIRST_PIPE_INSTANCE
        | (readable and dwOpenMode.PIPE_ACCESS_INBOUND or 0x00000000)
        | (writable and dwOpenMode.PIPE_ACCESS_OUTBOUND or 0x00000000)
    )
    pipe_mode = (
        0x00000000
        | (readable and dwPipeMode.PIPE_READMODE_BYTE or 0x00000000)
        | (writable and dwPipeMode.PIPE_TYPE_BYTE or 0x00000000)
        | dwPipeMode.PIPE_WAIT
    )
    # https://msdn.microsoft.com/en-US/library/windows/desktop/aa365150.aspx
    handle = _winapi.CreateNamedPipe(address, open_mode, pipe_mode, 1,
                                     BUFSIZE, BUFSIZE, timeout, 0x0)
    overlapped = _winapi.ConnectNamedPipe(handle, overlapped=True)

    if (nDefaultTimeOut.NMPWAIT_USE_DEFAULT_WAIT
            < timeout < nDefaultTimeOut.NMPWAIT_WAIT_FOREVER):
        timer = TimeoutTimer(timeout / 1000, overlapped.cancel)
    else:
        timer = TimeoutTimer(0, lambda: None)

    with timer:
        _, err = overlapped.GetOverlappedResult(True)  # Can block forever
        assert err == 0
    return PipeConnection(handle, readable=readable, writable=writable)


class RemotePowerShellOverWmi(object):
    def __init__(self, wmiconn, localhost=".", timeout=60, logfile="$NUL",
                 code_on_exc=255, logger=getLogger("RPSoWMI")):
        """Enable you to execute PowerShell script on remote host via WMI.

        :param wmiconn: Any object behaving like wmi.WMI().
        :type wmiconn: win32com.client.Dispatch("WbemScripting.SWbemLocator")

        :param localhost: Host name where named pipes are being created. The
            host name must be referable from remote host because remote host
            accesses to the named pipes using the host name.
        :type localhost: str

        :param timeout: Timeout seconds of execution. If None is provided,
            timeout is not set; i.e. The execution could be blocked forever.
        :type timeout: int or float or None

        :param logfile: Path to log file to be updated with utf-16le encoding
            by remote PowerShell process. By default, no log file is generated
            because of '$NUL'.
        :type logfile: str

        :param code_on_exc: Exit code when wrapper PowerShell code meets
            exception such as timeout, IO error, etc.
        :type code_on_exc: int

        :param logger: Logger to be used for debug logging.
        :type logger: logging.Logger
        """
        assert all([  # Minimum requirements of wmiconn object
            hasattr(wmiconn, "Win32_ProcessStartup"),
            hasattr(wmiconn.Win32_ProcessStartup, "new"),
            callable(wmiconn.Win32_ProcessStartup.new),
            hasattr(wmiconn, "Win32_Process"),
            hasattr(wmiconn.Win32_Process, "Create"),
            callable(wmiconn.Win32_Process.Create),
        ]), "Incompatible wmiconn object, %r" % wmiconn

        self.wmiconn = wmiconn
        self.localhost = localhost
        self.timeout = timeout
        self.logfile = logfile
        self.code_on_exc = code_on_exc
        self.logger = logger
        self.encoding = "utf-8"
        self.ps_cmd = "powershell.exe"
        self.ps_opts = "-NonInteractive -NoProfile -NoLogo -encodedCommand"
        self.no_stdin = "-InputFormat none"
        self.ps_encoding = "[System.Text.Encoding]::UTF8"
        self.ps_prepend = (
            "[Console]::OutputEncoding = {ENCODING};"
            "[Console]::InputEncoding = {ENCODING};"
        )
        self.npipe_in = r"\\.\pipe\%s" % uuid4()
        self.npipe_out = r"\\.\pipe\%s" % uuid4()

    @staticmethod
    def encode_ps_code(ps_code):
        """Encode PowerShell code into one-line using utf-16le and base64."""
        return encodebytes(
            ps_code.encode("utf-16le")).decode("ascii").replace("\n", "")

    @staticmethod
    def parse_ps_result(s):
        """Parse XML formatted output from remote PowerShell execution."""
        targets = (("code", int), ("stdout", str), ("stderr", str))
        with parseString(s) as dom:
            for ident, cast in targets:
                try:
                    yield cast(
                        dom.getElementById(ident).childNodes[0].nodeValue)
                except IndexError:
                    try:
                        yield cast("")  # empty stdout and stderr are ok.
                    except ValueError:  # empty code is invalid.
                        RuntimeError(
                            "Not found valid %s %r" % (ident, cast), s)

    @property
    def timeout_ms_or_forever(self):
        if self.timeout is None or self.timeout < 0:
            return nDefaultTimeOut.NMPWAIT_WAIT_FOREVER
        else:
            return int(self.timeout * 1000)

    def _handle_write(self, stdin):
        """Write data connected to STDIN through named pipe.

        :param stdin: String to be provided to STDIN.
        :type stdin: str
        """
        data = stdin.encode(self.encoding)
        self.logger.debug("[%s] Opening", self.npipe_in)
        with closing(PipeServerConnection(
            address=self.npipe_in,
            readable=False, writable=True,
            timeout=self.timeout_ms_or_forever
        )) as pipe:
            self.logger.debug("[%s] Established", self.npipe_in)
            pipe.send_bytes(data)
            self.logger.debug("[%s] Sent %d bytes", self.npipe_in, len(data))
        self.logger.debug("[%s] Closed", self.npipe_in)

    def _handle_read(self):
        """Read data of exit code, STDOUT and STDERR through named pipe.

        :return: XML string containing exit code, STDOUT and STDERR.
        :rtype: str
        """
        data = b""
        self.logger.debug("[%s] Opening", self.npipe_out)
        with closing(PipeServerConnection(
            address=self.npipe_out,
            readable=True, writable=False,
            timeout=self.timeout_ms_or_forever
        )) as pipe:
            self.logger.debug("[%s] Established", self.npipe_out)
            while True:
                try:
                    recv = pipe.recv_bytes(BUFSIZE)
                    self.logger.debug("[%s] Received %d bytes",
                                      self.npipe_out, len(recv))
                    data += recv
                except (BrokenPipeError, EOFError):
                    break
        self.logger.debug("[%s] Closed", self.npipe_out)
        return data.decode(self.encoding)

    def execute(self, ps_code, stdin=None):
        """Execute PowerShell code through Win32_Process.Create().

        TODO(X): Line separators in stdin are transformed to '\n' somewhere
            regardless of original formats such as '\r', '\n' or '\r\n'.
        TODO(X): '\n' is always appended at the end of stdout and maybe also
            stderr.

        :param ps_code: PowerShell code to be executed.
        :type ps_code: str

        :param stdin: String to be provided to PowerShell process.
        :type stdin: str

        :return: Named tuple of pid, code, stdout and stderr as an execution
            result of PowerShell code.
        :rtype: rpsowmi.ResultSet

        :raises RuntimeError: Process creation fails or remote execution of
            wrapper PowerShell code meets exception which may include timeout
            on remote host.

        :raises concurrent.futures.TimeoutError: Timeout on local host.
        """
        ps_code_encoded = self.encode_ps_code(
            self.ps_prepend.format(ENCODING=self.ps_encoding) + ps_code)
        wrapper = self.encode_ps_code(RPSOWMI_PS1.format(
            EXEC=self.ps_cmd,
            ARGS=" ".join([self.ps_opts, ps_code_encoded]),
            NPIPE_HOST=self.localhost,
            NPIPE_IN=self.npipe_in.rsplit("\\", 1)[-1],
            NPIPE_OUT=self.npipe_out.rsplit("\\", 1)[-1],
            LOGFILE=self.logfile,
            ENCODING=self.ps_encoding,
            TIMEOUT="" if not self.timeout else int(self.timeout * 1000),
            CODE_ON_EXC=self.code_on_exc,
        ))
        cmdline = " ".join([self.ps_cmd, self.no_stdin, self.ps_opts, wrapper])
        ps_info = self.wmiconn.Win32_ProcessStartup.new()
        ps_info.ShowWindow = ShowWindow.SW_HIDE.value

        with ThreadPoolExecutor(2) as pool:
            f_write = pool.submit(self._handle_write, stdin=stdin or "")
            f_read = pool.submit(self._handle_read)

            self.logger.debug("Creating new process with %d bytes command",
                              len(cmdline))
            pid, result = self.wmiconn.Win32_Process.Create(
                CommandLine=cmdline, ProcessStartupInformation=ps_info)

            if result != 0:
                f_write.cancel()
                f_read.cancel()
                raise RuntimeError(
                    "Creating new process failed with %d" % result,
                    "%d - %s" % (result, ReturnValues[result]),
                    cmdline, repr(self.wmiconn))
            else:
                f_write.result(timeout=self.timeout)
                self.logger.debug("Waiting for result set information from "
                                  "process pid=%d", pid)
                r = ResultSet(pid, *self.parse_ps_result(
                    f_read.result(timeout=self.timeout)
                ))
                if r.code == self.code_on_exc:
                    raise RuntimeError("Exception is recorded in wrapper code",
                                       r, cmdline, repr(self.wmiconn))
                else:
                    return r
