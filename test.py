'''
Created on 2017/03/01

@author: sakurai
'''
from concurrent.futures import TimeoutError
from logging import getLogger
import os
from platform import node
from tempfile import NamedTemporaryFile
import time
from unittest import main
from unittest import TestCase
from unittest import TestLoader

from python_wrap_cases import wrap_case

from rpsowmi import RemotePowerShellOverWmi as RPSoWMI
from wmi import WMI


@wrap_case
class RemotePowerShellOverWmiTest(TestCase):
    def setUp(self):
        TestCase.setUp(self)
        self.logfile = NamedTemporaryFile(delete=False)
        self.logfile.close()

    def tearDown(self):
        TestCase.tearDown(self)
        for _ in range(5):
            time.sleep(1)
            try:
                with open(self.logfile.name, "r", encoding="utf-16le") as fp:
                    getLogger(self.__class__.__name__).debug("\n%s", fp.read())
                    break
            except PermissionError as e:
                getLogger(self.__class__.__name__).warning(repr(e))
        os.remove(self.logfile.name)

    @wrap_case("")
    @wrap_case("Python")
    @wrap_case("Python ")
    @wrap_case(" ".join(["Python"] * 100))
    @wrap_case(" ".join(["Python"] * 200))
    # Limitation: Execution fails due to too long command
    # @wrap_case(" ".join(["Python"] * 300))
    def test_echo_code(self, text):
        ps_code = "[Console]::Out.Write('%s')" % text
        r = RPSoWMI(WMI(), logfile=self.logfile.name).execute(ps_code)
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip("\r\n"), text, r)

    @wrap_case("")
    @wrap_case("Python")
    @wrap_case("Python ")
    @wrap_case(" ".join(["Python"] * 100))
    @wrap_case(" ".join(["Python"] * 1000))
    @wrap_case(" ".join(["Python"] * 10000))
    @wrap_case("Python\nPython")
    # TODO(X): CR and CRLF are unified to LF
    # @wrap_case("Python\rPython")
    # @wrap_case("Python\r\nPython")
    def test_echo_stdin(self, text):
        ps_code = "[Console]::Out.Write([Console]::In.ReadToEnd())"
        r = RPSoWMI(WMI(), logfile=self.logfile.name).execute(ps_code, text)
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip("\r\n"), text, r)

    @wrap_case("Start-Sleep -s 3", 1)
    @wrap_case("Write-Host %s" % " ".join(["Python"] * 300), 1)
    def test_timeout(self, ps_code, timeout):
        rps = RPSoWMI(WMI(), logfile=self.logfile.name, timeout=timeout)
        self.assertRaises((RuntimeError, TimeoutError), rps.execute, ps_code)

    @wrap_case("1 / 0")
    def test_illegal_code(self, ps_code):
        r = RPSoWMI(WMI(), logfile=self.logfile.name).execute(ps_code)
        self.assertNotEqual(r.code, 0, r)
        self.assertEqual(len(r.stdout), 0, r)
        self.assertGreater(len(r.stderr), 0, r)

    @wrap_case("\n")
    @wrap_case("\r")
    @wrap_case("\r\n")
    @wrap_case("\r\n\r\r\n")
    @wrap_case("a\rb\nc")
    def test_1st_ascii_char_through_stdin(self, text):
        ps_code = "$c = [Console]::In.Read(); [Console]::Out.Write($c)"
        r = RPSoWMI(WMI(), logfile=self.logfile.name).execute(ps_code, text)
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip("\r\n"), str(ord(text[0])), r)

    @wrap_case("テスト")
    @wrap_case("测试")
    @wrap_case("próf")
    @wrap_case("테스트")
    @wrap_case("ทดสอบ")
    @wrap_case("परीक्षण")
    def test_1st_nonascii_char_through_stdin(self, text):
        ps_code = (
            "[Console]::InputEncoding ="
            " New-Object System.Text.UTF8Encoding $True;"
            "$c = [Console]::In.Read(); [Console]::Out.Write($c)"
        )
        r = RPSoWMI(WMI(), logfile=self.logfile.name).execute(ps_code, text)
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip("\r\n"), str(ord(text[0])), r)

    def test_with_hostname(self):
        r = RPSoWMI(WMI(computer=node()), localhost=node()).execute("hostname")
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip().casefold(), node().casefold(), r)

    def test_hello_world(self):
        r = RPSoWMI(WMI()).execute("[Console]::Out.Write('Hello, world')")
        self.assertEqual(r.code, 0, r)
        self.assertEqual(r.stdout.rstrip("\r\n"), "Hello, world", r)
        self.assertEqual(len(r.stderr), 0, r)


def suite():
    return TestLoader().loadTestsFromTestCase(RemotePowerShellOverWmiTest)


if __name__ == "__main__":
    from logging import basicConfig
    from logging import DEBUG
    basicConfig(level=DEBUG)
    main(verbosity=2)
