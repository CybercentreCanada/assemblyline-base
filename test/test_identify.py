import pytest

from os import remove
from re import findall, match, compile, IGNORECASE
from assemblyline.common import identify

# This testing suite will consist of two main parts:
# 1. Ensuring code coverage
# 2. Ensuring correct identification of files


@pytest.fixture
def dummy_zipfile_class():
    class DummyZipFile:
        def __init__(self, files):
            self.files = files

        def namelist(self):
            return self.files

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    yield DummyZipFile


@pytest.fixture
def dummy_office_file_class():
    class DummyOfficeFile:
        def __init__(self):
            pass

        def is_encrypted(self):
            return True

    yield DummyOfficeFile


def test_constants():
    from assemblyline.common.forge import get_constants
    assert identify.constants == get_constants()
    assert identify.STRONG_SCORE == 15
    assert identify.MINIMUM_GUESS_SCORE == 20
    assert identify.WEAK_SCORE == 1
    assert identify.recognized == identify.constants.RECOGNIZED_TYPES
    assert identify.custom == compile(r'^custom: ', IGNORECASE)


@pytest.mark.parametrize(
    "code_snippet, code_types",
    [
        # Nothing
        (b"blah", []),
        # VBS
        (b"On Error Resume Next", ["code/vbs"]),
        (b"\nOn Error Resume Next", ["code/vbs"]),
        (b"\nOn  Error  Resume  Next", ["code/vbs"]),
        (b"\nOn\tError\tResume\tNext", ["code/vbs"]),
        (b"Sub blah", ["code/vbs"]),
        (b"\nSub blah", ["code/vbs"]),
        (b"Private Sub blah", ["code/vbs"]),
        (b"Private\tSub\tblah", ["code/vbs"]),
        (b"\nPrivate\tSub\tblah", ["code/vbs"]),
        (b"\nPrivate\tSub\tblah(", ["code/vbs"]),
        (b"\nPrivate\tSub\tblah blah(", ["code/vbs"]),
        (b"End Module", ["code/vbs"]),
        (b"\nEnd Module", ["code/vbs"]),
        (b"\nEnd\tModule", ["code/vbs"]),
        (b"ExecuteGlobal", ["code/vbs"]),
        (b"\nExecuteGlobal", ["code/vbs"]),
        (b"REM ", ["code/vbs"]),
        (b"\nREM ", ["code/vbs"]),
        (b"\nREM\t", ["code/vbs"]),
        (b"ubound(", ["code/vbs"]),
        (b"lbound(", ["code/vbs"]),
        # JS
        (b"function(){", ["code/javascript"]),
        (b"function( ) {", ["code/javascript"]),
        (b"function(\t)\t{", ["code/javascript"]),
        (b"function(\tblah\t)\t{", ["code/javascript"]),
        (b"function( blah )\t{", ["code/javascript"]),
        (b"function(blah)\t{", ["code/javascript"]),
        (b"eval(", ["code/javascript", "code/php"]),
        (b"eval (", ["code/javascript", "code/php"]),
        (b"eval\t(", ["code/javascript", "code/php"]),
        (b"blaheval\t(", []),
        (b"new ActiveXObject(", ["code/javascript"]),
        (b"new\tActiveXObject(", ["code/javascript"]),
        (b"bnew\tActiveXObject(", ["code/javascript"]),
        (b"xfa.resolveNode", ["code/javascript"]),
        (b"xfa.datasets", ["code/javascript"]),
        (b"xfa.form", ["code/javascript"]),
        (b"xfa.createNode", ["code/javascript"]),
        (b".oneOfChild", ["code/javascript"]),
        (b"unescape(", ["code/javascript"]),
        (b".createElement(", ["code/javascript"]),
        (b"submitForm(", ["code/javascript"]),
        # C#
        (b"namespace blah", ["code/csharp", "code/php"]),
        (b"\nnamespace\tblah(", ["code/csharp", "code/php"]),
        (b"\n namespace\tblah(", ["code/csharp", "code/php"]),
        (b"\n\tnamespace\tblah(", ["code/csharp", "code/php"]),
        (b"using blah;", ["code/csharp"]),
        (b"\nusing blah;", ["code/csharp"]),
        (b"\n\tusing\tblah;", ["code/csharp"]),
        (b"internal class ", ["code/csharp"]),
        (b"\n\tinternal class ", ["code/csharp"]),
        (b"\n internal class ", ["code/csharp"]),
        (b"\n internal\tclass ", ["code/csharp"]),
        (b"\n internal\tclass\t", ["code/csharp"]),
        # PHP
        (b"<?php", ["code/php"]),
        (b"\n<?php", ["code/php"]),
        (b"namespace blah", ["code/csharp", "code/php"]),
        (b"namespace\tblah(", ["code/csharp", "code/php"]),
        (b"function blah($b){", ["code/php"]),
        (b"function blah ($b) {", ["code/php"]),
        (b"function blah ( $b ) {", ["code/php"]),
        (b"function\tblah\t($b)\t{", ["code/php"]),
        (b"function\tblah\t(\t$b\t)\t{", ["code/php"]),
        (b"function blah($){", []),
        (b"functionblah($b){", []),
        (b"function blah($b)\n{", ["code/php"]),
        (b"eval(", ["code/javascript", "code/php"]),
        (b"eval (", ["code/javascript", "code/php"]),
        (b"eval\t(", ["code/javascript", "code/php"]),
        # C
        (b"static struct", []),
        (b"static struct ", ["code/c"]),
        (b"\nstatic\tstruct\t", ["code/c"]),
        (b"typedef struct", []),
        (b"typedef struct ", ["code/c"]),
        (b"\ntypedef\tstruct\t", ["code/c"]),
        (b"\ntypedefstruct\t", []),
        (b"#include\"blah.\"", ["code/c"]),
        (b"#include \"blah.\"", ["code/c"]),
        (b"#include\t\"blah.\"", ["code/c"]),
        (b"#include\"blah/\"", ["code/c"]),
        (b"#include<blah.>", ["code/c"]),
        (b"#include<blah/>", ["code/c"]),
        (b"\n#include<blah/>", ["code/c"]),
        (b"#include<blah/\"", ["code/c"]),
        (b"#include\"blah/>", ["code/c"]),
        (b"#ifndef ", ["code/c"]),
        (b"#define ", ["code/c"]),
        (b"#endif ", ["code/c"]),
        (b"#pragma ", ["code/c"]),
        (b"#pragma\t", ["code/c"]),
        (b"\n#pragma ", ["code/c"]),
        # Python
        (b"\nif __name__==\"__main__\":", ["code/python"]),
        (b"\nif\t__name__==\"__main__\":", ["code/python"]),
        (b" if __name__ == \"__main__\" :", ["code/python"]),
        (b"\tif __name__\t==\t'__main__'\t:", ["code/python"]),
        (b"\tif __name__\t==\t'__main__'\t:", ["code/python"]),
        (b"\tif __name__\t==\t'__main__\"\t:", ["code/python"]),
        (b"\tif __name__\t==\t\"__main__'\t:", ["code/python"]),
        (b"from blah import blah", ["code/python"]),
        (b"from blah import blah as blah", ["code/python"]),
        (b" from blah import blah as", ["code/python"]),
        (b"\n\tfrom\tblah\timport\tblah\tas", ["code/python"]),
        (b"def blah():", ["code/python"]),
        (b"\n def\tblah (blah) :", ["code/python"]),
        (b"\n\tdef\tblah\t(\tblah\t)\t:", ["code/python"]),
        (b"def blah( blah ):", ["code/python"]),
        # Rust
        (b"pub struct ", ["code/rust"]),
        (b"priv struct ", ["code/rust"]),
        (b"pub\tenum ", ["code/rust"]),
        (b"pub\tenum\t", ["code/rust"]),
        (b"\npub\tenum ", ["code/rust"]),
        (b"\npub\timpl ", ["code/rust"]),
        (b"\npub\tconst ", ["code/rust"]),
        (b"\npubconst ", []),
        (b"fn blah(&self ", ["code/rust"]),
        (b"\n fn\tblah(&self ", ["code/rust"]),
        (b"\n\tfn\tblah\t(&self ", ["code/rust"]),
        (b"\n\tfn\tblah (&self ", ["code/rust"]),
        (b"fnblah(&self ", []),
        (b"println!", ["code/rust"]),
        (b"panic!", ["code/rust"]),
        (b"(defmacro ", ["code/lisp"]),
        (b"(defun ", ["code/lisp"]),
        (b"(eval-when ", ["code/lisp"]),
        (b"(in-package ", ["code/lisp"]),
        (b"(list ", ["code/lisp"]),
        (b"(export ", ["code/lisp"]),
        (b"(defvar ", ["code/lisp"]),
        (b"\n(defvar ", ["code/lisp"]),
        (b"\n (defvar ", ["code/lisp"]),
        (b"\n\t(defvar ", ["code/lisp"]),
        (b"\n\t(defvar\t", ["code/lisp"]),
        # Java
        (b"public class blah {", ["code/java"]),
        (b"public class blah{", ["code/java"]),
        (b" public class blah extends blah {", ["code/java"]),
        (b"\n\tpublic\tclass\tblah\textends\tblah\t{", ["code/java"]),
        (b"\n\tpublic\tclass\tblah\textends\tblah{", ["code/java"]),
        (b"blah(b) throws blah {", ["code/java"]),
        (b"blah(b) throws blah{", ["code/java"]),
        (b"blah() throws blah {", ["code/java"]),
        (b"blah(b) throws , {", []),
        (b"blah(b) throws blah, {", []),
        (b"\nblah(b) throws blah,blah {", ["code/java"]),
        (b"\nblah(b)\tthrows\tblah\t,\tblah\t{", ["code/java"]),
        # Perl
        (b"my $blah=", ["code/perl"]),
        (b"\n\tmy\t$blah\t=", ["code/perl"]),
        (b"\n my $blah =", ["code/perl"]),
        (b"\n my$blah =", []),
        (b"\n my $blah blah=", []),
        (b"sub blah{", ["code/perl"]),
        (b"\n sub\tblah\t{", ["code/perl"]),
        (b"\tsub blah {", ["code/perl"]),
        (b"subblah{", []),
        # Ruby
        (b"require 'blah'", ["code/ruby"]),
        (b"\n require\t'blah'", ["code/ruby"]),
        (b"\n\trequire\t'blah'", ["code/ruby"]),
        (b"require_all 'blah'", ["code/ruby"]),
        (b"require_all'blah'", ["code/ruby"]),
        (b"require_all 'blah/blah'", ["code/ruby"]),
        (b"rescue blah =>", ["code/ruby"]),
        (b"blahrescue blah =>", ["code/ruby"]),
        (b"rescue\tblah\t=>", ["code/ruby"]),
        # Go
        (b"import (", ["code/go"]),
        (b"\n import\t(", ["code/go"]),
        (b"\n\timport\t(", ["code/go"]),
        (b"func blah(", ["code/go"]),
        (b"\n func\tblah(", ["code/go"]),
        (b"\n\tfunc\tblah(", ["code/go"]),
        # CSS
        (b"html {padding: blah}", ["code/css"]),
        (b"body {padding: blah}", ["code/css"]),
        (b"footer {padding: blah}", ["code/css"]),
        (b"span.blah {padding: blah}", ["code/css"]),
        (b"img.blah {padding: blah}", ["code/css"]),
        (b"a.blah {padding: blah}", ["code/css"]),
        (b".blah {padding: blah}", ["code/css"]),
        (b".blah {color: blah}", ["code/css"]),
        (b".blah {width: blah}", ["code/css"]),
        (b".blah {margin: blah}", ["code/css"]),
        (b".blah {background: blah}", ["code/css"]),
        (b".blah {font: blah}", ["code/css"]),
        (b".blah {text: blah}", ["code/css"]),
        (b"\n.blah\t{textb}", ["code/css"]),
        (b"}.blah{textb}", ["code/css"]),
        # Markdown
        (b"*`blah`-blah", ["text/markdown"]),
        (b"* `blah` - blah", ["text/markdown"]),
        (b"*\t`blah`\t-\tblah", ["text/markdown"]),
        # Email
        (b"Content-Type: ", ["document/email"]),
        (b"Subject: ", ["document/email"]),
        (b"MIME-Version: ", ["document/email"]),
        (b"Message-ID: ", ["document/email"]),
        (b"To: ", ["document/email"]),
        (b"From: ", ["document/email"]),
        (b"\n\nFrom: ", ["document/email"]),
        # Sysmon Events
        (b"<Events>", []),
        (b"<Events", []),
        (b"<Events>>>>>", []),
        (b"<Events>b", ["metadata/sysmon"]),
        (b"<Event>", []),
        (b"<Event", []),
        (b"<Event>>>>>", []),
        (b"<Event>b", ["metadata/sysmon"]),
        (b"</Event>", ["metadata/sysmon"]),
        (b"</Events>", ["metadata/sysmon"]),
        # XML
        (b"<?xml blah?>", ["code/xml"]),
        (b"\n\t <?xml blah?>", ["code/xml"]),
        (b"<?xmlblah?>", ["code/xml"]),
        (b"<something>blah blah</something>", ['code/xml']),
        (b"\n\t <something>blah blah</something>\n\t ", ['code/xml']),
        (b"<blah xmlns:blah>", ["code/xml"]),
        (b"<blahxmlns:blah>", ["code/xml"]),
        (b"<blah xmlns=blah>", ["code/xml"]),
        # PowerShell
        (b"Get-ExecutionPolicy", ["code/ps1"]),
        (b"\nGet-ExecutionPolicy", ["code/ps1"]),
        (b"Get-Service", ["code/ps1"]),
        (b"Where-Object", ["code/ps1"]),
        (b"ConvertTo-HTML", ["code/ps1"]),
        (b"Select-Object", ["code/ps1"]),
        (b"Get-Process", ["code/ps1"]),
        (b"Clear-History", ["code/ps1"]),
        (b"ForEach-Object", ["code/ps1"]),
        (b"Clear-Content", ["code/ps1"]),
        (b"Compare-Object", ["code/ps1"]),
        (b"New-ItemProperty", ["code/ps1"]),
        (b"New-Object", ["code/ps1"]),
        (b"New-WebServiceProxy", ["code/ps1"]),
        (b"Set-Alias", ["code/ps1"]),
        (b"Wait-Job", ["code/ps1"]),
        (b"Get-Counter", ["code/ps1"]),
        (b"Test-Path", ["code/ps1"]),
        (b"Get-WinEvent", ["code/ps1"]),
        (b"Start-Sleep", ["code/ps1"]),
        (b"Set-Location", ["code/ps1"]),
        (b"Get-ChildItem", ["code/ps1"]),
        (b"Rename-Item", ["code/ps1"]),
        (b"Stop-Process", ["code/ps1"]),
        (b"Add-Type", ["code/ps1"]),
        (b"Out-String", ["code/ps1"]),
        (b"Write-Error", ["code/ps1"]),
        (b"Invoke-Expression", ["code/ps1"]),
        (b"Invoke-WebRequest", ["code/ps1"]),
        (b"-memberDefinition", ["code/ps1"]),
        (b"-Name", ["code/ps1"]),
        (b"-namespace", ["code/ps1"]),
        (b"-passthru", ["code/ps1"]),
        (b"-join", ["code/ps1"]),
        (b"-split", ["code/ps1"]),
        (b".GetString(", ["code/ps1"]),
        (b".GetField(", ["code/ps1"]),
        (b".GetType(", ["code/ps1"]),
        (b".GetMethod(", ["code/ps1"]),
        (b"FromBase64String(", ["code/ps1"]),
        (b"System.Net.WebClient", ["code/ps1"]),
        (b"Net.ServicePointManager", ["code/ps1"]),
        (b"Net.SecurityProtocolType", ["code/ps1"]),
    ]
)
def test_strong_indicators(code_snippet, code_types):
    actual_code_types = list()
    for lang, patterns in identify.STRONG_INDICATORS.items():
        for pattern in patterns:
            for _ in findall(pattern, code_snippet):
                actual_code_types.append(lang)
    assert actual_code_types == code_types


@pytest.mark.parametrize(
    "code_snippet, code_types",
    [
        # Nothing
        (b"blah", []),
        # Javascript
        (b"var ", ["code/javascript"]),
        (b"document.write(", ["code/javascript"]),
        (b"String.fromCharCode(", ["code/javascript"]),
        (b"String.raw(", ["code/javascript"]),
        (b"Math.round(", ["code/javascript"]),
        (b"Math.pow(", ["code/javascript"]),
        (b"Math.sin(", ["code/javascript"]),
        (b"Math.cos(", ["code/javascript"]),
        (b"isNaN(", ["code/javascript"]),
        (b"isFinite(", ["code/javascript"]),
        (b"parseInt(", ["code/javascript"]),
        (b"parseFloat(", ["code/javascript"]),
        (b"WSH", ["code/javascript", "code/vbs"]),
        (b"document[", ["code/javascript"]),
        (b"window[", ["code/javascript"]),
        # JScript
        (b"new ActiveXObject(", ["code/jscript"]),
        (b"new\tActiveXObject(", ["code/jscript"]),
        (b"Scripting.Dictionary", ["code/jscript"]),
        # PDFJS
        (b"xfa.resolveNode", ["code/pdfjs"]),
        (b"xfa.createNode", ["code/pdfjs"]),
        (b"xfa.datasets", ["code/pdfjs"]),
        (b"xfa.form", ["code/pdfjs"]),
        (b".oneOfChild", ["code/pdfjs"]),
        # VBS
        (b"Dim ", ["code/vbs"]),
        (b"\n\n  \t\tDim ", ["code/vbs"]),
        (b"Sub ", ["code/vbs"]),
        (b"Loop ", ["code/vbs"]),
        (b"Attribute ", ["code/vbs"]),
        (b"End Sub", ["code/vbs"]),
        (b"End Sub ", ["code/vbs"]),
        (b"Function ", ["code/vbs"]),
        (b"Function\t", ["code/vbs"]),
        (b"End Function ", ["code/vbs"]),
        (b"End Function", []),
        (b"CreateObject", ["code/vbs"]),
        (b"WScript", ["code/vbs"]),
        (b"window_onload", ["code/vbs"]),
        (b".SpawnInstance_", ["code/vbs"]),
        (b".Security_", ["code/vbs"]),
        (b"WSH", ["code/javascript", "code/vbs"]),
        # C#
        (b"protected override", ["code/csharp"]),
        (b"protected\toverride", ["code/csharp"]),
        (b"protectedoverride", []),
        (b"override", ["code/csharp"]),
        (b"\noverride", ["code/csharp"]),
        # SQL
        (b"create ", ["code/sql"]),
        (b"\ncreate ", ["code/sql"]),
        (b"drop ", ["code/sql"]),
        (b"select ", ["code/sql"]),
        (b"returns ", ["code/sql"]),
        (b"declare ", ["code/sql"]),
        (b"declare\t", ["code/sql"]),
        # PHP
        (b"$this->", ["code/php"]),
        # C
        (b"const char blah;", ["code/c"]),
        (b"const\tchar\tblah;", ["code/c"]),
        (b"extern ", ["code/c"]),
        (b"uint8_t ", ["code/c"]),
        (b"uint16_t ", ["code/c"]),
        (b"uint32_t ", ["code/c"]),
        (b"uint32_t\t", ["code/c"]),
        # Python
        (b"try:", ["code/python"]),
        (b"except:", ["code/python"]),
        (b"else:", ["code/python"]),
        # Java
        (b"package blah;", ["code/java", "code/perl"]),
        (b"package blah.blah;", ["code/java", "code/perl"]),
        (b"\n\t package\tblah.blah;", ["code/java", "code/perl"]),
        # Perl
        (b"package blah;", ["code/java", "code/perl"]),
        (b"package blah.blah;", ["code/java", "code/perl"]),
        (b"\n\t package\tblah.blah;", ["code/java", "code/perl"]),
        (b"@_", ["code/perl"]),
        # Markdown
        (b"[blah]:http:", ["text/markdown"]),
        (b"[blah]:\t http:", ["text/markdown"]),
        # Powershell
        (b" -Blah", ["code/ps1"]),
        (b"\t-Blah", ["code/ps1"]),
        (b"\t-Blah\t-Blah9", ["code/ps1", "code/ps1"]),
        (b"Blah-Blah", ["code/ps1"]),
        (b"Blah-Blah-Blah", ["code/ps1"]),
        (b"BlahBlah-BlahBlah", ["code/ps1"]),
    ]
)
def test_weak_indicators(code_snippet, code_types):
    actual_code_types = list()
    for lang, pattern in identify.WEAK_INDICATORS.items():
        for _ in findall(pattern, code_snippet):
            actual_code_types.append(lang)
    assert actual_code_types == code_types


@pytest.mark.parametrize("code_snippet, is_match",
                         [
                             (b"blah", False),
                             (b"#!", False),
                             (b"#!blah.blah/blah\n", True),
                             (b"#!blah.blah/blah\t \n", True),
                             (b"#!blah.blah/env blah\n", True),
                         ]
                         )
def test_shebang(code_snippet, is_match):
    assert match(identify.SHEBANG, code_snippet) if is_match else not match(identify.SHEBANG, code_snippet)


@pytest.mark.parametrize("executable, general_result",
                         [
                             ("escript", "erlang"),
                             ("nush", "nu"),
                             ("macruby", "ruby"),
                             ("jruby", "ruby"),
                             ("rbx", "ruby"),
                         ]
                         )
def test_executables(executable, general_result):
    assert identify.EXECUTABLES[executable] == general_result


@pytest.mark.parametrize(
    "guid, general_result",
    [
        # GUID v0 (0)
        ("00020803-0000-0000-C000-000000000046", "document/office/word"),
        ("00020900-0000-0000-C000-000000000046", "document/office/word"),
        ("00020901-0000-0000-C000-000000000046", "document/office/word"),
        ("00020906-0000-0000-C000-000000000046", "document/office/word"),
        ("00020907-0000-0000-C000-000000000046", "document/office/word"),
        ("00020C01-0000-0000-C000-000000000046", "document/office/excel"),
        ("00020821-0000-0000-C000-000000000046", "document/office/excel"),
        ("00020820-0000-0000-C000-000000000046", "document/office/excel"),
        ("00020810-0000-0000-C000-000000000046", "document/office/excel"),
        ("00021a14-0000-0000-C000-000000000046", "document/office/visio"),
        ("0002CE02-0000-0000-C000-000000000046", "document/office/equation"),
        ("0003000A-0000-0000-C000-000000000046", "document/office/paintbrush"),
        ("0003000C-0000-0000-C000-000000000046", "document/office/package"),
        ("000C1084-0000-0000-C000-000000000046", "document/installer/windows"),
        ("00020D0B-0000-0000-C000-000000000046", "document/email"),
        # GUID v1 (Timestamp & MAC-48)
        ("29130400-2EED-1069-BF5D-00DD011186B7", "document/office/wordpro"),
        ("46E31370-3F7A-11CE-BED6-00AA00611080", "document/office/word"),
        ("5512D110-5CC6-11CF-8D67-00AA00BDCE1D", "document/office/word"),
        ("5512D11A-5CC6-11CF-8D67-00AA00BDCE1D", "document/office/word"),
        ("5512D11C-5CC6-11CF-8D67-00AA00BDCE1D", "document/office/word"),
        ("64818D10-4F9B-11CF-86EA-00AA00B929E8", "document/office/powerpoint"),
        ("64818D11-4F9B-11CF-86EA-00AA00B929E8", "document/office/powerpoint"),
        ("11943940-36DE-11CF-953E-00C0A84029E9", "document/office/word"),
        ("B801CA65-A1FC-11D0-85AD-444553540000", "document/pdf"),
        ("A25250C4-50C1-11D3-8EA3-0090271BECDD", "document/office/wordperfect"),
        ("C62A69F0-16DC-11CE-9E98-00AA00574A4F", "document/office/word"),
        ("F4754C9B-64F5-4B40-8AF4-679732AC0607", "document/office/word"),
        ("BDD1F04B-858B-11D1-B16A-00C0F0283628", "document/office/word"),
    ]
)
def test_guids(guid, general_result):
    assert identify.OLE_CLSID_GUIDs[guid] == general_result


@pytest.mark.parametrize(
    "tag, ext",
    [
        ('archive/chm', '.chm'),
        ('audiovisual/flash', '.swf'),
        ('code/batch', '.bat'),
        ('code/c', '.c'),
        ('code/csharp', '.cs'),
        ('code/hta', '.hta'),
        ('code/html', '.html'),
        ('code/java', '.java'),
        ('code/javascript', '.js'),
        ('code/jscript', '.js'),
        ('code/pdfjs', '.js'),
        ('code/perl', '.pl'),
        ('code/php', '.php'),
        ('code/ps1', '.ps1'),
        ('code/python', '.py'),
        ('code/ruby', '.rb'),
        ('code/vbs', '.vbs'),
        ('code/wsf', '.wsf'),
        ('document/installer/windows', '.msi'),
        ('document/office/excel', '.xls'),
        ('document/office/mhtml', '.mhtml'),
        ('document/office/ole', '.doc'),
        ('document/office/powerpoint', '.ppt'),
        ('document/office/rtf', '.doc'),
        ('document/office/unknown', '.doc'),
        ('document/office/visio', '.vsd'),
        ('document/office/word', '.doc'),
        ('document/office/wordperfect', 'wp'),
        ('document/office/wordpro', 'lwp'),
        ('document/pdf', '.pdf'),
        ('document/email', '.eml'),
        ('executable/windows/pe32', '.exe'),
        ('executable/windows/pe64', '.exe'),
        ('executable/windows/dll32', '.dll'),
        ('executable/windows/dll64', '.dll'),
        ('executable/windows/dos', '.exe'),
        ('executable/windows/com', '.exe'),
        ('executable/linux/elf32', '.elf'),
        ('executable/linux/elf64', '.elf'),
        ('executable/linux/so32', '.so'),
        ('executable/linux/so64', '.so'),
        ('java/jar', '.jar'),
        ('silverlight/xap', '.xap'),
        ('meta/shortcut/windows', '.lnk'),
        ('document/office/onenote', '.one'),
    ]
)
def test_tag_to_extension(tag, ext):
    assert identify.tag_to_extension[tag] == ext


@pytest.mark.parametrize(
    "type, string",
    [
        ('tnef', r'Transport Neutral Encapsulation Format'),
        ('chm', r'MS Windows HtmlHelp Data'),
        ('windows/dll64', r'^pe32\+ .*dll.*x86\-64'),
        ('windows/pe64', r'^pe32\+ .*x86\-64.*windows'),
        ('windows/dll32', r'^pe32 .*dll'),
        ('windows/pe32', r'^pe32 .*windows'),
        ('windows/pe', r'^pe unknown.*windows'),
        ('windows/dos', r'^(ms-)?dos executable'),
        ('windows/com', r'^com executable'),
        ('windows/dos', r'^8086 relocatable'),
        ('linux/elf32', r'^elf 32-bit lsb +executable'),
        ('linux/elf64', r'^elf 64-bit lsb +executable'),
        ('linux/so32', r'^elf 32-bit lsb +shared object'),
        ('linux/so64', r'^elf 64-bit lsb +shared object'),
        ('mach-o', r'^Mach-O'),
        ('7-zip', r'^7-zip archive data'),
        ('ace', r'^ACE archive data'),
        ('bzip2', r'^bzip2 compressed data'),
        ('cabinet', r'^installshield cab'),
        ('cabinet', r'^microsoft cabinet archive data'),
        ('cpio', r'cpio archive'),
        ('gzip', r'^gzip compressed data'),
        ('iso', r'ISO 9660'),
        ('lzma', r'^LZMA compressed data'),
        ('rar', r'^rar archive data'),
        ('tar', r'^(GNU|POSIX) tar archive'),
        ('ar', r'ar archive'),
        ('xz', r'^XZ compressed data'),
        ('zip', r'^zip archive data'),
        ('tcpdump', r'^(tcpdump|pcap)'),
        ('pdf', r'^pdf document'),
        ('bmp', r'^pc bitmap'),
        ('gif', r'^gif image data'),
        ('jpg', r'^jpeg image data'),
        ('png', r'^png image data'),
        ('installer/windows', r'(Installation Database|Windows Installer)'),
        ('office/excel', r'Microsoft.*Excel'),
        ('office/powerpoint', r'Microsoft.*PowerPoint'),
        ('office/word', r'Microsoft.*Word'),
        ('office/rtf', r'Rich Text Format'),
        ('office/ole', r'OLE 2'),
        ('office/unknown', r'Composite Document File|CDFV2'),
        ('office/unknown', r'Microsoft.*(OOXML|Document)'),
        ('office/unknown', r'Number of (Characters|Pages|Words)'),
        ('flash', r'Macromedia Flash'),
        ('autorun', r'microsoft windows autorun'),
        ('batch', r'dos batch file'),
        ('jar', r'[ (]Jar[) ]'),
        ('java', r'java program'),
        ('class', r'java class data'),
        ('perl', r'perl .*script'),
        ('php', r'php script'),
        ('python', r'python .*(script|byte)'),
        ('shell', r'(shell|sh) script'),
        ('xml', r'OpenGIS KML'),
        ('html', r'html'),
        ('sgml', r'sgml'),
        ('xml', r'xml'),
        ('sff', r'Frame Format'),
        ('shortcut/windows', r'^MS Windows shortcut'),
        ('email', r'Mime entity text'),
        ('sysmon', r'MS Windows Vista Event Log'),
    ]
)
def test_sl_patterns(type, string):
    assert [type, compile(string, IGNORECASE)] in identify.sl_patterns


@pytest.mark.parametrize(
    "sl, tl",
    [
        ('windows/com', 'executable'),
        ('windows/dos', 'executable'),
        ('windows/pe32', 'executable'),
        ('windows/pe64', 'executable'),
        ('windows/dll32', 'executable'),
        ('windows/dll64', 'executable'),
        ('linux/elf32', 'executable'),
        ('linux/elf64', 'executable'),
        ('linux/so32', 'executable'),
        ('linux/so64', 'executable'),
        ('mach-o', 'executable'),
        ('7-zip', 'archive'),
        ('bzip2', 'archive'),
        ('cabinet', 'archive'),
        ('gzip', 'archive'),
        ('iso', 'archive'),
        ('rar', 'archive'),
        ('tar', 'archive'),
        ('zip', 'archive'),
        ('tcpdump', 'network'),
        ('pdf', 'document'),
        ('bmp', 'image'),
        ('gif', 'image'),
        ('jpg', 'image'),
        ('png', 'image'),
        ('shortcut/windows', 'meta'),
    ]
)
def test_sl_to_tl(sl, tl):
    assert identify.sl_to_tl[sl] == tl


@pytest.mark.parametrize(
    "tl, string",
    [('document',
      r'Composite Document File|CDFV2|Corel|OLE 2|OpenDocument |Rich Text Format|Microsoft.*'
      r'(Document|Excel|PowerPoint|Word|OOXML)|Number of (Characters|Pages|Words)'),
     ('document', r'PostScript|pdf|MIME entity text'),
     ('java', r'jar |java'),
     ('code',
      r'Autorun|HTML |KML |LLVM |SGML |Visual C|XML |awk|batch |bytecode|perl|php|program|python'
      r'|ruby|script text exe|shell script|tcl'),
     ('network', r'capture'),
     ('unknown', r'CoreFoundation|Dreamcast|KEYBoard|OSF/Rose|Zope|quota|uImage'),
     ('unknown', r'disk|file[ ]*system|floppy|tape'),
     ('audiovisual',
      r'Macromedia Flash|Matroska|MIDI data|MPEG|MP4|MPG|MP3|QuickTime|RIFF|WebM|animation|audio|movie|music|ogg'
      r'|sound|tracker|video|voice data'),
     ('executable', r'803?86|COFF|ELF|Mach-O|ia32|executable|kernel|library|libtool|object'),
     ('unknown', r'Emulator'),
     ('image', r'DjVu|Surface|XCursor|bitmap|cursor|font|graphics|icon|image|jpeg'),
     ('archive',
      r'BinHex|InstallShield CAB|Transport Neutral Encapsulation Format|archive data|compress|mcrypt'
      r'|MS Windows HtmlHelp Data|current ar archive|cpio archive|ISO 9660'),
     ('meta', r'^MS Windows shortcut'),
     ('metadata', r'MS Windows Vista Event Log'),
     ('unknown', r'.*'), ])
def test_tl_patterns(tl, string):
    assert [tl, compile(string, IGNORECASE)] in identify.tl_patterns


@pytest.mark.parametrize("mime, translated_type",
    [
        ('application/x-bittorrent', 'meta/torrent'),
        ('application/x-tar', 'archive/tar'),
        ('message/rfc822', 'document/email'),
        ('text/calendar', 'text/calendar'),
        ('image/svg+xml', 'image/svg'),
        ('application/x-mach-binary', 'executable/mach-o'),
        ('application/vnd.ms-outlook', 'document/office/email'),
        ('application/x-iso9660-image', 'archive/iso'),
    ]
)
def test_trusted_mimes(mime, translated_type):
    assert identify.trusted_mimes[mime] == translated_type


@pytest.mark.parametrize("label, expected",
    [
        ("blah", "unknown"),
        ("Transport Neutral Encapsulation Format", "tnef"),
        ("MS Windows HtmlHelp Data", "chm"),
        ("pe32+ blahdllblahx86-64", "windows/dll64"),
        ("pe32+ blahx86-64blahwindows", "windows/pe64"),
        ("pe32 blahdll", "windows/dll32"),
        ("pe32 blahwindows", "windows/pe32"),
        ("pe unknownblahwindows", "windows/pe"),
        ("ms-dos executable", "windows/dos"),
        ("dos executable", "windows/dos"),
        ("com executable", "windows/com"),
        ("8086 relocatable", "windows/dos"),
        ("elf 32-bit lsb executable", "linux/elf32"),
        ("elf 32-bit lsb           executable", "linux/elf32"),
        ("elf 64-bit lsb executable", "linux/elf64"),
        ("elf 64-bit lsb           executable", "linux/elf64"),
        ("elf 32-bit lsb shared object", "linux/so32"),
        ("elf 32-bit lsb           shared object", "linux/so32"),
        ("elf 64-bit lsb shared object", "linux/so64"),
        ("elf 64-bit lsb           shared object", "linux/so64"),
        ("Mach-O", "mach-o"),
        ("7-zip archive data", "7-zip"),
        ("ACE archive data", "ace"),
        ('bzip2 compressed data', 'bzip2'),
        ('installshield cab', 'cabinet'),
        ('microsoft cabinet archive data', 'cabinet'),
        ('cpio archive', 'cpio'),
        ('gzip compressed data', 'gzip'),
        ('ISO 9660', 'iso'),
        ('LZMA compressed data', 'lzma'),
        ('rar archive data', 'rar'),
        ('GNU tar archive', 'tar'),
        ('POSIX tar archive', 'tar'),
        ('ar archive', 'ar'),
        ('XZ compressed data', 'xz'),
        ('zip archive data', 'zip'),
        ('tcpdump', 'tcpdump'),
        ('pdf document', 'pdf'),
        ('pc bitmap', 'bmp'),
        ('gif image data', 'gif'),
        ('jpeg image data', 'jpg'),
        ('png image data', 'png'),
        ('Installation Database', 'installer/windows'),
        ('Windows Installer', 'installer/windows'),
        ('MicrosoftExcel', 'office/excel'),
        ('MicrosoftblahExcel', 'office/excel'),
        ('MicrosoftPowerPoint', 'office/powerpoint'),
        ('MicrosoftblahPowerPoint', 'office/powerpoint'),
        ('MicrosoftWord', 'office/word'),
        ('MicrosoftblahWord', 'office/word'),
        ('Rich Text Format', 'office/rtf'),
        ('OLE 2', 'office/ole'),
        ('Composite Document File', 'office/unknown'),
        ('CDFV2', 'office/unknown'),
        ('MicrosoftOOXML', 'office/unknown'),
        ('MicrosoftDocument', 'office/unknown'),
        ('MicrosoftblahOOXML', 'office/unknown'),
        ('MicrosoftblahDocument', 'office/unknown'),
        ('Number of Characters', 'office/unknown'),
        ('Number of Pages', 'office/unknown'),
        ('Number of Words', 'office/unknown'),
        ('Macromedia Flash', 'flash'),
        ('microsoft windows autorun', 'autorun'),
        ('dos batch file', 'batch'),
        (' Jar ', 'jar'),
        ('(Jar)', 'jar'),
        ('java program', 'java'),
        ('java class data', 'class'),
        ('perl script', 'perl'),
        ('perl blahscript', 'perl'),
        ('php script', 'php'),
        ('python script', 'python'),
        ('python byte', 'python'),
        ('python blahscript', 'python'),
        ('python blahbyte', 'python'),
        ('shell script', 'shell'),
        ('sh script', 'shell'),
        ('OpenGIS KML', 'xml'),
        ('html', 'html'),
        ('sgml', 'sgml'),
        ('xml', 'xml'),
        ('Frame Format', 'sff'),
        ('MS Windows shortcut', 'shortcut/windows'),
        ('Mime entity text', 'email'),
        ('MS Windows Vista Event Log', 'sysmon'),
    ]
)
def test_subtype(label, expected):
    assert identify._subtype(label) == expected


@pytest.mark.parametrize(
    "buf, expected_result, mocked_magic",
    [(b"", {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'},
      None),
     (b"blah",
      {'ascii': 'blah', 'hex': '626c6168', 'magic': 'ASCII text, with no line terminators', 'mime': 'text/plain',
       'type': 'unknown'},
      None),
     (b"if __name__=='__main__'",
      {'ascii': "if __name__=='__main__'", 'hex': '6966205f5f6e616d655f5f3d3d275f5f6d61696e5f5f27',
       'magic': 'Python script, ASCII text executable, with no line terminators', 'mime': 'text/plain',
       'type': 'code/python'},
      None),
     (b"", {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'},
      b"blah"),
     (b"", {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'},
      b"blah\nblip\nbloop"),
     (b"", {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'},
      b"blah\ncustom: yabadabadoo\nbloop"),
     (b"blah", {'ascii': "blah", 'hex': "626c6168", 'magic': "blah", 'mime': "blah", 'type': 'code/vbs'},
      b"blah\ncustom: code/vbs\nbloop"),
     (b"", {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'},
      b"blah\n- yabadabadoo \nbloop"),
     (b"blah", {'ascii': "blah", 'hex': "626c6168", 'magic': "blah", 'mime': "blah", 'type': 'meta/torrent'},
      b"blah\n- application/x-bittorrent \nbloop"),
     (b"blah",
      {'ascii': "blah", 'hex': "626c6168", 'magic': "blah", 'mime': "blah", 'type': 'document/office/unknown'},
      b"blah\ncustom: document/office/unknown\nbloop"),
     (u"Root Entrybbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00020803-0000-0000-C000-000000000046".encode(
         "utf-16-le"),
      {'ascii': 'R.o.o.t. .E.n.t.r.y.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.b.',
       'hex': '52006f006f007400200045006e007400720079006200620062006200620062006200620'
              '062006200620062006200620062006200620062006200620062006200',
       'magic': "blah", 'mime': "blah", 'type': 'document/office/unknown'},
      b"blah\ncustom: document/office/unknown\nbloop"),
     (b"blah",
      {'ascii': 'blah', 'hex': '626c6168', 'magic': 'OLE 2 Compound Document : Microsoft Word Document', 'mime': 'blah',
      'type': 'document/office/word'},
      b"blah\nOLE 2 Compound Document : Microsoft Word Document\n"),
     ])
def test_ident(buf, expected_result, mocked_magic, mocker):
    if mocked_magic:
        mocker.patch("magic.magic_file", return_value=mocked_magic)
    path = "/tmp/sample.txt"
    with open(path, "wb") as f:
        f.write(buf)
    assert identify.ident(buf, len(buf), path) == expected_result
    remove(path)


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, "0%"),
        (0.0, "0%"),
        (100, "100%"),
        (15, "20%"),
        (25, "33%"),
        (45, "60%"),
        (75, "100%"),
        (46, "61%"),
        (46.3, "61%"),
        (46.5, "62%"),
        (46.8, "62%"),
    ]
)
def test_confidence(score, expected):
    assert identify._confidence(score) == expected


@pytest.mark.parametrize(
    "lang, scores_map, expected",
    [
        ("blah", {}, "blah"),
        ("code/javascript", {"code/jscript": 0, "code/pdfjs": 0}, "code/javascript"),
        ("code/javascript", {"code/jscript": 1, "code/pdfjs": 0}, "code/jscript"),
        ("code/javascript", {"code/jscript": 0, "code/pdfjs": 1}, "code/pdfjs"),
    ]
)
def test_differentiate(lang, scores_map, expected):
    assert identify._differentiate(lang, scores_map) == expected


@pytest.mark.parametrize(
    "file_contents, expected_return",
    [
        (b"", ("unknown", 0)),
        (b"#!blah.blah/blah\n", ("code/blah", "60%")),
        (b"#!blah.blah/jruby\n", ("code/ruby", "60%")),
        (b"REM \nubound()", ("code/vbs", "40%")),
        (b"create \ndrop \nselect \nreturns \ndeclare ", ("unknown", 0)),
        (b"try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:"
         b"try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try"
         b":try:try:try:try:try:try:try:try:try:", ("code/python", "74%")),
        (b"REM \nubound()\nlbound()\ntry:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:"
         b"try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try"
         b":try:try:try:try:try:try:try:try:try:", ("code/python", "74%")),
        (b"REM \nubound()\nlbound()\nREM \ntry:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try"
         b":try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:try:"
         b"try:try:try:try:try:try:try:try:try:try:try:", ("code/vbs", "80%")),
        (b"really_big", ("unknown", 0)),
    ]
)
def test_guess_language(file_contents, expected_return):
    path = "/tmp/sample.txt"
    with open(path, "wb") as f:
        if file_contents == b"really_big":
            file_contents *= 13200
        f.write(file_contents)
    assert identify._guess_language(path) == expected_return
    remove(path)


@pytest.mark.parametrize(
    "file_contents, fallback, namelist, expected_return",
    [
        (b"", None, [], "archive/zip"),
        (b"", None, ["META-INF MANIFEST.MF"], "java/jar"),
        (b"", None, ["AndroidManifest.xml"], "archive/zip"),
        (b"", None, ["classes.dex"], "archive/zip"),
        (b"", None, ["Payload/blah.app/Info.plist"], "ios/ipa"),
        (b"", None, ["blah.class"], "java/jar"),
        (b"", None, ["blah.jar"], "java/jar"),
        (b"", None, ["word/blah"], "archive/zip"),
        (b"", None, ["xl/blah"], "archive/zip"),
        (b"", None, ["ppt/blah"], "archive/zip"),
        (b"", None, ["docProps/blah"], "archive/zip"),
        (b"", None, ["_rels/blah"], "archive/zip"),
        (b"", None, ["[Content_Types].xml"], "archive/zip"),
        (b"", None, ["META-INF MANIFEST.MF", "AndroidManifest.xml", "classes.dex"], "android/apk"),
        (b"", None, ["docProps/blah", "[Content_Types].xml"], "document/office/unknown"),
        (b"", None, ["_rels/blah", "[Content_Types].xml"], "document/office/unknown"),
        (b"", None, ["docProps/blah", "[Content_Types].xml", "word/blah"], "document/office/word"),
        (b"", None, ["docProps/blah", "[Content_Types].xml", "xl/blah"], "document/office/excel"),
        (b"", None, ["docProps/blah", "[Content_Types].xml", "ppt/blah"], "document/office/powerpoint"),
    ]
)
def test_zip_ident(file_contents, fallback, namelist, expected_return, dummy_zipfile_class, mocker):
    mocker.patch("zipfile.ZipFile", return_value=dummy_zipfile_class(namelist))
    path = "/tmp/sample.txt"
    with open(path, "wb") as f:
        f.write(file_contents)
    assert identify.zip_ident(path, fallback) == expected_return
    remove(path)


@pytest.mark.parametrize("file_contents, metadata, expected_return",
    [
        (b"", None, "archive/cart"),
        (b"", {"al": {"type": "blah"}}, "blah"),
        (None, None, "corrupted/cart"),
    ]
)
def test_cart_ident(file_contents, metadata, expected_return):
    from assemblyline.common.codec import encode_file
    if file_contents is not None:
        path = "/tmp/sample.txt"
        with open(path, "wb") as f:
            f.write(file_contents)
        output_path, file_name = encode_file(path, "blah", metadata)
    else:
        output_path = None
    assert identify.cart_ident(output_path) == expected_return
    if file_contents:
        remove(path)
        remove(output_path)


@pytest.mark.parametrize(
    "file_contents, expected_return",
    [
        (b"", "executable/windows/dos"),
        (b"MZ10010101010101010101010101010101010101010101010", "executable/windows/dos"),
        ("MZblahblahblahblahblahblahblahblahblahblahblahblah", "executable/windows/dos"),
    ]
)
def test_dos_ident(file_contents, expected_return):
    path = "/tmp/sample.txt"
    if type(file_contents) == str:
        write_method = "w"
    else:
        write_method = "wb"
    with open(path, write_method) as f:
        f.write(file_contents)
    assert identify.dos_ident(path) == expected_return
    remove(path)


@pytest.mark.parametrize(
    "file_contents, mocked_return, expected_return",
    [
        (b"", {"mime": None, "type": None}, {'mime': None, 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "blah", "type": None}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "application/cdfv2-corrupt", "type": None}, {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "application/cdfv2-unknown", "type": None}, {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "blah", "type": None, "size": 0}, {'mime': 'blah', 'size': 0, 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "blah", "type": "archive/zip"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'archive/zip'}),
        (b"", {"mime": "blah", "type": "java/jar"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'archive/zip'}),
        (b"", {"mime": "blah", "type": "document/office/unknown"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'document/office/unknown'}),
        (b"", {"mime": "blah", "type": "unknown"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'unknown'}),
        (b"", {"mime": "blah", "type": "archive/cart"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'corrupted/cart'}),
        (b"", {"mime": "blah", "type": "executable/windows/dos"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'executable/windows/dos'}),
        (b"", {"mime": "blah", "type": "code/html"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'code/html'}),
        (b"unescape(unescape(", {"mime": "blah", "type": "code/html"}, {'mime': 'blah', 'ssdeep': '3:eAWyfdn:eAWyfdn', 'type': 'code/hta'}),
        (b"", {"mime": "blah", "type": "document/office/word"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'document/office/word'}),
        (b"", {"mime": "blah", "type": "document/office/excel"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'document/office/excel'}),
        (b"", {"mime": "blah", "type": "document/office/powerpoint"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'document/office/powerpoint'}),
        (b"", {"mime": "blah", "type": "blah"}, {'mime': 'blah', 'ssdeep': '3::', 'type': 'unknown'}),
        (b"pp", {"mime": "blah", "type": "document/office/powerpoint"}, {'mime': 'blah', 'ssdeep': '3:/:/', 'type': 'document/office/passwordprotected'}),
    ]
)
def test_fileinfo(file_contents, mocked_return, expected_return, dummy_office_file_class, mocker):
    mocker.patch("assemblyline.common.identify.get_digests_for_file", return_value=mocked_return)
    path = "/tmp/sample.txt"
    with open(path, "wb") as f:
        f.write(file_contents)
    if file_contents == b"pp":
        mocker.patch("msoffcrypto.OfficeFile", return_value=dummy_office_file_class())
    assert identify.fileinfo(path) == expected_return
    remove(path)
