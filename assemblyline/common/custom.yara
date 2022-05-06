/*
code/javascript
*/

rule code_javascript {
    meta:
        type = "code/javascript"

    strings:
        $not_html = /^\s*<\w/

        $strong_js1  = /(^|;|\s|\()function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/
        $strong_js2  = /\beval[ \t]*\(['"]/
        // jscript
        $strong_js3  = /new[ \t]+ActiveXObject\(['"]/
        $strong_js4  = /Scripting\.Dictionary['"]/
        // pdfjs
        $strong_js5  = /xfa\.((resolve|create)Node|datasets|form)['"]/
        $strong_js6  = /\.oneOfChild['"]/
        $strong_js7  = /unescape\(/
        $strong_js8  = /\.createElement\(/
        $strong_js9  = /submitForm\(['"]/
        $strong_js10 = /(document|window)(\[['"]|\.)\w/
        $strong_js11 = /setTimeout\(/

        $weak_js1 = /(^|;|\s)(var|let|const)[ \t]+\w+[ \t]*=[ \t]*/
        $weak_js2 = /String(\[['"]|\.)(fromCharCode|raw)(['"]\])?\(/
        $weak_js3 = /Math\.(round|pow|sin|cos)\(/
        $weak_js4 = /(isNaN|isFinite|parseInt|parseFloat|toLowerCase|toUpperCase)\(/
        $weak_js5 = /([^\w]|^)this\.[\w]+/

    condition:
        mime startswith "text"
        and not $not_html
        and (2 of ($strong_js*)
             or (1 of ($strong_js*)
                 and 2 of ($weak_js*)))
}

/*
code/jscript
*/

rule code_jscript {

    meta:
        type = "code/jscript"
        score = 5

    strings:
        $jscript1 = /new[ \t]+ActiveXObject\(/
        $jscript2 = /Scripting\.Dictionary['"]/

    condition:
        code_javascript
        and 1 of ($jscript*)
}

/*
code/pdfjs
*/

rule code_pdfjs {

    meta:
        type = "code/pdfjs"
        score = 5

    strings:
        $pdfjs1 = /xfa\.((resolve|create)Node|datasets|form)['"]/
        $pdfjs2 = /\.oneOfChild['"]/

    condition:
        code_javascript
        and 1 of ($pdfjs*)
}

/*
code/vbs
*/

rule code_vbs {

    meta:
        type = "code/vbs"

    strings:
        $strong_vbs1 = /(^|\n)On[ \t]+Error[ \t]+Resume[ \t]+Next/
        $strong_vbs2 = /(^|\n)(Private)?[ \t]*Sub[ \t]+\w+\(*/
        $strong_vbs3 = /(^|\n)End[ \t]+Module/
        $strong_vbs4 = /(^|\n)ExecuteGlobal/
        $strong_vbs5 = /(^|\n)REM[ \t]+/
        $strong_vbs6 = "ubound(" nocase
        $strong_vbs7 = "CreateObject(" nocase
        $strong_vbs8 = /\.Run[ \t]+\w+,\d(,(False|True))?/
        $strong_vbs9 = /replace\(([^,]+,){2}([^)]+)\)/
        $strong_vbs10 = "lbound(" nocase

        $weak_vbs1 = /(^|\n)[ \t]{0,1000}((Dim|Sub|Loop|Attribute|Function|End[ \t]+Function)[ \t]+)|(End[ \t]+Sub)/i
        $weak_vbs2 = "CreateObject" wide ascii nocase
        $weak_vbs3 = "WScript" wide ascii nocase
        $weak_vbs4 = "window_onload" wide ascii nocase
        $weak_vbs5 = ".SpawnInstance_" wide ascii nocase
        $weak_vbs6 = ".Security_" wide ascii nocase
        $weak_vbs7 = "WSH" wide ascii nocase
        $weak_vbs8 = /Set[ \t]+\w+[ \t]*=/i

    condition:
        2 of ($strong_vbs*)
        or (1 of ($strong_vbs*)
            and 2 of ($weak_vbs*))
}

/*
code/html
*/

rule code_html {

    meta:
        type = "code/html"

    strings:
        $html_doctype = "<!doctype html>" nocase
        $html_start = "<html" nocase
        $html_end = "</html" nocase

    condition:
        $html_doctype in (0..256)
        or $html_start in (0..256)
        or $html_end in (filesize-256..filesize)
}

/*
code/hta
*/

rule code_hta1 {

    meta:
        type = "code/hta"
        score = 10

    strings:
        $hta = "<hta:application " nocase

    condition:
        $hta
}

rule code_html_with_script {
    meta:
        type = "code/hta"
        score = 10

    strings:
        $script = "<script" nocase
        $lang_js1 = "language=\"javascript\"" nocase
        $lang_js2 = "language=\"jscript\"" nocase
        $lang_js3 = "language=\"js\"" nocase
        $lang_js4 = "type=\"text/javascript\"" nocase
        $lang_vbs1 = "language=\"vbscript\"" nocase
        $lang_vbs2 = "language=\"vb\"" nocase
        $lang_vbs3 = "type=\"text/vbscript\"" nocase

    condition:
        (code_html or mime startswith "text")
        and $script
        and 1 of ($lang*)
}

rule code_html_with_code {

    meta:
        type = "code/hta"
        score = 10

    condition:
        code_html and (1 of (code_javascript*) or 1 of (code_vbs*))
}

/*
code/htc
*/

rule code_htc {

    meta:
        type = "code/htc"
        score = 15

    strings:
        $component1 = "public:component " nocase
        $component2 = "/public:component" nocase
        $script = "<script" nocase
        $lang_js1 = "language=\"javascript\"" nocase
        $lang_js2 = "language=\"jscript\"" nocase
        $lang_js3 = "language=\"js\"" nocase
        $lang_vbs1 = "language=\"vbscript\"" nocase
        $lang_vbs2 = "language=\"vb\"" nocase

    condition:
        all of ($component*)
        and $script
        and 1 of ($lang*)
}

/*
document/email
*/

rule document_email_1 {

    meta:
        type = "document/email"
        score = 15

    strings:
        $rec = /(^|\n)From: /
        $rec2 = /(^|\n)Date: /
        $subrec1 = /(^|\n)Bcc: /
        $subrec2 = /(^|\n)To: /
        $opt1 = /(^|\n)Subject: /
        $opt2 = /(^|\n)Received: from/
        $opt3 = /(^|\n)MIME-Version: /
        $opt4 = /(^|\n)Content-Type: /

    condition:
        all of ($rec*)
        and 1 of ($subrec*)
        and 1 of ($opt*)
}

rule document_email_2 {

    meta:
        type = "document/email"
        score = 10

    strings:
        $ = /(^|\n)MIME-Version: /
        $ = /(^|\n)Content-Type: /
        $ = "This is a multipart message in MIME format."

    condition:
        all of them
}

/*
log/vipermonkey
*/

rule log_vipermonkey {

    meta:
        type = "log/vipermonkey"
        score = 20

    strings:
        $ = "======================="
        $ = "FILE: /"
        $ = "-----------------------"
        $ = "VBA MACRO"
        $ = "in file: "
        $ = "VBA CODE (with long lines collapsed):"
        $ = "PARSING VBA CODE:"

    condition:
        all of them
}

/*
text/json
*/

rule text_json {

    meta:
        type = "text/json"
        score = 1

    strings:
        $start = "{"
        $invalid_keys1 = /\w+:[\s]*[\{\["\d]/
        $valid_keys1 = /"\w+":[\s]*[\{\["\d]/
        $end = "}"

    condition:
        $start at 0
        and 0 of ($invalid_keys*)
        and $valid_keys1
        and $end at filesize-1
}

/*
code/csharp
*/

rule code_csharp {

    meta:
        type = "code/csharp"
        score = 1

    strings:
        $ = /(^|\n)[ \t]*namespace[ \t]+[\w.]+/
        $ = /(^|\n)[ \t]*using[ \t]+(static[ \t]+)?([\w.]+;|\w+[ \t]*=[ \t]*[\w.:<>]+;)/
        $ = /(^|\n)[ \t]*(internal|public)[ \t]+((static|sealed)[ \t]+)?class[ \t]+/
        $ = /(^|\n)[ \t]*fixed[ \t]+\(/
        $ = /(^|\n)[ \t]*(protected[ \t]+)?[ \t]*override/
        $ = /(^|\n)[ \t]*\[DllImport\("\w"\)\]public static extern/
        $ = /(^|\n)[ \t]*\[assembly: \w+\([\.\w"]+\)\]/
        $ = "IsNullOrWhiteSpace("

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/php
*/

rule code_php {

    meta:
        type = "code/php"

    strings:
        $php = /(^|\n)<\?php/
        $rec1 = /namespace[ \t]+[\w.]+/
        $rec2 = /function[ \t]+\w+[ \t]*\([ \t]*\$[^)]+\)[ \t\n]*{/
        $rec3 = /\beval[ \t]*\(/
        $rec4 = /\$this\->/
        $rec5 = /require[ \t]+([\w\.]+)?('[^']+\.php'|"[^"]+\.php")[ \t]*;/
        $rec6 = /require\(([\w\.]+)?('[^']+\.php'|"[^"]+\.php")\);/

    condition:
        mime startswith "text"
        and $php in (0..256)
        and 1 of ($rec*)
}

/*
code/jsp
*/

rule code_jsp {

    meta:
        type = "code/jsp"
        score = 3

    strings:
        $ = /(^|\n)<%@page[ \t]+import=['"][\w\.]+['"][ \t]*%>/
        $ = /(^|\n)<%![^%]*%>/
        $ = /<%=\w+%>/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/ps1
*/

rule code_ps1 {

    meta:
        type = "code/ps1"

    strings:
        $ = /(IWR|Start-BitsTransfer|Get-ExecutionPolicy|Get-Service|Where-Object|ConvertTo-HTML|Select-Object|Get-Process|Clear-History|ForEach-Object|Clear-Content|Compare-Object|New-ItemProperty|New-Object|New-WebServiceProxy|Set-Alias|Wait-Job|Get-Counter|Test-Path|Get-WinEvent|Start-Sleep|Set-Location|Get-ChildItem|Rename-Item|Stop-Process|Add-Type|Out-String|Write-Error|Invoke-(Expression|WebRequest))/i
        $ = /(-memberDefinition|-Name|-namespace|-passthru|-command|-TypeName|-join|-split|-sou|-dest|-property|-OutFile|-ExecutionPolicy Bypass)/i
        $ = /(\.Get(String|Field|Type|Method)|FromBase64String)\(/i
        $ = /(System\.Net\.WebClient)/i
        $ = /(Net\.ServicePointManager)/i
        $ = /(Net\.SecurityProtocolType)/i
        $ = /\[(System\.)?Text\.Encoding\]::UTF8/i
        $ = /\[(System\.)?Convert\]::ToInt32/i
        $ = /\[(System\.)?String]::Join\(/i
        $ = /\[byte\[\]\][ \t]*\$\w+[ \t]*=/i
        $ = /\[Microsoft\.VisualBasic\.(Interaction|CallType)\]/i

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/c
*/

rule code_c {

    meta:
        type = "code/c"
        score = 1

    strings:
        $ = /(^|\n)(static|typedef)?[ \t]+(struct|const)[ \t]+/
        $ = /(^|\n)#include[ \t]*([<"])[\w.\/]+([>"])/
        $ = /(^|\n)#(if !defined|ifndef|define|endif|pragma)[ \t]+/
        $ = /(^|\n)public[ \t]*:/
        $ = /ULONG|HRESULT|STDMETHOD(_)?/
        $ = /THIS(_)?/
        $ = /(^|\n)(const[ \t]+char[ \t]+\w+;|extern[ \t]+|uint(8|16|32)_t[ \t]+)/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/h
*/

rule code_h {

    meta:
        type = "code/h"

    strings:
        $if = /(^|\n)#if[ \t]+!defined[ \t]+\w+/
        $if2 = /(^|\n)#ifndef[ \t]+\w+/
        $if3 = /(^|\n)#endif[ \t]*(\n|$)/
        $def = /(^|\n)#define[ \t]+\w+[ \t]+[^\n]+/

    condition:
        mime startswith "text"
        and not code_c
        and for all of ($def) : ( # > 2 )
        and 1 of ($if*)
}

/*
code/idl
*/

rule code_idl {

    meta:
        type = "code/idl"

    strings:
        $ = /(^|\n)[ \t]*\[helpstring\([^\)]+\)\][ \t]*[^,]+,/
        $ = /(^|\n)[ \t]*importlib\("[^\)]+.tlb"\)[ \t]*;/
        $ = /(^|\n)[ \t]*import[ \t]*"[^"]+.idl"[ \t]*;/
        $ = /(^|\n)[ \t]*typedef[ \t]*\[\w+\][ \t]*\w+[ \t]*\w+[^{]*/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/glsl
*/

rule code_glsl {

    meta:
        type = "code/glsl"
        score = 2

    strings:
        $ = /(^|\n)#version\s+\d{1,4}\s*(es)?/
        $ = /(^|\n)precision(\s+\w+){2};/
        $ = /(^|\n)uniform(\s+\w+){2};/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/python
*/

rule code_python {

    meta:
        type = "code/python"

    strings:
        $ = /(^|\n)[ \t]*if[ \t]+__name__[ \t]*==[ \t]*['"]__main__['"][ \t]*:/
        $ = /(^|\n)[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]+[\w.*]+([ \t]+as \w+)?/
        $ = /(^|\n)[ \t]*def[ \t]*\w+[ \t]*\([^)]*\)[ \t]*:/
        $ = /(try:|except:|else:)/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/java
*/

rule code_java {

    meta:
        type = "code/java"

    strings:
        $ = /(^|\n)[ \t]*(public|private|protected)[ \t]+((abstract|final)[ \t]+)?class[ \t]+\w+[ \t]*([ \t]+extends[ \t]+\w+[ \t]*)?{/
        $ = /(^|\n)[ \t]*(public|private|protected)[ \t]+(static[ \t]+)?((abstract|final)[ \t]+)?(\w+[ \t]+){2}=/
        $ = /(^|\n)[\w \t]+\([^)]*\)[ \t]+throws[ \t]+\w+[ \t]*(,[ \t]*\w+[ \t]*)*{/
        $ = /\.hasNext\(/
        $ = /[ \t\n]*final[ \t]+\w/
        $ = /(ArrayList|Class|Stack|Map|Set|HashSet|PrivilegedAction|Vector)<(\w|\?)/
        $ = /(^|\n)[ \t]*package[ \t]+[\w\.]+;/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/protobuf
*/

rule code_protobuf {

    meta:
        type = "code/protobuf"
        score = 3

    strings:
        $ = /(^|\n)[ \t]*syntax[ \t]+=[ \t]+"proto\d"[ \t]*;/
        $ = /(^|\n)[ \t]*package[ \t]+google\.protobuf[ \t]*;/
        $ = /(^|\n)[ \t]*option[ \t]+\w+[ \t]+=[ \t]+[^;^\n]+[ \t]*;/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/xml
*/

rule code_xml {

    meta:
        type = "code/xml"

    strings:
        $ = /^\s*<\?xml[^>]+\?>/
        $ = /<[^>]+xmlns[:=][^>]+>/
        $ = /<\/xml>/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/css
*/

rule code_css {

    meta:
        type = "code/css"

    strings:
        $css = /(^|\n|\})(html|body|footer|span\.|img\.|a\.|\.[a-zA-Z\-.]+)[^{]+{[ \t]*(padding|color|width|margin|background|font|text)[^}]+\}/

    condition:
        mime startswith "text"
        and for all of ($css) : ( # > 2 )
}

/*
metadata/sysmon/evtx
*/

rule metadata_sysmon_evtx {

    meta:
        type = "metadata/sysmon/evtx"

    strings:
        $ = /<Events[^>]*>/
        $ = /<Event[^s][^>]*(\/)?>/
        $ = /<\/Event(s)?>/

    condition:
        mime startswith "text"
        and all of them
}

/*
code/batch
*/

// rule code_batch {

//     meta:
//         type = "code/batch"

//     strings:
//         $ = /(^|\n| |\t|@)(chcp|set \/p)[ \t]+/i
//         $ = /(^|\n| |\t|&)start[ \t]*\/(min|b)[ \t]+.*([ \t]+(-win[ \t]+1[ \t]+)?-enc[ \t]+)?"/i
//         $ = /(^|\n| |\t|&)start[ \t]*\/wait[ \t]+.*/i
//         $ = /(^|\n|@)cd[ \t]+(\/d )?["']%~dp0["']/i
//         $ = /(^|\n)taskkill[ \t]+(\/F|\/im)/i
//         $ = /(^|\n)reg[ \t]+delete[ \t]+/i
//         $ = /(^|\n)%comspec%[ \t]+\/c[ \t]+/i
//         $ = /(^|\n)dir&echo[ \t]+/i
//         $ = /(^|\n)net[ \t]+(share|stop|start|accounts|computer|config|continue|file|group|localgroup|pause|session|statistics|time|use|user|view)/i

//         $ = /(^|\n| |\t|@|&)(echo|netsh|sc|pkgmgr|netstat|rem|::|move)[ \t]+/i
//         $ = /(^|\n)pause/
//         $ = /(^|\n)shutdown[ \t]*(\/s)?/
//         $ = /Set[ \t]+\w+[ \t]*=/

//     condition:
//         mime startswith "text"
//         and 2 of them
// }

rule code_batch {

    meta:
        type = "code/batch"
        score = 1

    strings:
        $obf = /%(commonprogramfiles|programfiles|comspec|pathext):~\-?\d{1,2},\d%/
        $power = /(^|\n|@|&)\^?p\^?o\^?w\^?e\^?r\^?s\^?h\^?e\^?l\^?l\^?\.\^?e\^?x\^?e\^?[ \t]+-c[ \t]"/
        $cmd1 = /(^|\n)(echo|set|netsh|goto|pkgmgr|del|netstat|timeout|taskkill|vssadmin|tasklist|schtasks)[ \t][\/]?\w+/i
        $cmd2 = /(^|\n|@|&)net[ \t]+(share|stop|start|accounts|computer|config|continue|file|group|localgroup|pause|session|statistics|time|use|user|view)/i
        $cmd3 = /(^|\n|@|&)reg[ \t]+(delete|query|add|copy|save|load|unload|restore|compare|export|import|flags)[ \t]+/i
        $cmd4 = /(^|\n|@|&)start[ \t]+(\/(min|b|wait|belownormal|abovenormal|realtime|high|normal|low|shared|seperate|max|i)[ \t]+|"\w*"[ \t]+)*["']?([A-Z]:)?([\\|\/]?[\w.]+)+['"]?/i

    condition:
        mime startswith "text"
        and (for all of ($obf) :( # > 3 )
             or $power
             or for all of ($cmd*) :( # > 3 ))
}

rule code_batch_small {

    meta:
        type = "code/batch"
        score = -1

    strings:
        $ = /(^|\n|@|&)\^?s\^?t\^?a\^?r\^?t\^?[ \t]+(\/(min|b|wait|belownormal|abovenormal|realtime|high|normal|low|shared|seperate|max|i)[ \t]+|"\w*"[ \t]+)*["']?([A-Z]:)?([\\|\/]?[\w.]+)+['"]?/
        $ = /%(commonprogramfiles|programfiles|comspec|pathext):~\-?\d{1,2},\d%/
        $ = /(^|\n|@|&)\^?f\^?i\^?n\^?d\^?s\^?t\^?r\^?[ \t]+["][^"]+["][ \t]+(["][^"]+["]|[^[ \t]+)[ \t]+>[ \t]+(["][^"]+["]|[^[ \t]+)[ \t]+&[ \t]+/
        $ = /(^|\n)[ "]*([a-zA-Z]:)?(\.?\\[^\\^\n]+|\.?\/[^\/^\n]+)+\.(exe|bat|cmd|ps1)[ "]*(([\/\-]?\w+[ "]*|&)[ \t]*)*($|\n)/
        $ = /(^|\n) *[\w\.]+\.(exe|bat|cmd|ps1)( [\-\/"]?[^ ^\n]+"?)+ *($|\n)/
        $ = /(^|\n)(timeout|copy|taskkill|tasklist|vssadmin|schtasks)( ([\/"]?[\w\.:\\\/]"?|&)+)+/

    condition:
        mime startswith "text"
        and 1 of them
        and filesize < 512
}

/*
document/ps
*/

rule document_ps {

    meta:
        type = "document/ps"

    strings:
        $header = /(^|\n)%!PS[ \t]*\n/
        $opt1 = /(^|\n)[ \t]+\d+[ \t]+(selectfont|scalefont|setlinejoin|setlinewidth)[ \t]*[^\n]*/
        $opt2 = /(^|\n)[ \t]+\d+[ \t]+\d+[ \t]+(moveto|lineto|scale|translate)[ \t]*[^\n]*/
        $opt3 = /(^|\n)[ \t]+(showpage|newpath|stroke|setfont)[ \t]*[^\n]*/
        $opt4 = /(^|\n)[ \t]+\([^\)]+\)[ \t]+show[ \t]*[^\n]*/

    condition:
        mime startswith "text"
        and $header
        and for all of ($opt*) : ( # > 2 )
}

/*
code/markdown
*/

rule code_markdown {

    meta:
        type = "code/markdown"

    strings:
        $ = /\*[ \t]*`[^`]+`[ \t]*-[ \t]*\w+/
        $ = /\[[\w]+\]:[ \t]*http:/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/sql
*/

rule code_sql {

    meta:
        type = "code/sql"

    strings:
        $ = /(^|\n)(create|drop|select|returns|declare)[ \t]+(view|table)[ \t]+/i

    condition:
        mime startswith "text"
        and for all of them : ( # > 2 )
}

///////////////////////////////////////////////////////////////////////////////////////////////
// The following have to be at the end with no score since I have no testing files for them. //
///////////////////////////////////////////////////////////////////////////////////////////////

/*
code/go
*/

rule code_go {

    meta:
        type = "code/go"

    strings:
        $ = /(^|\n)[ \t]*import[ \t]+\(/
        $ = /(^|\n)[ \t]*func[ \t]+\w+\(/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/ruby
*/

rule code_ruby {

    meta:
        type = "code/ruby"

    strings:
        $ = /(^|\n)[ \t]*require(_all)?[ \t]*'[\w\/]+'/
        $ = /rescue[ \t]+\w+[ \t]+=>/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/perl
*/

rule code_perl {

    meta:
        type = "code/perl"

    strings:
        $ = /(^|\n)[ \t]*my[ \t]+\$\w+[ \t]*=/
        $ = /(^|\n)[ \t]*sub[ \t]+\w+[ \t]*{/
        $ = /(^|\n)[ \t]*package[ \t]+[\w\.]+;", b"@_/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/rust
*/

rule code_rust {

    meta:
        type = "code/rust"

    strings:
        $ = /(^|\n)(pub|priv)[ \t]+(struct|enum|impl|const)[ \t]+/
        $ = /(^|\n)[ \t]*fn[ \t]+\w+[ \t]*\(&self/
        $ = /(println!|panic!)/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/lisp
*/

rule code_lisp {

    meta:
        type = "code/lisp"

    strings:
        $ = /(^|\n)[ \t]*\(defvar[ \t]+/
        $ = /(^|\n)[ \t]*\(defmacro[ \t]+/
        $ = /(^|\n)[ \t]*\(eval-when[ \t]+/
        $ = /(^|\n)[ \t]*\(in-package[ \t]+/
        $ = /(^|\n)[ \t]*\(list[ \t]+/
        $ = /(^|\n)[ \t]*\(export[ \t]+/

    condition:
        mime startswith "text"
        and 2 of them
}
