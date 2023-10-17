/*
code/javascript
*/

rule code_javascript {
    meta:
        type = "code/javascript"
        score = 1

    strings:
        $not_html = /^\s*<\w/

        $strong_js2  = /\beval[ \t]*\(['"]/

        // jscript
        $strong_js3  = /new[ \t]+ActiveXObject\(/

        $strong_js4  = /Scripting\.Dictionary['"]/
        $strong_js5  = "unescape("
        $strong_js6  = ".createElement("
        $strong_js7  = /submitForm\(['"]/
        $strong_js8  = /\b(document|window)(\[['"a-zA-Z]|\.)\w+\b/
        $strong_js9  = "setTimeout("
        $strong_js10 = /(^|;|\s)(var|let|const)[ \t]+\w+[ \t]*=/
        // If this is exactly in the sample, will trigger a second time because of strong_js10
        $strong_js11 = /(^|\n)window.location.href[ \t]*=/

        // Used in a lot of malware samples to fail silently
        $strong_js12 = /catch\s+\(\w*\)\s+\{/

        // Firefox browser specific method
        $strong_js13 = /user_pref\("[\w.]+",\s*[\w"']+\)/

        // This method of function declaration is shared with PowerShell, so it should be considered weak-ish
        $function_declaration  = /(^|;|\s|\(|\*\/)function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/

        $weak_js2 = /String(\[['"]|\.)(fromCharCode|raw)(['"]\])?\(/
        $weak_js3 = /Math\.(round|pow|sin|cos)\(/
        $weak_js4 = /(isNaN|isFinite|parseInt|parseFloat|toLowerCase|toUpperCase)\(/
        $weak_js5 = /([^\w]|^)this\.[\w]+/
        $weak_js6 = /([^\w]|^)[\w]+\.length/

    condition:
        // Note that application/javascript is obsolete
        not $not_html
        and (
                (
                    (
                        mime startswith "text" or mime == "application/javascript"
                    )
                    and (
                        2 of ($strong_js*)
                        or (
                            1 of ($strong_js*)
                            and 2 of ($weak_js*)
                        )
                        or (
                            // A bunch of function declarations is not enough since the function declaration syntax is
                            // shared between JavaScript and PowerShell. Therefore, look for an additional indicator.
                            $function_declaration
                            and (
                                1 of ($strong_js*)
                                or 1 of ($weak_js*)
                            )
                        )
                    )
                )
                or (
                    mime == "application/octet-stream"
                    and 4 of ($strong_js*)
                )
            )
}

/*
code/jscript
*/

rule code_jscript {

    meta:
        type = "code/jscript"
        score = 5

    strings:
        $jscript1 = "ActiveXObject" fullword
        $jscript2 = "= GetObject("
        $jscript3 = "WScript.CreateObject("

        // Conditional comments
        $jscript4 = "/*@cc_on"
        $jscript5 = "@*/"
        $jscript6 = "/*@if (@_jscript_version >= "
        $jscript7 = "/*@end"

    condition:
        code_javascript
        and 1 of ($jscript*)
}

/*
code/xfa
*/

rule code_xfa {

    meta:
        type = "code/xfa"
        score = 5

    strings:
        $xfa1 = /xfa\.([\w]*[.)=( ]){2,}/
        $xfa2 = "ui.oneOfChild."
        $xmlns_url = "http://www.xfa.org/schema/xfa-template/"

    condition:
        1 of ($xfa*)
        and $xmlns_url in (0..256)
}

/*
code/vbs
*/

rule code_vbs {

    meta:
        type = "code/vbs"
        score = 2

    strings:
        $multiline = " = @'\r\n" //powershell multiline string

        $strong_vbs1 = /(^|\n)On[ \t]+Error[ \t]+Resume[ \t]+Next/i ascii wide
        $strong_vbs2 = /(^|\n|\()(Private|Public)?[ \t]*(Sub|Function)[ \t]+\w+\([ \t]*((ByVal[ \t]+)?\w+([ \t]+As[ \t]+\w+)?,?)*\)[ \t]*[\)\r]/i ascii wide
        $strong_vbs3 = /(^|\n)[ \t]*End[ \t]+(Module|Function|Sub|If)/i ascii wide
        $strong_vbs4 = "\nExecuteGlobal" ascii wide
        $strong_vbs6 = /(^|\n|:)(Attribute|Set|const)[ \t]+\w+[ \t]+=/i ascii wide
        $strong_vbs7 = /(^|\n)[ \t]*Err.Raise[ \t]+\d+(,[ \t]+"[^"]+")+/i ascii wide
        $strong_vbs8 = /[ \t(=]replace\(/i ascii wide
        // CreateObject("blah")
        $strong_vbs9 = "CreateObject(" nocase ascii wide
        $strong_vbs10 = "GetObject(" nocase ascii wide
        $strong_vbs11 = "\nEval(" nocase ascii wide
        $strong_vbs12 = "Execute(" nocase ascii wide
        $strong_vbs13 = "\nMsgBox \"" nocase ascii wide
        // Dim blah
        $weak_vbs1 = /\bDim\b\s+\w+[\r:]/i ascii wide

    condition:
        not code_javascript and not $multiline
        and (2 of ($strong_vbs*)
            or (1 of ($strong_vbs*)
            and (#weak_vbs1) > 3))
}

/*
code/xml
*/

rule code_xml {

    meta:
        type = "code/xml"

    strings:
        $header = /^\s*<\?xml[^>]+\?>/
        $ns1 = /<xml[^>]+xmlns[:=][^>]+>/
        $ns2 = "</xml>"

    condition:
        $header
        or all of ($ns*)
}

/*
code/xml
*/

rule code_xml_start_tag {

    strings:
        $tag_start = /\s*<[^\/<>\n][^<>]*>/

    condition:
        $tag_start in (0..256)
}

/*
code/xml
*/

rule code_xml_end_tag {

    strings:
        $tag_end = /<\/[^<>\n]+>\s*$/

    condition:
        $tag_end in (filesize-256..filesize)
}

/*
code/xml
*/

rule code_xml_tags {

    meta:
        type = "code/xml"

    condition:
        code_xml_start_tag and code_xml_end_tag
}

/*
code/html
*/

rule code_html_1 {

    meta:
        type = "code/html"
        score = 10

    strings:
        $html_doctype = /(^|\n|\>)[ \t]*<!doctype html>/i
        $html_start = /(^|\n|\>)[ \t]*<html/i
        $html_end = /(^|\n|\>)[ \t]*<\/html/i

    condition:
        $html_doctype in (0..256)
        or $html_start in (0..256)
        or $html_end in (filesize-256..filesize)
}

/*
code/html
*/

rule code_html_2 {

    meta:
        type = "code/html"
        score = 10

    strings:
        $html_tag = /(^|\n)\s*<(div|script|body|head|img|iframe|pre|span|style|table|title|strong|link|input|form)[ \t>]/i

    condition:
        code_xml_tags
        and $html_tag
}

/*
code/html
*/

rule code_html_3 {

    meta:
        type = "code/html"
        score = 10

    strings:
        $bad_html_tag = /(^|\n)\s*<(body)[ \t>]/i
        $html_void_tag = /(^|\n)\s*<(area|base|br|col|command|embed|hr|img|input|keygen|link|meta|param|source|track|wbr)[ \t>]/i

    condition:
        code_xml_start_tag
        and ($html_void_tag or $bad_html_tag)
}

/*
code/html/application
*/

rule code_html_application {

    meta:
        type = "code/hta"
        score = 12

    strings:
        $hta = /(^|\n|\>)[ \t]*<hta:application /i

    condition:
        $hta
}

/*
code/html/component
*/

rule code_html_component {

    meta:
        type = "code/html/component"
        score = 10

    strings:
        $component1 = "public:component " nocase
        $component2 = "/public:component" nocase
        $script = "<script" nocase
        $lang_js1 = "language=\"javascript\"" nocase
        $lang_js2 = "language=\"jscript\"" nocase
        $lang_js3 = "language=\"js\"" nocase
        $lang_js4 = "type=\"text/javascript\"" nocase
        $lang_vbs1 = "language=\"vbscript\"" nocase
        $lang_vbs2 = "language=\"vb\"" nocase
        $lang_vbs3 = "type=\"text/vbscript\"" nocase

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
        $rec = "From:"
        $subrec1 = "Bcc:"
        $subrec2 = "To:"
        $subrec3 = "Date:"
        $opt1 = "Subject:"
        $opt2 = "Received: from"
        $opt3 = "MIME-Version:"
        $opt4 = "Content-Type:"

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
        $ = /(^|\n)From: /
        $ = /(^|\n)MIME-Version: /
        $ = /(^|\n)Content-Type: multipart\/mixed;\s*boundary=/

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
        score = 2

    strings:
        $invalid_keys1 = /^\s*\w+:[\s]*[\{\["\d]/
        $valid_keys1 = /"\w+":[\s]*[\{\["\d]/

    condition:
        // "{" at 0
        uint8(0) == 0x7B
        // "}" at filesize-1
        and uint8(filesize-1) == 0x7D
        and 0 of ($invalid_keys*)
        and $valid_keys1
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
        $rec4 = "$this->"
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
        $xml_begin = "<jsp:"
        $xml_end = "</jsp:"
        $non_xml_begin = "<%"
        $non_xml_end = "%>"
        $java1 = "FileOutputStream"
        $java2 = "System.getProperty"
        $java3 = "public void"
        $java4 = "public Class"
        $java5 = "ClassLoad"
        $java6 = "java.util.*"
        $jsp1 = "<%@ page"
        $jsp2 = "<%@ include"
        $jsp3 = "<%@ taglib"

    condition:
        mime startswith "text"
        and (
            all of ($xml*)
            or 2 of ($jsp*)
            or (
                #non_xml_begin >= 2
                and #non_xml_end >= 2
                and (#java1 + #java2 + #java3 + #java4 + #java5 + #java6) >= 2
            )
        )
}

/*
code/ps1
*/

rule code_ps1 {

    meta:
        type = "code/ps1"
        score = 1

    strings:
        $strong_pwsh1 = /(IWR|Add-(MpPreference|Type)|Start-(BitsTransfer|Sleep)|Get-(ExecutionPolicy|Service|Process|Counter|WinEvent|ChildItem|Variable|Item)|Where-Object|ConvertTo-HTML|Select-Object|Clear-(History|Content)|ForEach-Object|Compare-Object|New-(ItemProperty|Object|WebServiceProxy)|Set-(Alias|Location|Item)|Wait-Job|Test-Path|Rename-Item|Stop-Process|Out-String|Write-Error|Invoke-(Expression|WebRequest))\b/i ascii wide
        $strong_pwsh2 = /(-ExclusionPath|-memberDefinition|-Name|-namespace|-passthru|-command|-TypeName|-join|-split|-sou|-dest|-property|-OutF(ile)?|-ExecutionPolicy Bypass|-uri|-AllowStartIfOnBatteries|-MultipleInstances|-TaskName|-Trigger)\b/i ascii wide
        $strong_pwsh3 = /(\.Get(String|Field|Type|Method)|FromBase64String)\(/i ascii wide
        $strong_pwsh4 = "System.Net.WebClient" nocase ascii wide
        $strong_pwsh5 = "Net.ServicePointManager" nocase ascii wide
        $strong_pwsh6 = "Net.SecurityProtocolType" nocase ascii wide
        $strong_pwsh7 = /\[(System\.)?Text\.Encoding\]::UTF8/i ascii wide
        $strong_pwsh8 = /\[(System\.)?Convert\]::ToInt32/i ascii wide
        $strong_pwsh9 = /\[(System\.)?String]::Join\(/i ascii wide
        $strong_pwsh10 = /\[byte\[\]\][ \t]*\$\w+[ \t]*=/i ascii wide
        $strong_pwsh11 = /\[Microsoft\.VisualBasic\.(Interaction|CallType)\]/i ascii wide
        $strong_pwsh12 = /[ \t;\n]foreach[ \t]*\([ \t]*\$\w+[ \t]+in[ \t]+[^)]+\)[ \t;\n]*{/i ascii wide
        $strong_pwsh13 = /\bfunction[ \t]+\w+[ \t]*\([^)]*\)[ \t\n]*{/i ascii wide
        $strong_pwsh14 = /\[char\][ \t]*(\d\d|0x[0-9a-f]{1,2})/i ascii wide
        $weak_pwsh1 = /\$\w+[ \t]*=[ \t]*[^;\n|]+[;\n|]/ ascii wide

        // https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.3
        // Equality
        $weak_pwsh2 = /\s\-[ic]?(eq|ne|gt|ge|lt|le)\s/ ascii wide
        // Matching
        $weak_pwsh3 = /\s\-[ic]?(like|notlike|match|notmatch)\s/ ascii wide
        // Replacement
        $weak_pwsh4 = /\s\-[ic]?(replace)\s/ ascii wide
        // Containment
        $weak_pwsh5 = /\s\-[ic]?(contains|notcontains|in|notin)\s/ ascii wide
        // Type
        $weak_pwsh6 = /\s\-[ic]?(is|isnot)\s/ ascii wide

        // https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logical_operators?view=powershell-7.3
        $weak_pwsh7 = /[\s\(]\-(not)\s/ ascii wide
        $weak_pwsh8 = /\s\-(and|or|xor)\s/ ascii wide

        // This method of function declaration is shared with JavaScript, so it should be considered weak
        $weak_pwsh9  = /(^|;|\s|\(|\*\/)function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/

    condition:
        (
            mime startswith "text"
            and
                (
                    2 of ($strong_pwsh*)
                    or
                    3 of them
                )
        ) or (
            mime == "application/octet-stream"
            and 3 of ($strong_pwsh*)
        )
}

rule code_ps1_in_ps1 {

    meta:
        type = "code/ps1"
        score = -1

    strings:
        $power = /(^|\n|@|&)\^?p(\^|%.+%)?o(\^|%.+%)?w(\^|%.+%)?e(\^|%.+%)?r(\^|%.+%)?s(\^|%.+%)?h(\^|%.+%)?e(\^|%.+%)?l(\^|%.+%)?l(\^|%.+%)?[ \t-.]/i

    condition:
        code_ps1 and $power
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
        $ = /ULONG|HRESULT|STDMETHOD/
        $ = "THIS"
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
        $ = /(^|\n)#version\s+\d{1,4}/
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
        $strong_py1 = /(^|\n)[ \t]*if[ \t]+__name__[ \t]*==[ \t]*['"]__main__['"][ \t]*:/
        $strong_py2 = /(^|\n)[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]+[\w.*]+/
        $strong_py3 = /(^|\n)[ \t]*def[ \t]*\w+[ \t]*\([^)]*\)[ \t]*:/
        $strong_py4 = /(try:|except:|else:)/
        // High confidence one-liner used to execute base64 blobs
        $strong_py5 = /exec\(__import__\(['"]base64['"]\)\.b64decode\(__import__\(['"]codecs['"]\)\.getencoder\(/

    condition:
        mime startswith "text"
        and (2 of ($strong_py*) or $strong_py5)
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
        $ = ".hasNext("
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
        $ = /(^|\n)[ \t]*option[ \t]+\w+[ \t]+=[ \t]+[^;\n]+[ \t]*;/

    condition:
        mime startswith "text"
        and 2 of them
}

/*
code/clickonce
*/

rule code_clickonce {

    meta:
        type = "code/clickonce"

    strings:
        $ns1 = /^\s*<assembly[^>]+xmlns=[^>]+>/
        $ns2 = "</assembly>"

    condition:
       all of ($ns*)
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
code/ducky
*/

rule code_ducky {
    meta:
        type = "code/ducky"

    strings:
        $commands = /(^|\n)(REM|REM_BLOCK|END_REM|STRING|END_STRING|STRINGLN|END_STRINGLN|DELAY|ENTER|GUI)/

    condition:
        mime startswith "text"
        and #commands >= 10

}

rule code_batch {

    meta:
        type = "code/batch"
        score = 2

    strings:
        $obf1 = /%[^:\n\r%]+:~[ \t]*[\-+]?\d{1,3},[ \t]*[\-+]?\d{1,3}%/
        // Example: %blah1%%blah2%%blah3%%blah4%%blah5%%blah6%%blah7%%blah8%%blah9%%blah10%
        $obf2 = /\%([^:\n\r\%]+(\%\%)?)+\%/
        // powershell does not need to be followed with -c or -command for it to be considered batch
        $power1 = /(^|\n|@|&|\b)\^?p(\^|%[^%\n]{0,100}%)?o(\^|%[^%\n]{0,100}%)?w(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?r(\^|%[^%\n]{0,100}%)?s(\^|%[^%\n]{0,100}%)?h(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?(\.(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?x(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?)?\b/i
        // check for it seperately
        $command = /(-c|-command)(\^|%[^%\n]{0,100}%)?[ \t]/i

        // del is not a batch-specific command, and is an alias for Remove-Item in PowerShell.
        // Therefore do not include it in the command set for batch.
        $cmd1 = /(^|\n|@|&)(echo|netsh|goto|pkgmgr|netstat|taskkill|vssadmin|tasklist|schtasks)[ \t][\/]?\w+/i
        $cmd2 = /(^|\n|@|&)net[ \t]+(share|stop|start|accounts|computer|config|continue|file|group|localgroup|pause|session|statistics|time|use|user|view)/i
        $cmd3 = /(^|\n|@|&)reg[ \t]+(delete|query|add|copy|save|load|unload|restore|compare|export|import|flags)[ \t]+/i
        $cmd4 = /(^|\n|@|&|^\s)start[ \t]+(\/(min|b|wait|belownormal|abovenormal|realtime|high|normal|low|shared|seperate|max|i)[ \t]+|"\w*"[ \t]+)+["']?([A-Z]:)?([\\|\/]?[\w.]+)+/i
        $cmd5 = /(^|\n)exit\s*$/i
        $cmd6 = /(^|\n|@|&)%comspec%/i
        $cmd7 = /(^|\n|@|&)timeout[ \t](\/\w+|[-]?\d{1,5})/i
        $rem1 = /(^|\n|@|&)\^?r\^?e\^?m\^?[ \t]\w+/i
        $rem2 = /(^|\n)::/
        $set = /(^|\n|@|&)\^?s\^?e\^?t\^?[ \t]\^?\w+\^?=\^?\w+/i
        $exp = /setlocal[ \t](enableDelayedExpansion|disableDelayedExpansion)/i

    condition:
        (mime startswith "text" or uint16(0) == 0xFEFF)  // little-endian utf-16 BOM at 0
        and (for 1 of ($obf1) :( # > 3 )
             // powershell can have a command in it that looks like this: "powershell -command blah"
             // so we need something else
             or ($power1 and $command and (1 of ($cmd*) or 1 of ($rem*)))
             or ($power1 and 1 of ($cmd*))
             or for 1 of ($cmd*) :( # > 3 )
             or $exp
             or (2 of ($cmd*)
                and (#rem1+#rem2+#set) > 4))
             or (for 1 of ($obf2) :( # > 3 )
                and 1 of ($cmd*)
                and (#rem1+#rem2+#set) > 4)
}

rule code_batch_small {

    meta:
        type = "code/batch"
        score = -1

    strings:
        $batch1 = /(^|\n|@|&| )\^?s\^?t\^?a\^?r\^?t\^?[ \t]+(\/(min|b|wait|belownormal|abovenormal|realtime|high|normal|low|shared|seperate|max|i)[ \t]+|"\w*"[ \t]+)*["']?([A-Z]:)?([\\|\/]?[\w.]+)+/i
        $batch2 = /%[^:\n\r%]+:~[ \t]*[\-+]?\d{1,3},[ \t]*[\-+]?\d{1,3}%/
        $batch3 = /(^|\n|@|&| )\^?f\^?i\^?n\^?d\^?s\^?t\^?r\^?[ \t]+["][^"]+["][ \t]+(["][^"]+["]|[^[ \t]+)[ \t]+>[ \t]+[^[ \t\n]+/i
        $batch4 = /(^|\n| )[ "]*([a-zA-Z]:)?(\.?\\[^\\\n]+|\.?\/[^\/\n]+)+\.(exe|bat|cmd|ps1)[ "]*(([\/\-]?\w+[ "]*|&)[ \t]*)*($|\n)/i
        $batch5 = /(^|\n| ) *[\w\.]+\.(exe|bat|cmd|ps1)( [\-\/"]?[^ \n]+"?)+ *($|\n)/i
        $batch6 = /(^|\n|@|&| )(timeout|copy|taskkill|tasklist|vssadmin|schtasks)( ([\/"]?[\w\.:\\\/]"?|&)+)+/i
        $rem = /(^|\n|@|&)\^?r\^?e\^?m\^?[ \t]\w+/i
        $set = /(^|\n|@|&)\^?s\^?e\^?t\^?[ \t]\^?\w+\^?=\^?\w+/i

    condition:
        (mime startswith "text" or uint16(0) == 0xFEFF)  // little-endian utf-16 BOM at 0
        and filesize < 512
        and (1 of ($batch*)
            or (#rem+#set) > 4)
}

/*
document/ps
*/

rule document_ps {

    meta:
        type = "document/ps"

    strings:
        $header = /(^|\n)%!PS[ \t]*\n/
        $opt1 = /(^|\n)[ \t]+\d+[ \t]+(selectfont|scalefont|setlinejoin|setlinewidth)/
        $opt2 = /(^|\n)[ \t]+\d+[ \t]+\d+[ \t]+(moveto|lineto|scale|translate)/
        $opt3 = /(^|\n)[ \t]+(showpage|newpath|stroke|setfont)/
        $opt4 = /(^|\n)[ \t]+\([^\)]+\)[ \t]+show/

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
        $strong1 = "(defvar" fullword
        $strong2 = "(defmacro" fullword
        $strong3 = "(eval-when" fullword
        $strong4 = "(in-package" fullword
        $weak1 = "(list" fullword
        $weak2 = "(export" fullword

    condition:
        mime startswith "text"
        and 1 of ($strong*)
        and 2 of them
}

/*
code/wsf
*/

rule code_wsf {

    meta:
        type = "code/wsf"
        score = 10

    strings:
        $ = "<job"
        $ = /<script\s+?language=/

    condition:
        mime startswith "text"
        and all of them
}

/*
code/wsc
*/

rule code_wsc {

    meta:
        type = "code/wsc"
        score = 10

    strings:
        $ = "<component"
        $ = /<script\s+?language=/

    condition:
        mime startswith "text"
        and all of them
}

/*
archive/udf
*/

rule archive_udf {

    meta:
        type = "archive/udf"
        score = 1

    strings:
        $ID1 = "CD001"
        $ID2 = "BEA01"
        $ID3 = "NSR02"
        $ID4 = "NSR03"
        $ID5 = "BOOT2"
        $ID6 = "TEA01"

    condition:
        3 of ($ID*) in (0x8000..0x10000)
}

/*
code/a3x
Source: https://github.com/CAPESandbox/community/blob/master/data/yara/binaries/AutoIT.yar
*/

rule code_a3x {
    meta:
        type = "code/a3x"
        description = "Identifies AutoIT script."
        author = "@bartblaze"
        date = "2020-09"
        tlp = "White"

    strings:
        $ = "#OnAutoItStartRegister" ascii wide
        $ = "#pragma compile" ascii wide
        $ = "/AutoIt3ExecuteLine" ascii wide
        $ = "/AutoIt3ExecuteScript" ascii wide
        $ = "/AutoIt3OutputDebug" ascii wide
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide
        $ = "AU3!EA06" ascii wide

    condition:
        uint16(0) != 0x5A4D and any of them
}
