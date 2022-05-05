/*
code/javascript
*/

rule code_javascript_1 {
    meta:
        type = "code/javascript"

    strings:
        $script = "<script" nocase
        $lang_js1 = "language=\"javascript\"" nocase
        $lang_js2 = "language=\"jscript\"" nocase
        $lang_js3 = "language=\"js\"" nocase
        $lang_js4 = "type=\"text/javascript\"" nocase

    condition:
        mime startswith "text"
        and $script
        and 1 of ($lang*)
}

rule code_javascript_2 {
    meta:
        type = "code/javascript"

    strings:
        $strong_js1 = /function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/
        $strong_js2 = /\beval[ \t]*\("/
        $strong_js3 = /new[ \t]+ActiveXObject\("/
        $strong_js4 = /xfa\.((resolve|create)Node|datasets|form)"/
        $strong_js5 = /\.oneOfChild"/
        $strong_js6 = /unescape\(/
        $strong_js7 = /\.createElement\(/
        $strong_js8 = /submitForm\("/
        $strong_js9 = /document\.write\(/
        $strong_js10 = /setTimeout\(/

        $weak_js1 = /var /
        $weak_js2 = /String\.(fromCharCode|raw)\(/
        $weak_js3 = /Math\.(round|pow|sin|cos)\(/
        $weak_js4 = /(isNaN|isFinite|parseInt|parseFloat)\(/
        $weak_js5 = /WSH/
        $weak_js6 = /(document|window)\[/
        $weak_js7 = /([^\w]|^)this\.[\w]+/

    condition:
        mime startswith "text"
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
        $jscript2 = /Scripting\.Dictionary"/

    condition:
        1 of (code_javascript*)
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
        $pdfjs1 = /xfa\.((resolve|create)Node|datasets|form)/
        $pdfjs2 = /\.oneOfChild"/

    condition:
        1 of (code_javascript*)
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
        $strong_vbs9 = /replace\(([\"']?.+[\"']?,){2}([\"']?.+[\"']?)\)/
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
code/html
*/

rule code_hta {

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
        $lang_vbs1 = "language=\"vbscript\"" nocase
        $lang_vbs2 = "language=\"vb\"" nocase

    condition:
        code_html
        and $script
        and 1 of ($lang*)
}

rule code_html_with_js {

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
        $rec = "From: "
        $rec2 = "Date: "
        $subrec1 = "Bcc: "
        $subrec2 = "To: "
        $opt1 = "Subject: "
        $opt2 = "Received: from"
        $opt3 = "MIME-Version: "
        $opt4 = "Content-Type: "

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
        $ = "MIME-Version: "
        $ = "Content-Type: "
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
        and none of ($invalid_keys*)
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

    condition:
        mime startswith "text"
        and $php in (0..256)
        and 1 of ($rec*)
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
        $ = /(^|\n)[ \t]*if[ \t]+__name__[ \t]*==[ \t]*[\'\"]__main__[\'\"][ \t]*:/
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




























///////////////////////////////////////////////////////////////////////////////////////////////
// The following have to be at the end with no score since I have no testing files for them. //
///////////////////////////////////////////////////////////////////////////////////////////////

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
