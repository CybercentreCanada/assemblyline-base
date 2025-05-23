/*
code/javascript
*/

rule code_javascript {
    meta:
        type = "code/javascript"
        score = 1

    strings:
        $not_html = /^\s*<(\w|!--)/

        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L431
        $strong_js2  = /\beval[ \t]*\(['"]/ ascii wide

        // jscript
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L659
        $strong_js3  = /new[ \t]+ActiveXObject\(/ ascii wide

        $strong_js4  = /Scripting\.Dictionary['"]/ ascii wide
        $strong_js5  = "unescape(" ascii wide
        $strong_js6  = ".createElement(" ascii wide
        $strong_js7  = /submitForm\(['"]/ ascii wide
        $strong_js8  = /\b(document|window)(\[['"a-zA-Z]|\.)\w+\b/ ascii wide
        $strong_js9  = "setTimeout(" ascii wide
        // Suported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L659
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L431
        $strong_js10 = /(^|;|\s)(var|let|const)[ \t]+\w+[ \t]*=/ ascii wide
        // If this is exactly in the sample, will trigger a second time because of strong_js10
        $strong_js11 = /(^|\n)window.location.href[ \t]*=/ ascii wide

        // Used in a lot of malware samples to fail silently
        $strong_js12 = /catch\s*\(\w*\)\s*\{/ ascii wide

        // Firefox browser specific method
        $strong_js13 = /user_pref\("[\w.]+",\s*[\w"']+\)/ ascii wide

        // Inspired by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L431
        $strong_js14 = "alert(" ascii wide
        $strong_js15 = ".charAt(" ascii wide
        $strong_js16 = "decodeURIComponent(" ascii wide
        $strong_js17 = ".charCodeAt(" ascii wide
        $strong_js18 = ".toString(" ascii wide

        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L659
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L431
        // This method of function declaration is shared with PowerShell, so it should be considered weak-ish
        $function_declaration  = /(^|;|\s|\(|\*\/)function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/ ascii wide

        // In javascript empty parentheses are mandatory for a function without parameters.
        // In powershell empty parentheses are legal but optional and so are usually omitted.
        $empty_function_param = /\bfunction\s+\w+\s*\(\)\s*{/ ascii wide
        // In powershell function calls can have arguments in parentheses or no parentheses, but not empty parentheses.
        $empty_function_call = /\w\(\);/ ascii wide

        $weak_js2 = /String(\[['"]|\.)(fromCharCode|raw)(['"]\])?\(/ ascii wide
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L431
        $weak_js3 = /Math\.(round|pow|sin|cos)\(/ ascii wide
        $weak_js4 = /(isNaN|isFinite|parseInt|parseFloat|toLowerCase|toUpperCase)\(/ ascii wide
        // Supported and inspired by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L659
        $weak_js5 = /([^\w]|^)this[\.\[][\w'"]+/ ascii wide
        // This is shared in PowerShell (although in PowerShell it should be .Length)
        $weak_js6 = /([^\w]|^)[\w]+\.length/ ascii wide
        // This is shared in C++
        $weak_js7 = /([^\w]|^)[\w]+\.substr\(/ ascii wide

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
                            // shared between JavaScript and PowerShell. Therefore, look for an additional indicator(s).
                            $function_declaration
                            and (
                                1 of ($strong_js*)
                                or 2 of ($weak_js*)
                            )
                        )
                        or (
                            $empty_function_param
                            and $empty_function_call
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
        $jscript1 = "ActiveXObject" fullword ascii wide
        $jscript2 = "= GetObject(" ascii wide
        $jscript3 = "WScript.CreateObject(" ascii wide

        // Conditional comments
        $jscript4 = "/*@cc_on" ascii wide
        $jscript5 = "@*/" ascii wide
        $jscript6 = "/*@if (@_jscript_version >= " ascii wide
        $jscript7 = "/*@end" ascii wide

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

        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L485
        $strong_vbs1 = /(^|\n)On[ \t]+Error[ \t]+Resume[ \t]+Next/i ascii wide
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L485
        $strong_vbs2 = /(^|\n|\()(Private|Public)?[ \t]*(Sub|Function)[ \t]+\w+\([ \t]*((ByVal[ \t]+)?\w+([ \t]+As[ \t]+\w+)?,?)*\)[ \t]*[\)\r]/i ascii wide
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L485
        $strong_vbs3 = /(^|\n|:)[ \t]*End[ \t]+(Module|Function|Sub|If)($|\s)/i ascii wide
        $strong_vbs4 = "\nExecuteGlobal" ascii wide
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L485
        $strong_vbs6 = /(^|\n|:)(Attribute|Set|const)[ \t]+\w+[ \t]+=/i ascii wide
        $strong_vbs7 = /(^|\n)[ \t]*Err.Raise[ \t]+\d+(,[ \t]+"[^"]+")+/i ascii wide
        $strong_vbs8 = /[ \t(=]replace\(/i ascii wide
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        // CreateObject("blah")
        $strong_vbs9 = "CreateObject(" nocase ascii wide
        $strong_vbs10 = "GetObject(" nocase ascii wide
        $strong_vbs11 = "\nEval(" nocase ascii wide
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        $strong_vbs12 = /(^|\n|:)[ \t]*Execute[( \t]/ nocase ascii wide
        $strong_vbs13 = "\nMsgBox \"" nocase ascii wide
        // Inspired by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L650
        $strong_vbs14 = /[ \t(=]Array\(/i ascii wide
        $strong_vbs15 = "& Chr(" nocase ascii wide
        $weak_vbs1 = "\"Scripting.FileSystemObject\"" nocase ascii wide
        $weak_vbs2 = ".OpenAsTextStream(" nocase ascii wide
        $weak_vbs3 = ".CreateTextFile" nocase ascii wide
        // Dim blah
        // Supported by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L485
        $dim_declaration = /\bDim\b\s+\w+[\r:]/i ascii wide

    condition:
        not code_javascript and not $multiline
        and (
            2 of ($strong_vbs*)
            or (
                1 of ($strong_vbs*)
                and (
                    (#dim_declaration) > 1
                    or 2 of ($weak_vbs*)
                )
            )
        )
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
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L670
        $html_doctype = /(^|\n|\>)[ \t]*<!doctype html>/i
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L670
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
        $html_comment_start = "<!--"
        $html_comment_end = "-->"

    condition:
        (
            code_xml_start_tag
            or $html_comment_start in (0..64)
        )
        and (
            code_xml_end_tag
            or $html_comment_end in (filesize-64..filesize)
        )
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
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L670
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
        // This is a common JavaScript key
        $rec = "From:"
        $subrec1 = "Bcc:"
        // This is a common JavaScript key
        $subrec2 = "To:"
        $subrec3 = "Date:"
        // This is a common JavaScript key
        $opt1 = "Subject:"
        $opt2 = "Received: from"
        $opt3 = "MIME-Version:"
        $opt4 = "Content-Type:"

    condition:
        // This is a relatively* trusted mime for identifying JavaScript that could be mis-identified as emails
        mime != "application/javascript"
        and
        (
            all of ($rec*)
            and 1 of ($subrec*)
            and 1 of ($opt*)
        )
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
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L671
        // Supported and inspired by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L406
        $strong_pwsh1 = "IWR" nocase ascii wide fullword
        $strong_pwsh2 = "Add-MpPreference" nocase ascii wide fullword
        $strong_pwsh3 = "Add-Type" nocase ascii wide fullword
        $strong_pwsh4 = "Start-BitsTransfer" nocase ascii wide fullword
        $strong_pwsh5 = "Start-Sleep" nocase ascii wide fullword
        $strong_pwsh6 = "Start-Process" nocase ascii wide fullword
        $strong_pwsh7 = "Get-ExecutionPolicy" nocase ascii wide fullword
        $strong_pwsh8 = "Get-Service" nocase ascii wide fullword
        $strong_pwsh9 = "Get-Process" nocase ascii wide fullword
        $strong_pwsh10 = "Get-Counter" nocase ascii wide fullword
        $strong_pwsh11 = "Get-WinEvent" nocase ascii wide fullword
        $strong_pwsh12 = "Get-ChildItem" nocase ascii wide fullword
        $strong_pwsh13 = "Get-Variable" nocase ascii wide fullword
        $strong_pwsh14 = "Get-Item" nocase ascii wide fullword
        $strong_pwsh15 = "Get-WmiObject" nocase ascii wide fullword
        $strong_pwsh16 = "Where-Object" nocase ascii wide fullword
        $strong_pwsh17 = "ConvertTo-HTML" nocase ascii wide fullword
        $strong_pwsh18 = "Select-Object" nocase ascii wide fullword
        $strong_pwsh19 = "Clear-History" nocase ascii wide fullword
        $strong_pwsh20 = "Clear-Content" nocase ascii wide fullword
        $strong_pwsh21 = "ForEach-Object" nocase ascii wide fullword
        $strong_pwsh22 = "Compare-Object" nocase ascii wide fullword
        $strong_pwsh23 = "New-ItemProperty" nocase ascii wide fullword
        $strong_pwsh24 = "New-Object" nocase ascii wide fullword
        $strong_pwsh25 = "New-WebServiceProxy" nocase ascii wide fullword
        $strong_pwsh26 = "Set-Alias" nocase ascii wide fullword
        $strong_pwsh27 = "Set-Location" nocase ascii wide fullword
        $strong_pwsh28 = "Set-Item" nocase ascii wide fullword
        $strong_pwsh29 = "Set-ItemProperty" nocase ascii wide fullword
        $strong_pwsh30 = "Set-StringMode" nocase ascii wide fullword
        $strong_pwsh31 = "Wait-Job" nocase ascii wide fullword
        $strong_pwsh32 = "Test-Path" nocase ascii wide fullword
        $strong_pwsh33 = "Rename-Item" nocase ascii wide fullword
        $strong_pwsh34 = "Stop-Process" nocase ascii wide fullword
        $strong_pwsh35 = "Out-String" nocase ascii wide fullword
        $strong_pwsh36 = "Write-Error" nocase ascii wide fullword
        $strong_pwsh37 = "Invoke-Expression" nocase ascii wide fullword
        $strong_pwsh38 = "Invoke-WebRequest" nocase ascii wide fullword
        $strong_pwsh39 = "Copy-Item" nocase ascii wide fullword
        $strong_pwsh40 = "Import-Module" nocase ascii wide fullword
        $strong_pwsh41 = "Expand-Archive" nocase ascii wide fullword

        $strong_pwsh100 = /(-ExclusionPath|-memberDefinition|-Name|-namespace|-passthru|-command|-TypeName|-join|-split|-sou|-dest|-property|-OutF(ile)?|-ExecutionPolicy Bypass|-uri|-AllowStartIfOnBatteries|-MultipleInstances|-TaskName|-Trigger)\b/i ascii wide
        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L671
        $strong_pwsh101 = /(\.Get(String|Field|Type|Method)|FromBase64String)\(/i ascii wide
        $strong_pwsh102 = "System.Net.WebClient" nocase ascii wide
        $strong_pwsh103 = "Net.ServicePointManager" nocase ascii wide
        $strong_pwsh104 = "Net.SecurityProtocolType" nocase ascii wide
        $strong_pwsh105 = /\[(System\.)?Text\.Encoding\]::UTF8/i ascii wide
        $strong_pwsh106 = /\[(System\.)?Convert\]::ToInt32/i ascii wide
        $strong_pwsh107 = /\[(System\.)?String]::Join\(/i ascii wide
        $strong_pwsh108 = /\[byte\[\]\][ \t]*\$\w+[ \t]*=/i ascii wide
        $strong_pwsh109 = /\[Microsoft\.VisualBasic\.(Interaction|CallType)\]/i ascii wide
        $strong_pwsh110 = /[ \t;\n]foreach[ \t]*\([ \t]*\$\w+[ \t]+in[ \t]+[^)]+\)[ \t;\n]*{/i ascii wide
        $strong_pwsh111 = /\[char\][ \t]*(\d\d|0x[0-9a-f]{1,2})/i ascii wide
        // Inspired by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L671
        $strong_pwsh112 = /\|[ \t]*iex\b/i ascii wide
        // Inspired by https://github.com/CAPESandbox/sflock/blob/1e0ed7e18ddfe723c2d2603875ca26d63887c189/sflock/ident.py#L406
        $strong_pwsh113 = "$PSHOME" nocase ascii wide
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

        // Supported by https://github.com/CERT-Polska/karton-classifier/blob/4cf125296e3a0c1d6c1cb8c16f97d608054c7f19/karton/classifier/classifier.py#L659
        // This method of function declaration is shared with JavaScript, so it should be considered weak
        $weak_pwsh9  = /(^|;|\s|\(|\*\/)function([ \t]*|[ \t]+[\w|_]+[ \t]*)\([\w_ \t,]*\)[ \t\n\r]*{/

    condition:
        (
            mime startswith "text"
            and (
                2 of ($strong_pwsh*)
                or 3 of them
            )
        )
        or (
            mime == "application/octet-stream"
            and 3 of ($strong_pwsh*)
        )
}

rule code_ps1_first_line {

    meta:
        type = "code/ps1"
        score = 5

    strings:
        $strong_pwsh = /^[^\n]*(IWR|Add-(MpPreference|Type)|Start-(BitsTransfer|Sleep|Process)|Get-(ExecutionPolicy|Service|Process|Counter|WinEvent|ChildItem|Variable|Item|WmiObject)|Where-Object|ConvertTo-HTML|Select-Object|Clear-(History|Content)|ForEach-Object|Compare-Object|New-(ItemProperty|Object|WebServiceProxy)|Set-(Alias|Location|Item|ItemProperty|StringMode)|Wait-Job|Test-Path|Rename-Item|Stop-Process|Out-String|Write-Error|Invoke-(Expression|WebRequest)|Copy-Item|Import-Module|Expand-Archive)\b/i ascii wide
        $powershell = /^[^\n]*\^?p(\^|%[^%\n]{0,100}%)?o(\^|%[^%\n]{0,100}%)?w(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?r(\^|%[^%\n]{0,100}%)?s(\^|%[^%\n]{0,100}%)?h(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?(\.(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?x(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?)?\b/i

    condition:
        code_ps1
        and (
            @strong_pwsh[1] < @powershell[1]
            or ($strong_pwsh and not $powershell)
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

rule code_ps1_small {

    meta:
        type = "code/ps1"
        score = 1

    strings:
        $power = "powershell" nocase fullword

    condition:
        filesize < 12288
        and $power at 0
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

        $strong_py20 = "asyncio.run("
        $strong_py21 = "asyncio.sleep("
        $strong_py22 = "pty.spawn("
        $strong_py23 = "platform.system()"
        $strong_py24 = "subprocess.run("
        $strong_py25 = "subprocess.Popen("
        $strong_py26 = "base64.b64decode("
        $strong_py27 = "socket.socket("

        // Setup.py indicators
        $strong_py50 = "python_requires" ascii wide
        $strong_py51 = "setuptools.setup(" ascii wide
        $strong_py52 = "setuptools.find_packages(" ascii wide

        // https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/exfiltrate-sensitive-data.yml
        // and similar
        $strong_py100 = "requests.get("
        $strong_py101 = "requests.post("
        $strong_py102 = "requests.request("
        $strong_py103 = "urllib.request.Request("
        $strong_py104 = "urllib.request.urlopen("
        $strong_py105 = "urllib.urlopen("
        $strong_py106 = "socket.gethostbyname("
        $strong_py107 = "socket.gethostname("
        $strong_py108 = "os.getcwd()"
        $strong_py109 = "getpass.getuser()"
        $strong_py110 = "platform.node()"
        $strong_py111 = "httpx.AsyncClient("
        $strong_py112 = "httpx.Client("
        // https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/silent-process-execution.yml
        $strong_py120 = "subprocess.DEVNULL"
        // https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/clipboard-access.yml
        $strong_py130 = "pyperclip.copy("
        $strong_py131 = "pyperclip.paste()"
        $strong_py132 = "pandas.read_clipboard("
        // https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/obfuscation.yml
        $strong_py140 = "eval(\"\\145\\166\\141\\154\")"
        $strong_py141 = "eval(\"\\x65\\x76\\x61\\x6c\")"
        // https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/download-executable.yml
        $strong_py150 = "os.system("
        $strong_py151 = "os.chmod("
        $strong_py152 = "os.rename("


        // High confidence one-liner used to execute encoded blobs
        // reference: https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/exec-base64.yml
        $executor1 = /((exec|eval|check_output|run|call|[Pp]open|os\.system)\(|lambda[ \t]+\w{1,100}[ \t]*:)\s*(((zlib|__import__\((['"]zlib['"]|['"]\\x0*7a\\x0*6c\\x0*69\\x0*62['"]|['"]\\0*172\\0*154\\0*151\\0*142['"])\)|lzma|__import__\((['"]lzma['"]|['"]\\x0*6c\\x0*7a\\x0*6d\\x0*61['"]|['"]\\0*154\\0*172\\0*155\\0*141['"])\))\.decompress\()|(base64|__import__\((['"]base64['"]|['"]\\x0*62\\x0*61\\x0*73\\x0*65\\x0*36\\x0*34['"]|['"]\\0*142\\0*141\\0*163\\0*145\\0*66\\0*64['"])\))\.b64decode\()/
        $executor2 = /(marshal|__import__\((['"]marshal['"]|['"]\\x0*6d\\x0*61\\x0*72\\x0*73\\x0*68\\x0*61\\x0*6c['"]|['"]\\0*155\\0*141\\0*162\\0*163\\0*150\\0*141\\0*154['"])\)|pickle|__import__\((['"]pickle['"]|['"]\\x0*70\\x0*69\\x0*63\\x0*6b\\x0*6c\\x0*65['"]|['"]\\0*160\\0*151\\0*143\\0*153\\0*154\\0*145['"])\))\.loads\(/

    condition:
        mime startswith "text"
        and (
            2 of ($strong_py*)
            or any of ($executor*)
            or (
                filesize < 1024
                and 1 of ($strong_py*)
            )
        )
}


rule code_python_os_system {

    meta:
        type = "code/python"
        score = -2

    strings:
        $import_os_system1 = "__import__('os').system("
        $import_os_system2 = "__import__(\"os\").system("

    condition:
        mime startswith "text"
        and (
            $import_os_system1 at 0 or $import_os_system2 at 0
            or #import_os_system1 + #import_os_system2 >= 2
        )

}

/*
code/java
*/

rule code_java {

    meta:
        type = "code/java"
        score = 2

    strings:
        $ = /(^|\n)[ \t]*(public|private|protected)[ \t]+((abstract|final)[ \t]+)?class[ \t]+\w+[ \t]*([ \t]+extends[ \t]+\w+[ \t]*)?{/
        $ = /(^|\n)[ \t]*(public|private|protected)[ \t]+(static[ \t]+)?((abstract|final)[ \t]+)?(\w+[ \t]+){2}=/
        $ = /(^|\n)[\w \t]+\([^)]*\)[ \t]+throws[ \t]+\w+[ \t]*(,[ \t]*\w+[ \t]*)*{/
        $ = ".hasNext("
        $ = /[ \t\n]*final[ \t]+\w/
        $ = /(ArrayList|Class|Stack|Map|Set|HashSet|PrivilegedAction|Vector)<(\w|\?)/
        $ = /(^|\n)[ \t]*package[ \t]+[\w\.]+;/
        $ = /(^|\n)[ \t]*public[ \t]+static[ \t]+void[ \t]+main\(String/
        $ = "import java.io.File" ascii wide
        $ = "System.out.println" ascii wide

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
        and mime != "text/html"
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
        $obf2 = /%%\w{1,500}%(%\w{1,500}%){4,30}/
        // powershell does not need to be followed with -c or -command for it to be considered batch
        $power1 = /(^|\n|@|&|\b)\^?p(\^|%[^%\n]{0,100}%)?o(\^|%[^%\n]{0,100}%)?w(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?r(\^|%[^%\n]{0,100}%)?s(\^|%[^%\n]{0,100}%)?h(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?l(\^|%[^%\n]{0,100}%)?(\.(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?x(\^|%[^%\n]{0,100}%)?e(\^|%[^%\n]{0,100}%)?)?\b/i
        // check for it seperately
        $command = /(-c|-command)(\^|%[^%\n]{0,100}%)?[ \t]/i

        // del is not a batch-specific command, and is an alias for Remove-Item in PowerShell.
        // Therefore do not include it in the command set for batch.
        $cmd0 = /(^|\n|@|&)echo[ \t]{1,10}(%\w+%|\w+)/i
        $cmd1 = /(^|\n|@|&)(netsh|goto|pkgmgr|netstat|taskkill|vssadmin|tasklist|schtasks|copy)[ \t][\/]?\w+/i
        $cmd2 = /(^|\n|@|&)net[ \t]+(share|stop|start|accounts|computer|config|continue|file|group|localgroup|pause|session|statistics|time|use|user|view)/i
        $cmd3 = /(^|\n|@|&)reg[ \t]+(delete|query|add|copy|save|load|unload|restore|compare|export|import|flags)[ \t]+/i
        $cmd4 = /(^|\n|@|&|^\s)start[ \t]+(\/(min|b|wait|belownormal|abovenormal|realtime|high|normal|low|shared|seperate|max|i)[ \t]+|"\w*"[ \t]+)+["']?([A-Z]:)?([\\|\/]?[\w.]+)+/i
        $cmd5 = /(^|\n)exit\s*$/i
        $cmd6 = /(^|\n|@|&)%comspec%/i
        $cmd7 = /(^|\n|@|&)timeout[ \t](\/\w+|[-]?\d{1,5})/i
        $cmd8 = /(^|\n|@|&)for[ \t]\/f[ \t]/i
        $rem1 = /(^|\n|@|&)\^?r\^?e\^?m\^?[ \t]\^?\w+/i
        $rem2 = /(^|\n)::/
        $set = /(^|\n|@|&)\^?s\^?e\^?t\^?[ \t]\^?["']?\w+\^?=\^?%?\^?\w+/i
        $exp = /setlocal[ \t](enableDelayedExpansion|disableDelayedExpansion|enableExtensions|disableExtensions)/i

    condition:
        (
            (
                mime startswith "text"
                or uint16(0) == 0xFEFF  // little-endian utf-16 BOM at 0
                or $cmd1 at 0
            )
            and (
                #obf1 > 3
                // powershell can have a command in it that looks like this: "powershell -command blah"
                // so we need something else
                or (
                    $power1
                    and $command
                    and (
                        1 of ($cmd*)
                        or 1 of ($rem*)
                    )
                )
                or (
                    $power1
                    and 1 of ($cmd*)
                )
                or for 1 of ($cmd*) :( # > 3 )
                or $exp
                or (
                    2 of ($cmd*)
                    and (#rem1+#rem2+#set) > 4
                )
            )
        )
        or (
            mime == "application/octet-stream"
            and
            (
                for 1 of ($cmd*) :( # > 20 )
                or (
                    2 of ($cmd*)
                    and (#rem1+#rem2+#set) > 20
                )
            )
        )
        or (
            #obf2 > 3
            and 1 of ($cmd*)
            and (#rem1+#rem2+#set) > 4
        )
        or (
            #obf2 > 10
            and #set > 30
        )
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
        $batch6 = /(^|\n|@|&| )(timeout|taskkill|tasklist|vssadmin|schtasks)( ([\/"]?[\w\.:\\\/]"?|&)+)+/i
        $rem = /(^|\n|@|&)\^?r\^?e\^?m\^?[ \t]\^?\w+/i
        $set = /(^|\n|@|&)\^?s\^?e\^?t\^?[ \t]\^?["']?\w+\^?=\^?\w+/i

    condition:
        (
            mime startswith "text"
            or uint16(0) == 0xFEFF  // little-endian utf-16 BOM at 0
        )
        and filesize < 512
        and (
            1 of ($batch*)
            or (#rem+#set) > 4
        )
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
        $create_or_replace = "CREATE OR REPLACE"
        $table = /(^|\n)(create|drop|select|returns|declare)[ \t]+(view|table)[ \t]+/i

    condition:
        mime startswith "text"
        and (
            #table > 2
            or $create_or_replace
        )
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
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide

        // Supported by https://github.com/CERT-Polska/karton-autoit-ripper/blob/9aef5046d012f4a14f0c12de7a682fad0202c19c/karton/autoit_ripper/autoit.yar
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide
        $ = "AU3!EA06" ascii wide

        // Inspired by https://github.com/CERT-Polska/karton-autoit-ripper/blob/9aef5046d012f4a14f0c12de7a682fad0202c19c/karton/autoit_ripper/autoit.yar
        $ = "AutoIt v3" ascii wide
        $ = "AU3_GetPluginDetails" ascii wide
        $ = "AU3!EA05"
        $ = "AutoIt script files (*.au3, *.a3x)" wide
        $ = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 }
        $ = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 35 }

    condition:
        uint16(0) != 0x5A4D and any of them
}

/*
code/au3
*/

rule code_au3 {

    meta:
        type = "code/au3"
        score = 2

    strings:
        // Keywords: https://www.autoitscript.com/autoit3/docs/keywords.htm
        $strong_keywords = /(ExitLoop|EndFunc|#comments-start|#include-once|#NoTrayIcon|#OnAutoItStartRegister|#pragma|#RequireAdmin|EndWith|EndSwitch)\b/i ascii wide

        // Macros: https://www.autoitscript.com/autoit3/docs/macros.htm
        // 5525cb089669d927874e4b21803cc5186e0e6acfee923990a4cf9c6289bfa4d8 only has one macro, so we should not rely on macros

        // Functions: https://www.autoitscript.com/autoit3/docs/functions/
        $strong_functions = /(WinExists|DllCall|DllStructSetData|DllStructGetSize|DllStructGetData|DllStructCreate|DllStructGetPtr|DllCallbackGetPtr|DllCallAddress|StringInStr|StringLeft|StringStripWS|DllCallbackRegister|AdlibRegister|AdlibUnRegister|AutoItSetOption|AutoItWinGetTitle|AutoItWinSetTitle|DllCallbackFree|GUISetStateHttpSetUserAgent|IniReadSection|IniReadSectionNames|IniRenameSection|IniWriteSection|MouseClickDrag|MouseGetCursor|ObjCreateInterface|OnAutoItExitRegister|OnAutoItExitUnRegister|PixelChecksum|PixelGetColor|ProcessExists|ProcessGetStats|ProcessSetPriority|ProcessWaitClose|SendKeepActive|ShellExecuteWait|SoundSetWaveVolume|SplashImageOn|StatusbarGetText|StringCompare|StringFromASCIIArray|TCPCloseSocket|UDPCloseSocket|WinGetCaretPos|WinGetClassList|WinGetClientSize|WinGetProcess|WinMenuSelectItem|WinMinimizeAll|WinMinimizeAllUndo|WinWaitActive|WinWaitNotActive|GUICreate|GUICtl[a-zA-Z]{1,20}|GUISetState)\b/i ascii wide

        $weak_functions = /(IsBinary|IsString|Execute|IsBool|StringMid|StringLen|FileExists)\b/i ascii wide

    condition:
        // First off, we want at least one strong keyword
        #strong_keywords >= 1
        and mime startswith "text"
        and (
            // Next we are looking for a high-confidence amount of functions
            // If we have 5 or more strong functions, great
            #strong_functions >= 5
            or (
                // If we have at least 10 functions, whether they are strong or weak, that's good too, but we need at
                // least 2 strong functions before we can be confident
                (#strong_functions + #weak_functions) >= 10
                and #strong_functions >= 2
            )
        )
}

rule text_rdp {

    meta:
        type = "text/rdp"
        score = -2

    strings:
        // https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties
        // Connections
        $optional1  = "alternate full address:s:" ascii wide
        $optional2  = "alternate shell:s:" ascii wide
        $optional3  = "authentication level:i:" ascii wide
        $optional4  = "disableconnectionsharing:i:" ascii wide
        $optional5  = "domain:s:" ascii wide
        $optional6  = "enablecredsspsupport:i:" ascii wide
        $optional7  = "enablerdsaadauth:i:" ascii wide
        $mandatory  = "full address:s:" ascii wide // The only mandatory property
        $optional8  = "gatewaycredentialssource:i:" ascii wide
        $optional9  = "gatewayhostname:s:" ascii wide
        $optional10 = "gatewayprofileusagemethod:i:" ascii wide
        $optional11 = "gatewayusagemethod:i:" ascii wide
        $optional12 = "kdcproxyname:s:" ascii wide
        $optional13 = "promptcredentialonce:i:" ascii wide
        $optional14 = "targetisaadjoined:i:" ascii wide
        $optional15 = "username:s:" ascii wide
        // Session behavior
        $optional16 = "autoreconnection enabled:i:" ascii wide
        $optional17 = "bandwidthautodetect:i:" ascii wide
        $optional18 = "compression:i:" ascii wide
        $optional19 = "networkautodetect:i:" ascii wide
        $optional20 = "videoplaybackmode:i:" ascii wide
        // Device redirection
        $optional21 = "audiocapturemode:i:" ascii wide
        $optional22 = "audiomode:i:" ascii wide
        $optional23 = "camerastoredirect:s:" ascii wide
        $optional24 = "devicestoredirect:s:" ascii wide
        $optional25 = "drivestoredirect:s:" ascii wide
        $optional26 = "encode redirected video capture:i:" ascii wide
        $optional27 = "keyboardhook:i:" ascii wide
        $optional28 = "redirectclipboard:i:" ascii wide
        $optional29 = "redirectcomports:i:" ascii wide
        $optional30 = "redirected video capture encoding quality:i:" ascii wide
        $optional31 = "redirectlocation:i:" ascii wide
        $optional32 = "redirectprinters:i:" ascii wide
        $optional33 = "redirectsmartcards:i:" ascii wide
        $optional34 = "redirectwebauthn:i:" ascii wide
        $optional35 = "usbdevicestoredirect:s:" ascii wide
        // Display settings
        $optional36 = "desktop size id:i:" ascii wide
        $optional37 = "desktopheight:i:" ascii wide
        $optional38 = "desktopscalefactor:i:" ascii wide
        $optional39 = "desktopwidth:i:" ascii wide
        $optional40 = "dynamic resolution:i:" ascii wide
        $optional41 = "maximizetocurrentdisplays:i:" ascii wide
        $optional42 = "screen mode id:i:" ascii wide
        $optional43 = "selectedmonitors:s:" ascii wide
        $optional44 = "singlemoninwindowedmode:i:" ascii wide
        $optional45 = "smart sizing:i:" ascii wide
        $optional46 = "use multimon:i:" ascii wide
        // RemoteApp
        $optional47 = "remoteapplicationcmdline:s:" ascii wide
        $optional48 = "remoteapplicationexpandcmdline:i:" ascii wide
        $optional49 = "remoteapplicationexpandworkingdir:i:" ascii wide
        $optional50 = "remoteapplicationfile:s:" ascii wide
        $optional51 = "remoteapplicationicon:s:" ascii wide
        $optional52 = "remoteapplicationmode:i:" ascii wide
        $optional53 = "remoteapplicationname:s:" ascii wide
        $optional54 = "remoteapplicationprogram:s:" ascii wide

        // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/ff393699(v=ws.10)
        $optional55 = "administrative session:i:" ascii wide
        $optional56 = "autoreconnect max retries:i:" ascii wide
        $optional57 = "bitmapcachepersistenable:i:" ascii wide
        $optional58 = "connection type:i:" ascii wide
        $optional59 = "disable ctrl+alt+del:i:" ascii wide
        $optional60 = "disableprinterredirection:i:" ascii wide
        $optional61 = "disableclipboardredirection:i:" ascii wide
        $optional62 = "displayconnectionbar:i:" ascii wide
        $optional63 = "loadbalanceinfo:s:" ascii wide
        $optional64 = "negotiate security layer:i:" ascii wide
        $optional65 = "pinconnectionbar:i:" ascii wide
        $optional66 = "prompt for credentials on client:i:" ascii wide
        $optional67 = "redirectdrives:i:" ascii wide
        $optional68 = "server port:i:" ascii wide
        $optional69 = "session bpp:i:" ascii wide
        $optional70 = "span monitors:i:" ascii wide
        $optional71 = "winposstr:s:" ascii wide
        $optional72 = "workspaceid:s:" ascii wide

        // https://www.donkz.nl/overview-rdp-file-settings/
        $optional73 = "allow desktop composition:i:" ascii wide
        $optional74 = "allow font smoothing:i:" ascii wide
        $optional75 = "audioqualitymode:i:" ascii wide
        $optional76 = "bitmapcachesize:i:" ascii wide
        $optional77 = "connect to console:i:" ascii wide
        $optional78 = "disable full window drag:i:" ascii wide
        $optional79 = "disable menu anims:i:" ascii wide
        $optional80 = "disable themes:i:" ascii wide
        $optional81 = "disable wallpaper:i:" ascii wide
        $optional82 = "disableremoteappcapscheck:i:" ascii wide
        $optional83 = "enablesuperpan:i:" ascii wide
        $optional84 = "password 51:b:" ascii wide
        $optional85 = "prompt for credentials:i:" ascii wide
        $optional86 = "public mode:i:" ascii wide
        $optional87 = "redirectdirectx:i:" ascii wide
        $optional88 = "redirectposdevices:i:" ascii wide
        $optional89 = "shell working directory:s:" ascii wide
        $optional90 = "signature:s:" ascii wide
        $optional91 = "signscope:s:" ascii wide
        $optional92 = "superpanaccelerationfactor:i:" ascii wide

        // Others
        $optional93 = "rdgiskdcproxy:i:" ascii wide
        $optional94 = "use redirection server name:i:" ascii wide
        $optional95 = "gatewaybrokeringtype:i:" ascii wide
        $optional96 = "disable cursor setting:i:" ascii wide
        $optional97 = "enableworkspacereconnect:i:" ascii wide
        $optional98 = "bitmapcachesize:i:" ascii wide

    condition:
        mime startswith "text"
        and $mandatory
        // Add two optionals, to reduce false positives.
        and 2 of ($optional*)
}
