import os
import re
import yara

from collections import defaultdict
from typing import Tuple, Union, Dict

from assemblyline.common.forge import get_constants
from assemblyline.common.str_utils import safe_str

STRONG_INDICATORS = {
    "code/vbs": [
        re.compile(rb"(?i)(^|\n)On[ \t]+Error[ \t]+Resume[ \t]+Next"),
        re.compile(rb"(?i)(^|\n)(?:Private)?[ \t]*Sub[ \t]+\w+\(*"),
        re.compile(rb"(?i)(^|\n)End[ \t]+Module"),
        re.compile(rb"(?i)(^|\n)ExecuteGlobal"),
        re.compile(rb"(?i)(^|\n)REM[ \t]+"),
        re.compile(rb"(?i)(ubound|lbound)\("),
        re.compile(rb"(?i)CreateObject\("),
        re.compile(rb"(?i)\.Run[ \t]+\w+,\d(?:,(?:False|True))?"),
        re.compile(rb"(?i)replace\((?:[\"']?.+?[\"']?,){2}(?:[\"']?.+?[\"']?)\)"),
    ],
    "code/javascript": [
        re.compile(rb"function([ \t]*|[ \t]+[\w]+[ \t]*)\([\w \t,]*\)[ \t\n\r]*{"),
        re.compile(rb"\beval[ \t]*\("),
        re.compile(rb"new[ \t]+ActiveXObject\("),
        re.compile(rb"xfa\.((resolve|create)Node|datasets|form)"),
        re.compile(rb"\.oneOfChild"),
        re.compile(rb"unescape\("),
        re.compile(rb"\.createElement\("),
        re.compile(rb"submitForm\("),
        re.compile(rb"document\.write\("),
    ],
    "code/csharp": [
        re.compile(rb"(^|\n)[ \t]*namespace[ \t]+[\w.]+"),
        re.compile(
            rb"(^|\n)[ \t]*using[ \t]+(static[ \t]+)*([\w.]+;|\w+[ \t]*=[ \t]*[\w.:<>]+;)"
        ),
        re.compile(rb"(^|\n)[ \t]*internal[ \t]+class[ \t]+"),
        re.compile(rb"(^|\n)[ \t]*fixed[ \t]+\("),
        re.compile(rb"IsNullOrWhiteSpace\("),
    ],
    "code/php": [
        re.compile(rb"(^|\n)<\?php"),
        re.compile(rb"namespace[ \t]+[\w.]+"),
        re.compile(rb"function[ \t]+\w+[ \t]*\([ \t]*\$[^)]+\)[ \t\n]*{"),
        re.compile(rb"\beval[ \t]*\("),
    ],
    "code/c": [
        re.compile(rb"(^|\n)(static|typedef)?[ \t]+(struct|const)[ \t]+"),
        re.compile(rb'(^|\n)#include[ \t]*([<"])[\w./]+([>"])'),
        re.compile(rb"(^|\n)#(ifndef|define|endif|pragma)[ \t]+"),
        re.compile(rb"(^|\n)public[ \t]*:"),
        # Microsoft Types
        re.compile(rb"ULONG|HRESULT|STDMETHOD(_)?"),
        re.compile(rb"THIS(_)?"),
    ],
    "code/python": [
        re.compile(
            rb"(^|\n)[ \t]*if[ \t]+__name__[ \t]*==[ \t]*[\'\"]__main__[\'\"][ \t]*:"
        ),
        re.compile(
            rb"(^|\n)[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]+[\w.*]+([ \t]+as \w+)?"
        ),
        re.compile(rb"(^|\n)[ \t]*def[ \t]*\w+[ \t]*\([^)]*\)[ \t]*:"),
    ],
    "code/rust": [
        re.compile(rb"(^|\n)(pub|priv)[ \t]+(struct|enum|impl|const)[ \t]+"),
        re.compile(rb"(^|\n)[ \t]*fn[ \t]+\w+[ \t]*\(&self"),
        re.compile(rb"(println!|panic!)"),
    ],
    "code/lisp": [
        re.compile(
            rb"(^|\n)[ \t]*\((defmacro|defun|eval-when|in-package|list|export|defvar)[ \t]+"
        ),
    ],
    "code/java": [
        re.compile(
            rb"(^|\n)[ \t]*public[ \t]+class[ \t]+\w+[ \t]*([ \t]+extends[ \t]+\w+[ \t]*)?{"
        ),
        re.compile(
            rb"(^|\n)[\w \t]+\([^)]*\)[ \t]+throws[ \t]+\w+[ \t]*(,[ \t]*\w+[ \t]*)*{"
        ),
        re.compile(rb"\.hasNext\("),
        re.compile(rb"[ \t\n]*final[ \t]+\w"),
        re.compile(
            rb"(ArrayList|Class|Stack|Map|Set|HashSet|PrivilegedAction|Vector)<(\w|\?)"
        ),
    ],
    "code/perl": [
        re.compile(rb"(^|\n)[ \t]*my[ \t]+\$\w+[ \t]*="),
        re.compile(rb"(^|\n)[ \t]*sub[ \t]+\w+[ \t]*{"),
    ],
    "code/ruby": [
        re.compile(rb"(^|\n)[ \t]*require(_all)?[ \t]*\'[\w/]+\'"),
        re.compile(rb"rescue[ \t]+\w+[ \t]+=>"),
    ],
    "code/go": [
        re.compile(rb"(^|\n)[ \t]*import[ \t]+\("),
        re.compile(rb"(^|\n)[ \t]*func[ \t]+\w+\("),
    ],
    "code/css": [
        re.compile(
            rb"(^|\n|\})(html|body|footer|span\.|img\.|a\.|\.[a-zA-Z\-.]+)[^{]+{"
            rb"[ \t]*(padding|color|width|margin|background|font|text)[^}]+\}"
        ),
    ],
    "text/markdown": [
        re.compile(rb"\*[ \t]*`[^`]+`[ \t]*-[ \t]*\w+"),
    ],
    "document/email": [
        # Shorter headers are commented out to prevent possible false positives
        re.compile(rb"^ARC-Authentication-Results: ", re.MULTILINE),
        re.compile(rb"^ARC-Message-Signature: ", re.MULTILINE),
        re.compile(rb"^ARC-Seal: ", re.MULTILINE),
        re.compile(rb"^Accept-Language: ", re.MULTILINE),
        re.compile(rb"^Archived-At: ", re.MULTILINE),
        re.compile(rb"^Authentication-Results-Original: ", re.MULTILINE),
        re.compile(rb"^Authentication-Results: ", re.MULTILINE),
        re.compile(rb"^Auto-Submitted: ", re.MULTILINE),
        # re.compile(rb'^Bcc: ', re.MULTILINE),
        # re.compile(rb'^Cc: ', re.MULTILINE),
        re.compile(rb"^Content-Language: ", re.MULTILINE),
        re.compile(rb"^DKIM-Signature: ", re.MULTILINE),
        # re.compile(rb'^Date: ', re.MULTILINE),
        re.compile(rb"^Downgraded-Final-Recipient: ", re.MULTILINE),
        re.compile(rb"^Downgraded-In-Reply-To: ", re.MULTILINE),
        re.compile(rb"^Downgraded-Message-Id: ", re.MULTILINE),
        re.compile(rb"^Downgraded-Original-Recipient: ", re.MULTILINE),
        re.compile(rb"^Downgraded-References: ", re.MULTILINE),
        # re.compile(rb'^From: ', re.MULTILINE),
        re.compile(rb"^In-Reply-To: ", re.MULTILINE),
        # re.compile(rb'^Keywords: ', re.MULTILINE),
        re.compile(rb"^List-Unsubscribe-Post: ", re.MULTILINE),
        re.compile(rb"^MIME-Version: ", re.MULTILINE),
        re.compile(rb"^MT-Priority: ", re.MULTILINE),
        re.compile(rb"^Message-ID: ", re.MULTILINE),
        re.compile(rb"^Original-From: ", re.MULTILINE),
        re.compile(rb"^Original-Recipient: ", re.MULTILINE),
        re.compile(rb"^Original-Subject: ", re.MULTILINE),
        re.compile(rb"^Received-SPF: ", re.MULTILINE),
        re.compile(rb"^Received: ", re.MULTILINE),
        re.compile(rb"^References: ", re.MULTILINE),
        re.compile(rb"^Reply-To: ", re.MULTILINE),
        re.compile(rb"^Require-Recipient-Valid-Since: ", re.MULTILINE),
        re.compile(rb"^Resent-Bcc: ", re.MULTILINE),
        re.compile(rb"^Resent-Cc: ", re.MULTILINE),
        re.compile(rb"^Resent-Date: ", re.MULTILINE),
        re.compile(rb"^Resent-From: ", re.MULTILINE),
        re.compile(rb"^Resent-Message-ID: ", re.MULTILINE),
        re.compile(rb"^Resent-Sender: ", re.MULTILINE),
        re.compile(rb"^Resent-To: ", re.MULTILINE),
        re.compile(rb"^Return-Path: ", re.MULTILINE),
        # re.compile(rb'^Sender: ', re.MULTILINE),
        # re.compile(rb'^Subject: ', re.MULTILINE),
        re.compile(rb"^TLS-Report-Domain: ", re.MULTILINE),
        re.compile(rb"^TLS-Report-Submitter: ", re.MULTILINE),
        re.compile(rb"^TLS-Required: ", re.MULTILINE),
        re.compile(rb"^Thread-Index: ", re.MULTILINE),
        re.compile(rb"^Thread-Topic: ", re.MULTILINE),
        # re.compile(rb'^To: ', re.MULTILINE),
        re.compile(rb"^VBR-Info: ", re.MULTILINE),
        re.compile(rb"^X-EOP-Exchange-Organization-ExtractionTags: ", re.MULTILINE),
        re.compile(rb"^X-EOPAttributedMessage: ", re.MULTILINE),
        re.compile(rb"^X-EOPTenantAttributedMessage: ", re.MULTILINE),
        re.compile(rb"^X-ExternalRecipientOutboundConnectors: ", re.MULTILINE),
        re.compile(rb"^X-Forefront-Antispam-Report-Untrusted: ", re.MULTILINE),
        re.compile(rb"^X-LD-Processed: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-ATPSafeLinks-BitVector: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-ATPSafeLinks-Stat: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-AtpMessageProperties: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-CrossTenant-AuthAs: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-CrossTenant-FromEntityHeader: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-CrossTenant-Id: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-CrossTenant-Network-Message-Id: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-CrossTenant-OriginalArrivalTime: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-ArrivalHubServer: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-EmailMessageHash: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-IndexAgent: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-Language: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-MessageScope: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Forest-RulesExecuted: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-ACSExecutionContext: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-AS-LastExternalIp: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-ASDirectionalityType: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ATPCustomPipelineScanCompleteAction: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ATPDetonation-SonarData-ChunkCount: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ATPDetonationLatency: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ATPSafeLinks-UrlContainer-Data-ChunkCount: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-AVScanComplete: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-AVScannedByV2: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-Antispam-ScanContext: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-AttachmentDetailsHeaderStamp-Success: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-AttachmentDetailsInfo-ChunkCount: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-Auth-DmarcStatus: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-AuthAs: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-Boomerang-Verdict: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-CFA-UserOption: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-CommunicationStateSummary: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-CompAuthReason: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-CompAuthRes: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-ConnectingIP: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-DelayAnalysis-Summary: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-DlpRulesExecuted: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-ExpirationInterval: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-ExpirationIntervalReason: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-ExpirationStartTime: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-ExpirationStartTimeReason: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-ExtractionTagsFrom: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-ExtractionTagsSubject: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ExtractionTagsSubjectNormalized: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-ExtractionTagsURLFound: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-FromEntityHeader: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-GroupForkPerf: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-HMATPModel-DkimAuthStatus: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-HMATPModel-DmarcAuthStatus: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-HMATPModel-Spf: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-HMATPModel-SpfAuthStatus: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-HVERecipientsForked: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-HygienePolicy: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-Id: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-InternalOrgSender,: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-InternalOrgSender: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-IntraOrgSpoof-ImplicitAllowReason: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-IsAtpTenant: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-IsTrialAtpTenant: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-Malware-OriginalScanContext: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-MessageDirectionality: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-MessageScope: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-MxPointsToUs: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-Network-Message-Id: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-OrgEopForest: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-OriginalArrivalTime: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalClientIPAddress: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalServerIPAddress: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-OriginalSize: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalTenant-AuthAs: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalTenant-AuthSource: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalTenant-FromEntityHeader: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-OriginalTenant-Id: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalTenant-Network-Message-Id: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginalTenant-OriginalArrivalTime: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-Originating-Country: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-OriginatorOrganization: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-OutboundCrossTenantAgentProcessed: ",
            re.MULTILINE,
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-PFAHub-Total-Message-Size: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-Persisted-Urls-ChunkCount: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-PersistedUrlCount: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-Processed-By-Gcc-Journaling: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-Recipient-Limit-Verified: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-RunDetonationScan: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-SCL: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-SafeAttachmentPolicy: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-SafeLinksPolicy: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-SenderRecipientCommunicationState: ",
            re.MULTILINE,
        ),
        re.compile(rb"^X-MS-Exchange-Organization-SenderRep-Score: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-SpoofDetection-ImplicitAllow: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-TargetResourceForest: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-TenantServiceProvider: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-TotalRecipientCount: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Organization-Transport-Properties: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Organization-TransportTrafficType: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Exchange-Organization-UrlLogged: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-UrlMinimumDomainAge: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-UrlSelected: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Organization-VBR-Class: ", re.MULTILINE),
        re.compile(rb"^X-MS-Exchange-Safelinks-Url-KeyVer: ", re.MULTILINE),
        re.compile(
            rb"^X-MS-Exchange-Transport-CrossTenantHeadersPromoted: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Transport-CrossTenantHeadersStamped: ", re.MULTILINE
        ),
        re.compile(
            rb"^X-MS-Exchange-Transport-CrossTenantHeadersStripped: ", re.MULTILINE
        ),
        re.compile(rb"^X-MS-Has-Attach: ", re.MULTILINE),
        re.compile(rb"^X-MS-Office365-Filtering-Correlation-Id-Prvs: ", re.MULTILINE),
        re.compile(rb"^X-MS-Office365-Filtering-Correlation-Id: ", re.MULTILINE),
        re.compile(rb"^X-MS-PublicTrafficType: ", re.MULTILINE),
        re.compile(rb"^X-MS-TNEF-Correlator: ", re.MULTILINE),
        re.compile(rb"^X-Microsoft-Antispam-Message-Info-Original: ", re.MULTILINE),
        re.compile(rb"^X-Microsoft-Antispam-Untrusted: ", re.MULTILINE),
        re.compile(rb"^X-OriginatorOrg: ", re.MULTILINE),
        re.compile(rb"^x-ms-exchange-atpsafelinks-stat: ", re.MULTILINE),
        re.compile(rb"^x-ms-exchange-calendar-series-instance-id: ", re.MULTILINE),
        re.compile(rb"^x-ms-exchange-messagesentrepresentingtype: ", re.MULTILINE),
        re.compile(rb"^x-ms-exchange-safelinks-url-keyver: ", re.MULTILINE),
        re.compile(rb"^x-ms-traffictypediagnostic: ", re.MULTILINE),
    ],
    "metadata/sysmon": [
        re.compile(rb"<Events>[^>]+"),
        re.compile(rb"<Event>[^>]+"),
        re.compile(rb"<\/Event>"),
        re.compile(rb"<\/Events>"),
    ],
    "code/xml": [
        # Check if it has an xml declaration header
        re.compile(rb"^\s*<\?xml[^>]+\?>", re.DOTALL | re.MULTILINE),
        # Check if it begins and ends with <tag ... and </tag ...> (for informal xml usages)
        re.compile(rb"^\s*<(?P<open>[\w:]+).+</(?P=open)>\s*$", re.DOTALL),
        # Check if a tag has an xmlns attribute
        re.compile(rb"<[^>]+xmlns[:=][^>]+>", re.MULTILINE),
    ],
    "code/ps1": [
        # Match one of the common Cmdlets (case-insensitive)
        re.compile(
            rb"(?i)(Get-ExecutionPolicy|Get-Service|Where-Object|ConvertTo-HTML|Select-Object|Get-Process|"
            rb"Clear-History|ForEach-Object|Clear-Content|Compare-Object|New-ItemProperty|New-Object|"
            rb"New-WebServiceProxy|Set-Alias|Wait-Job|Get-Counter|Test-Path|Get-WinEvent|Start-Sleep|"
            rb"Set-Location|Get-ChildItem|Rename-Item|Stop-Process|Add-Type|Out-String|Write-Error|"
            rb"Invoke-(Expression|WebRequest))"
        ),
        # Match one of the common Classes (case-insensitive)
        re.compile(
            rb"(?i)(-memberDefinition|-Name|-namespace|-passthru|-command|-TypeName|-join|-split)"
        ),
        # Match one of the common Methods (case-insensitive)
        re.compile(rb"(?i)(\.Get(String|Field|Type|Method)|FromBase64String)\("),
        # Commonly used .NET classed found in PowerShell
        re.compile(rb"(?i)(System\.Net\.WebClient)"),
        re.compile(rb"(?i)(Net\.ServicePointManager)"),
        re.compile(rb"(?i)(Net\.SecurityProtocolType)"),
        # String conversion libraries
        re.compile(rb"(?i)\[System\.Text\.Encoding\]::UTF8"),
        re.compile(rb"(?i)\[System\.Convert\]::ToInt32"),
        re.compile(rb"(?i)\[System.String]::Join\("),
        re.compile(rb"(?i)\[byte\[\]\][ \t]*\$\w+[ \t]*="),
        re.compile(rb"(?i)\[Microsoft\.VisualBasic\.(?:Interaction|CallType)\]"),
    ],
    "code/postscript": [
        re.compile(rb"%!PS"),
        re.compile(rb"def /\w+"),
    ],
    "code/batch": [
        re.compile(rb"(?i)(^|\n| |\t|@)(chcp|set /p)[ \t]+"),
        re.compile(
            rb"(?i)(^|\n| |\t|&)start[ \t]*/(min|b)[ \t]+.*([ \t]+(-win[ \t]+1[ \t]+)?-enc[ \t]+)?"
        ),
        re.compile(rb"(?i)(^|\n| |\t|&)start[ \t]*/wait[ \t]+.*?"),
        re.compile(rb'(?i)(^|\n|@)cd[ \t]+(/d )?["\']%~dp0["\']'),
        re.compile(rb"(?i)(^|\n)taskkill[ \t]+(/F|/im)"),
        re.compile(rb"(?i)(^|\n)reg[ \t]+delete[ \t]+"),
        re.compile(rb"(?i)(^|\n)%comspec%[ \t]+/c[ \t]+"),
        re.compile(rb"(?i)(^|\n)dir&echo[ \t]+"),
        re.compile(
            rb"(?i)(^|\n)net[ \t]+(share|stop|start|accounts|computer|config|continue|"
            rb"file|group|localgroup|pause|session|statistics|time|use|user|view)"
        ),
    ],
}
STRONG_SCORE = 15
MINIMUM_GUESS_SCORE = 20

WEAK_INDICATORS = {
    "code/javascript": [
        rb"var ",
        rb"String\.(fromCharCode|raw)\(",
        rb"Math\.(round|pow|sin|cos)\(",
        rb"(isNaN|isFinite|parseInt|parseFloat)\(",
        b"WSH",
        rb"(document|window)\[",
        rb"(?:[^\w]|^)this\.[\w]+",
    ],
    "code/jscript": [rb"new[ \t]+ActiveXObject\(", rb"Scripting\.Dictionary"],
    "code/pdfjs": [rb"xfa\.((resolve|create)Node|datasets|form)", rb"\.oneOfChild"],
    "code/vbs": [
        rb"(?i)(^|\n)*[ \t]{0,1000}((Dim|Sub|Loop|Attribute|Function|End[ \t]+Function)[ \t]+)|(End[ \t]+Sub)",
        rb"CreateObject",
        rb"WScript",
        rb"window_onload",
        rb".SpawnInstance_",
        rb".Security_",
        rb"WSH",
        rb"Set[ \t]+\w+[ \t]*=",
    ],
    "code/csharp": [rb"(^|\n)(protected[ \t]+)?[ \t]*override"],
    "code/sql": [rb"(^|\n)(create|drop|select|returns|declare)[ \t]+"],
    "code/php": [rb"\$this\->"],
    "code/c": [
        rb"(^|\n)(const[ \t]+char[ \t]+\w+;|extern[ \t]+|uint(8|16|32)_t[ \t]+)"
    ],
    "code/python": [b"try:", b"except:", b"else:"],
    "code/java": [rb"(^|\n)[ \t]*package[ \t]+[\w\.]+;"],
    "code/perl": [rb"(^|\n)[ \t]*package[ \t]+[\w\.]+;", b"@_"],
    "text/markdown": [rb"\[[\w]+\]:[ \t]*http:"],
    "code/ps1": [
        # Check for PowerShell Parameters ex.  -Online -FeatureName
        rb"\s-([A-Z][a-z0-9]+)+",
        # Check for cmdlet names ex. Disable-WindowsOptionalFeature
        rb"([A-Z][a-z0-9]+)+-([A-Z][a-z0-9]+)+",
        rb"::",
    ],
    "code/postscript": [
        rb"pop ",
        rb"\}for ",
        rb"dup ",
        rb"get ",
        rb"xor ",
        rb"copy ",
    ],
    "document/email": [rb"^Content-Type: "],
    "code/batch": [
        rb"(?i)(^|\n| |\t|@|&)(echo|netsh|sc|pkgmgr|netstat|rem|::|move)[ \t]+",
        rb"(^|\n)pause",
        rb"(^|\n)shutdown[ \t]*(/s)?",
        rb"Set[ \t]+\w+[ \t]*=",
    ],
}
WEAK_SCORE = 1

WEAK_INDICATORS = {k: re.compile(b"|".join(v)) for k, v in WEAK_INDICATORS.items()}

SHEBANG = re.compile(rb"^#![\w./]+/(?:env[ \t]*)?(\w+)[ \t]*\n")

EXECUTABLES = {
    "escript": "erlang",
    "nush": "nu",
    "macruby": "ruby",
    "jruby": "ruby",
    "rbx": "ruby",
}


def _confidence(score: Union[int, float]) -> str:
    conf = float(score) / float(STRONG_SCORE * 5)
    conf = min(1.0, conf) * 100
    return str(int(conf)) + r"%"


def _differentiate(lang: str, scores_map: Dict) -> str:
    if lang == "code/javascript":
        jscript_score = scores_map["code/jscript"]
        pdfjs_score = scores_map["code/pdfjs"]
        if pdfjs_score > 0 and pdfjs_score > jscript_score:
            return "code/pdfjs"
        elif jscript_score > 0:
            return "code/jscript"

    return lang


# Pass a filepath and this will return the guessed language in the AL tag format.
def guess_language(path: str, fallback="unknown") -> Tuple[str, Union[str, int]]:
    file_length = os.path.getsize(path)
    with open(path, "rb") as fh:
        if file_length > 131070:
            buf = fh.read(65535)
            fh.seek(file_length - 65535)
            buf += fh.read(65535)
        else:
            buf = fh.read()

    scores = defaultdict(int)
    shebang_lang = re.match(SHEBANG, buf)
    if shebang_lang:
        lang = shebang_lang.group(1)
        lang = "code/" + EXECUTABLES.get(safe_str(lang), safe_str(lang))
        scores[lang] = STRONG_SCORE * 3

    for lang, patterns in STRONG_INDICATORS.items():
        for pattern in patterns:
            for _ in re.findall(pattern, buf):
                scores[lang] += STRONG_SCORE

    for lang, pattern in WEAK_INDICATORS.items():
        for _ in re.findall(pattern, buf):
            scores[lang] += WEAK_SCORE

    for lang in list(scores.keys()):
        if scores[lang] < MINIMUM_GUESS_SCORE:
            scores.pop(lang)

    max_v = 0
    if len(scores) > 0:
        max_v = max(list(scores.values()))
    high_scores = [(k, v) for k, v in scores.items() if v == max_v]
    high_scores = [(_differentiate(k, scores), v) for k, v in high_scores]

    if len(high_scores) != 1:
        return fallback, 0
    else:
        confidences = [(k, _confidence(v)) for k, v in high_scores]
        return confidences[0]


constants = get_constants()
default_externals = {'mime': '', 'magic': '', 'type': ''}
rules_list = {"default": constants.YARA_RULE_PATH}
rules = yara.compile(filepaths=rules_list, externals=default_externals)


def guess_language_new(path: str, info: Dict, fallback="unknown") -> Tuple[str, Union[str, int]]:
    externals = {k: v for k, v in info.items() if k in default_externals}
    matches = rules.match(path, externals=externals, fast=True)
    if len(matches) > 1:
        print(matches)
    for match in matches:
        return match.meta['type']

    return fallback
