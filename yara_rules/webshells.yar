/*
  DeepSIFT — webshells.yar
  Web shell detection for PHP, ASP/ASPX, JSP.
  MITRE: T1505.003
*/

rule PHP_Webshell_Generic {
    meta:
        description = "Generic PHP web shell — eval-based execution"
        reference = "T1505.003"
    strings:
        $a1 = "eval(base64_decode" nocase
        $a2 = "eval(gzinflate" nocase
        $a3 = "eval(str_rot13" nocase
        $a4 = "eval(gzuncompress" nocase
        $a5 = "eval(rawurldecode" nocase
    condition:
        any of them
}

rule PHP_Webshell_Exec {
    meta:
        description = "PHP web shell — system/exec command execution"
        reference = "T1505.003"
    strings:
        $a1 = "system($_GET" nocase
        $a2 = "system($_POST" nocase
        $a3 = "system($_REQUEST" nocase
        $a4 = "passthru($_GET" nocase
        $a5 = "passthru($_POST" nocase
        $a6 = "shell_exec($_GET" nocase
        $a7 = "shell_exec($_POST" nocase
        $a8 = "exec($_GET" nocase
        $a9 = "exec($_POST" nocase
        $a10 = "assert($_POST" nocase
    condition:
        any of them
}

rule PHP_Webshell_China_Chopper {
    meta:
        description = "China Chopper-style one-liner web shell"
        reference = "T1505.003"
    strings:
        $a1 = "<?php @eval($_POST[" nocase
        $a2 = "<?php @assert($_POST[" nocase
        $a3 = "@preg_replace" nocase
        $a4 = "e}($_POST[" nocase
    condition:
        any of them
}

rule ASPX_Webshell_Generic {
    meta:
        description = "Generic ASP/ASPX web shell"
        reference = "T1505.003"
    strings:
        $a1 = "<%@ Page Language=\"Jscript\"" nocase
        $a2 = "eval(Request.Item[" nocase
        $a3 = "Response.Write(eval(" nocase
        $a4 = "System.Diagnostics.Process.Start" nocase
        $a5 = "Shell.Application" nocase
    condition:
        any of them
}

rule JSP_Webshell_Generic {
    meta:
        description = "Generic JSP web shell"
        reference = "T1505.003"
    strings:
        $a = "Runtime.getRuntime().exec(" nocase
        $b = "ProcessBuilder" nocase
        $c = "request.getParameter(" nocase
        $d = "getOutputStream()" nocase
    condition:
        ($a or $b) and ($c or $d)
}
