# Judges the Authenticode signature of release files.
#
# `signtool verify /pa /v` (run by the workflow step before this script) says
# whether the signature chains to a trusted root. This script adds what
# signtool does not decide for us:
#   - the status is exactly `Valid` (an unsigned file reports `NotSigned`),
#   - the signer is the identity we expect (-ExpectedSubject, the repository
#     variable WINDOWS_SIGN_EXPECTED_SUBJECT), and
#   - the signature carries an RFC 3161 timestamp, which is what keeps it
#     valid after the certificate expires.
#
# -ExpectedSubject matches the signer certificate's full subject
# (`CN=..., O=..., C=...`) or its simple name (the CN), case-insensitively.
# An empty value is an error, never a pass: the verification step must not
# turn into a no-op because a variable was not set.
#
# Usage:
#   verify-signature.ps1 -Path <file>[,<file>...] -ExpectedSubject <subject>
# Exit status 0 when every file passes, 1 otherwise.

param(
    [string[]]$Path,
    [string]$ExpectedSubject
)

# Returns the reasons a signature is not acceptable; empty means acceptable.
function Get-QshSignatureProblems {
    param(
        [string]$Status,
        [string]$Subject,
        [string]$SimpleName,
        [bool]$HasTimestamp,
        [string]$ExpectedSubject
    )
    $problems = @()
    if ($Status -cne 'Valid') {
        $problems += "status is $Status, expected Valid"
    }
    $subjectOk = ($Subject -and $Subject -ieq $ExpectedSubject) -or ($SimpleName -and $SimpleName -ieq $ExpectedSubject)
    if (-not $subjectOk) {
        $problems += "signer is '$Subject', expected '$ExpectedSubject'"
    }
    if (-not $HasTimestamp) {
        $problems += 'no RFC 3161 timestamp countersignature'
    }
    return $problems
}

function Test-QshFileSignature {
    param([string[]]$Path, [string]$ExpectedSubject)

    if ([string]::IsNullOrWhiteSpace($ExpectedSubject)) {
        throw 'the expected signer subject is empty (repository variable WINDOWS_SIGN_EXPECTED_SUBJECT); refusing to verify against nothing'
    }
    if (-not $Path -or $Path.Count -eq 0) {
        throw '-Path names no file to verify'
    }

    $failed = 0
    foreach ($file in $Path) {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $cert = $sig.SignerCertificate
        $subject = ''
        $simple = ''
        if ($null -ne $cert) {
            $subject = [string]$cert.Subject
            $simple = [string]$cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        $problems = @(Get-QshSignatureProblems `
            -Status ([string]$sig.Status) `
            -Subject $subject `
            -SimpleName $simple `
            -HasTimestamp ($null -ne $sig.TimeStamperCertificate) `
            -ExpectedSubject $ExpectedSubject)
        if ($problems.Count -eq 0) {
            Write-Host "OK   ${file}: Valid, signer '$subject', timestamped"
        } else {
            $failed++
            Write-Host "FAIL ${file}: $($problems -join '; ')"
            Write-Host "::error title=Signature check::${file}: $($problems -join '; ')"
        }
    }
    return $failed
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    $failed = Test-QshFileSignature -Path $Path -ExpectedSubject $ExpectedSubject
    if ($failed -gt 0) { exit 1 }
}
