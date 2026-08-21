$Operations = @(
  "CaseAdded", "CaseUpdated", "CaseMembersUpdated",
  "PurviewSearchUpdated", "PurviewSearchViewed",
  "PurviewSearchStatisticsJobSubmitted",
  "PurviewSearchAddToReviewSetJobSubmitted",
  "PurviewSearchExportJobSubmitted", "ReviewSetExportJobSubmitted"
)
$UtcStyles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
$StartUtc = [DateTimeOffset]::Parse(
  "<START_RFC3339_UTC>", [Globalization.CultureInfo]::InvariantCulture, $UtcStyles
).UtcDateTime
$EndUtc = [DateTimeOffset]::Parse(
  "<END_RFC3339_UTC>", [Globalization.CultureInfo]::InvariantCulture, $UtcStyles
).UtcDateTime
$SessionId = [guid]::NewGuid().ToString()
$Records = [System.Collections.Generic.List[object]]::new()
$ExpectedCount = $null
$CompleteByIndex = $false

do {
  $Page = @(Search-UnifiedAuditLog `
    -StartDate $StartUtc `
    -EndDate $EndUtc `
    -Operations $Operations `
    -UserIds "<ACTOR_UPN>" `
    -SessionId $SessionId `
    -SessionCommand ReturnLargeSet `
    -ResultSize 5000)

  if ($Page.Count -eq 0) { break }
  foreach ($Record in $Page) { [void]$Records.Add($Record) }

  if ($null -eq $ExpectedCount) {
    $ExpectedCount = [int64]$Page[0].ResultCount
  }
  $CompleteByIndex = ([int64]$Page[-1].ResultIndex -ge $ExpectedCount)
}
while (-not $CompleteByIndex -and $Records.Count -lt 50000)

if (($Records.Count -ge 50000) -or
    ($null -ne $ExpectedCount -and $Records.Count -lt $ExpectedCount)) {
  throw "Incomplete audit retrieval: split the UTC interval and rerun each slice."
}

$Records
