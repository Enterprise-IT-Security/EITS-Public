<# --- USER ENTRY REQUIRED HERE - SET TO YOUR VALUES --- #>
$CISACSV = Import-Csv -Path "C:\temp\20211105_cisa.csv" ## Download from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
$ExportCSVPath = ("C:\temp\" + (Get-Date -Format 'yyyyMMdd') + "_summary_csvoutput.csv")
$VulnDetailExportPath = ("C:\temp\" + (Get-Date -Format 'yyyyMMdd') + "_vulndetail_csvoutput.csv")
$NessusURI = "https://yoursecuritycenterlink/rest"
$APIKey01 = "" ## Nessus Access Key
$APIKey02 = "" ## Nessus Secret Key
<# /// USER ENTRY REQUIRED HERE - SET TO YOUR VALUES \\\ #>

<# --- DO NOT MODIFY --- #>
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } ## Required to connect to Nessus API
catch { $Error | fl -Force; BREAK } ## Stop execution if setting TLS fails

$Counter = 0
$TimeSwitch = 0
$Start = Get-Date
$Entries = @()
$CSVRefresh = 0

$Headers = @{ 'x-apikey' = "accesskey=$APIKey01;secretkey=$APIKey02" }
<# /// DO NOT MODIFY \\\ #>

foreach ($a in $CISACSV)
{
    $TimeSwitch ++
    $Counter ++
    $PluginCounter = 0

    Switch ($TimeSwitch)
    {
        {$_ -ge 1 -and $_ -lt 3}
        {
            if (!$SecondsRemaining) { Write-Progress -Activity ("Processing $Counter of " + $CISACSV.Count.ToString()) -PercentComplete ([Int](($Counter / ($CISACSV.Count)) * 100)) }
            else { Write-Progress -Activity 'CISA CVE Processing' -Status ("Processing $Counter of " + $CISACSV.Count.ToString()) -PercentComplete ([Int](($Counter / ($CISACSV.Count)) * 100)) -SecondsRemaining $SecondsRemaining }
        }

        3
        {
            $TimeSwitch = 0 ## Reset the counter for the switch statement
            $SecondsRemaining = ((((Get-Date) - $Start).TotalSeconds / $Counter)) * (($CISACSV.Count) - $Counter)
            Write-Progress -Activity 'CISA CVE Processing' -Status ("Processing $Counter of " + $CISACSV.Count.ToString()) -PercentComplete ([Int](($Counter / ($CISACSV.Count)) * 100)) -SecondsRemaining $SecondsRemaining

        }
    }

    $CVERecord = $a.CVE.Replace('?','') ## For some reason the CSV import has an appended ? at the end of each entry... get rid of it...

    $NessusResult = Invoke-RestMethod -Method Get -Uri ($NessusURI + '/plugin?filterField=xrefs:CVE&endOffset=500&op=like&value=' + $CVERecord) -Headers $Headers
    
    if ($NessusResult.response.Count -gt 0)
    {
        foreach ($b in $NessusResult.response)
        {
            $PluginCounter ++
            ## Build the data sheet ##
            $Entry = New-Object psobject
            $Entry | Add-Member -MemberType NoteProperty -Name 'CVE' -Value $CVERecord
            $Entry | Add-Member -MemberType NoteProperty -Name 'NessusPluginId' -Value $b.id
            $Entry | Add-Member -MemberType NoteProperty -Name 'NessusPluginName' -Value $b.name
            
            $PluginDetails = (Invoke-RestMethod -Method Get -Uri ($NessusURI + '/plugin/' + $b.id + '?fields=exploitEase,exploitAvailable,exploitFrameworks,cvssV3BaseScore,cvssV3TemporalScore,pluginPubDate,patchPubDate,vulnPubDate') -Headers $Headers).response
            
            $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitAvailable' -Value $PluginDetails.exploitAvailable
            $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitEase' -Value $PluginDetails.exploitEase
            $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitFrameworks' -Value $PluginDetails.exploitFrameworks
            $Entry | Add-Member -MemberType NoteProperty -Name 'cvssV3BaseScore' -Value $PluginDetails.cvssV3BaseScore
            $Entry | Add-Member -MemberType NoteProperty -Name 'cvssV3TemporalScore' -Value $PluginDetails.cvssV3TemporalScore
            $Entry | Add-Member -MemberType NoteProperty -Name 'pluginPubDate' -Value ((Get-Date 1970-01-01T00:00:00).AddSeconds($PluginDetails.pluginPubDate))
            $Entry | Add-Member -MemberType NoteProperty -Name 'patchPubDate' -Value ((Get-Date 1970-01-01T00:00:00).AddSeconds($PluginDetails.patchPubDate))
            $Entry | Add-Member -MemberType NoteProperty -Name 'vulnPubDate' -Value ((Get-Date 1970-01-01T00:00:00).AddSeconds($PluginDetails.vulnPubDate))

            $Body = ('{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"cumulative","startOffset":0,"endOffset":1,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":true,"value":"' + $b.id + '"}],"vulnTool":"vulndetails"},"sourceType":"cumulative","columns":[],"type":"vuln"}')
            $VulnCheck = Invoke-RestMethod -Method Post -Uri ($NessusURI + '/analysis') -Headers $Headers -Body $Body

            if (($VulnCheck.response.totalRecords -gt 0))
            {
                Write-Host $VulnCheck.response.totalRecords vulnerabilities found for $CVERecord
                if ($CSVRefresh -eq 0)
                {
                    $CSVRefresh = 1 ## Delete the existing CSV for multiple runs in a single day

                    if (Test-Path -Path $VulnDetailExportPath) { Remove-Item -Path $VulnDetailExportPath -Force }
                }

                ## Set the results to gather all vulnerable details (set endoffset)
                $Body = ('{"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"cumulative","startOffset":0,"endOffset":' + ($VulnCheck.response.totalRecords) + ',"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":true,"value":"' + $b.id + '"}],"vulnTool":"vulndetails"},"sourceType":"cumulative","columns":[],"type":"vuln"}')
                $VulnCheck = Invoke-RestMethod -Method Post -Uri ($NessusURI + '/analysis') -Headers $Headers -Body $Body

                ($VulnCheck.response.results) | Export-Csv -Path $VulnDetailExportPath -NoTypeInformation -Append
            }

            $Entry | Add-Member -MemberType NoteProperty -Name 'DetectionCount' -Value ($VulnCheck.response.totalRecords)

            $Entries += $Entry
        }

        Write-Host $PluginCounter plugins found for $CVERecord $a.'Vulnerability Name'
    }
    else
    {
        $Entry = New-Object psobject
        $Entry | Add-Member -MemberType NoteProperty -Name 'CVE' -Value $CVERecord
        $Entry | Add-Member -MemberType NoteProperty -Name 'NessusPluginId' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'NessusPluginName' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitAvailable' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitEase' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'ExploitFrameworks' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'cvssV3BaseScore' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'cvssV3TemporalScore' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'pluginPubDate' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'patchPubDate' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'vulnPubDate' -Value 'No Plugin Found'
        $Entry | Add-Member -MemberType NoteProperty -Name 'DetectionCount' -Value 'No Plugin Found'

        $Entries += $Entry
    }

    if ($Counter -eq $CISACSV.Count) { Write-Progress -Activity 'CISA CVE Processing' -Status ("Processing $Counter of " + $CISACSV.Count.ToString()) -PercentComplete ([Int](($Counter / ($CISACSV.Count)) * 100)) -SecondsRemaining 0 -Completed }
}

$Entries | Export-Csv -Path $ExportCSVPath -NoTypeInformation
