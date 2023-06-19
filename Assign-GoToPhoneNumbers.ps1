<#
This script assigns GoTo phone numbers in bulk by importing the info from a CSV.
#>

# functions
function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:warningColor = "Yellow"
    $script:failColor = "Red"
}

function Show-Introduction
{
    Write-Host "This script assigns GoTo phone numbers in bulk by importing the info from a CSV." -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function Prompt-YesOrNo($question, [switch]$includeYesToAll, [switch]$includeNoToAll)
{
    $prompt = ("$question`n" + 
        "[Y] Yes  [N] No")
    
    if ($includeYesToAll -and $includeNoToAll)
    {
        $prompt += "  [A] Yes to All  [L] No to All"

        $response = ReadValidate-Host -Prompt $prompt -Regex '^\s*[ynal]\s*$' -Warning "Please enter y, n, a, or l."
    }
    elseif ($includeYesToAll)
    {
        $prompt += "  [A] Yes to All"

        $response = ReadValidate-Host -Prompt $prompt -Regex '^\s*[yna]\s*$' -Warning "Please enter y, n, or a."
    }
    elseif ($includeNoToAll)
    {
        $prompt += "  [L] No to All"

        $response = ReadValidate-Host -Prompt $prompt -Regex '^\s*[ynl]\s*$' -Warning "Please enter y, n, or l."        
    }
    else
    {
        $response = ReadValidate-Host -Prompt $prompt -Regex '^\s*[yn]\s*$' -Warning "Please enter y or n." 
    }

    return $response.Trim().ToUpper()
}

function Show-HelpMessage
{
    Write-Host ("To obtain an access token, follow the steps in the getting started and authentication guides: `n" +
        "https://developer.goto.com/guides/Get%20Started/00_Ref-Get-Started/ `n`n" +

        "This can be done from a Postman request: `n" +
        "1. Go to the `"Authorization`" tab and select `"OAuth 2.0`". `n" +
        "2. Check the box that says `"Authorize using browser`" and use the `"Callback URL`" as the `"Redirect URL`" in your GoTo OAuth client configuration. `n" +
        "3. Fill out the section under `"Configure New Token`" and click `"Get New Access Token`". `n") -ForegroundColor $infoColor
}

function ReadValidate-Host($prompt, $regex, $warning)
{
    Write-Host $prompt

    do
    {
        $response = Read-Host

        if ($response -inotmatch $regex)
        {
            Write-Warning $warning
        }
    }
    while ($response -inotmatch $regex)

    return $response
}

function Prompt-AuthToken
{
    do
    {
        $token = Read-Host "Please enter your API authorization token"
        $valid = Validate-AuthToken $token
    }
    while (-not($valid))
    
    return $token
}

function Validate-AuthToken($authToken)
{
    $url = "https://api.getgo.com/admin/rest/v1/me"

    $headers = @{
        Authorization = "Bearer $authToken"
        Accept        = "application/json"
    }

    try
    {
        Invoke-WebRequest -Method "Get" -Uri $url -Headers $headers -ErrorVariable responseError | Out-Null
        Write-Host "Your GoTo profile was found." -ForegroundColor $successColor
        $valid = $true
    }
    catch
    {
        Write-Warning "There was an error getting your profile."
        Write-Host "    $($responseError[0].Message)" -ForegroundColor $warningColor

        $responseCode = [int]$_.Exception.Response.StatusCode
        if (($responseCode -eq 403) -or ($responseCode -eq 401))
        {
            Write-Warning "Auth token invalid."
        }
        $valid = $false
    }
    
    return $valid
}

function Get-AccountKey($authToken)
{
    $url = "https://api.getgo.com/admin/rest/v1/me"

    $headers = @{
        Authorization = "Bearer $authToken"
        Accept        = "application/json"
    }

    try
    {
        $response = Invoke-RestMethod -Method "Get" -Uri $url -Headers $headers -ErrorVariable responseError
    }
    catch
    {
        Write-Host "There was an error getting your account info." $failColor
        Write-Host "    $($responseError[0].Message)" -ForegroundColor $failColor
        exit
    }

    return $response.accountKey
}

function Get-ExpectedHeaders
{
    return @("Phone Number", "Email", "SMS Users")
}

function Prompt-Csv($expectedHeaders)
{
    Show-CsvRequirements
    
    do
    {
        $path = Read-Host "Enter path to CSV"
        $path = $path.Trim('"')
        $extension = [IO.Path]::GetExtension($path)

        if ($extension -ne '.csv')
        {
            Write-Warning "File type is $extension. Please enter a CSV."
            $keepGoing = $true
            continue
        }

        try
        {
            $records = Import-CSV -Path $path -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Warning "CSV not found."
            $keepGoing = $true
            continue
        }

        if ($records.Count -eq 0)
        {
            Write-Warning "CSV is empty."
            $keepGoing = $true
            continue
        }

        $hasExpectedHeaders = Validate-CsvHeaders -ImportedCsv $records -ExpectedHeaders $expectedHeaders
        if (-not($hasExpectedHeaders))
        {
            $keepGoing = $true
            continue
        }
        
        $keepGoing = $false
    }
    while ($keepGoing)

    Write-Host "CSV was found and validated." -ForegroundColor $successColor

    return $records
}

function Show-CsvRequirements
{
    Write-Host ("Please fill out a CSV with the following headers: `n" +
                "    Phone Number `n" +
                "        (Phone Number to assign.) `n" +
                "    Email `n" +
                "        (Email of user to assign.) `n" +
                "    SMS Users `n" +
                "        (List of emails of users to grant SMS permissions, comma separated.) `n") -ForegroundColor $infoColor

}

function Validate-CsvHeaders($importedCsv, $expectedHeaders)
{
    $hasExpectedHeaders = $true

    if ($null -eq $expectedHeaders)
    {
        return $true
    }

    foreach ($header in $expectedHeaders)
    {
        # check if first record has a property named $header
        if ($importedCsv[0].psobject.properties.match($header).Count -eq 0)
        {
            Write-Warning "CSV is missing a header called $header."
            $hasExpectedHeaders = $false
        }
    }
    
    if (-not($hasExpectedHeaders))
    {
        Write-Host "Please add the missing headers and try again." -ForegroundColor $warningColor
    }

    return $hasExpectedHeaders
}

function Add-UserInfo($authToken, $accountKey, $importedCsv)
{
    # This function will modify the importedCsv, as the object is passed by reference.

    for ($i = 0; $i -lt $importedCsv.Count; $i++)
    {
        $userInfo = Get-GoToUser -AuthToken $authToken -AccountKey $accountKey -Email $importedCsv[$i].Email
        if ($userInfo)
        {
            Add-Member -InputObject $importedCsv[$i] -NotePropertyName "UserInfo" -NotePropertyValue $userInfo
        }
        else
        {
            $importedCsv[$i] = $null

            if (-not($noToAll))
            {
                $shouldExit = Prompt-YesOrNo -Question "Would you like to exit the script and make corrections?" -IncludeNoToAll
                if ($shouldExit -eq "L") { $noToAll = $true }
                if ($shouldExit -eq "Y") { exit }
            } 
        }
    }
}

function Get-GoToUser($authtToken, $accountKey, $email)
{
    # In URL encoding, %20 = space and %22 = quotation mark.
    $url = "https://api.getgo.com/admin/rest/v1/accounts/$accountKey/users?filter=email eq `"$email`""
    $url = [System.Uri]::EscapeUriString($url) # url encodes the string

    $headers = @{
        Authorization = "Bearer $authToken"
        Accept        = "application/json"
    }

    try
    {
        $response = Invoke-RestMethod -Method "Get" -Uri $url -Headers $headers -ErrorVariable "responseError"
        if ($response.total -eq 0)
        {
            Write-Warning "User was not found: $email"
            $response = $null
        }
    }
    catch
    {
        Write-Host "There was an error getting user: $email" -ForegroundColor $warningColor
        Write-Host $responseError[0].Message -ForegroundColor $warningColor
        $response = $null        
    }

    return $response
}

function Format-PhoneNumbers($importedCsv)
{
    # This function will modify the importedCsv, as the object is passed by reference.

    $phoneNumberRegex = '^\s*(?:\+?(\d{1,3}))?([-. (]*(\d{3})[-. )]*)?((\d{3})[-. ]*(\d{2,4})(?:[-.x ]*(\d+))?)\s*$'

    $amountBlankNumbers = 0
    foreach ($record in $importedCsv)
    {
        if ($null -eq $record) { continue }
        
        if ([String]::IsNullOrEmpty($record."Phone Number"))
        {
            $amountBlankNumbers++
            continue
        }
        
        if ($record."Phone Number" -notmatch $phoneNumberRegex)
        {
            Write-Warning "$($record."Phone Number") is not a valid number."
        }

        $record."Phone Number" = $record."Phone Number".Replace("-", "").Replace("(", "").Replace(")", "").Replace(".", "").Replace("+", "").Replace(" ", "")
        $record."Phone Number" = "+$($record."Phone Number")"
    }
    Write-Warning "There are $amountBlankNumbers empty phone numbers in the CSV."
}

function Get-AllPhoneNumbers($authToken, $accountKey)
{
    $url = "https://api.goto.com/voice-admin/v1/phone-numbers"

    $headers = @{
        Authorization = "Bearer $authToken"
        Accept        = "application/json"
    }

    $queryParams = @{
        accountKey = $accountKey
        pageSize   = 100
    }

    $responses = New-Object -TypeName System.Collections.Generic.List[PSObject]
    do
    {
        $response = SafelyInvoke-RestMethod -Method "Get" -Uri $url -Headers $headers -Body $queryParams        
        $responses.Add($response)

        if ($response.nextPageMarker)
        {
            $queryParams["pageMarker"] = $response.nextPageMarker
        }
    }
    while ($response.nextPageMarker)
    
    return $responses
}

function SafelyInvoke-RestMethod($method, $uri, $headers, $body)
{
    try
    {
        $response = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        Write-Host $responseError[0].Message -ForegroundColor $failColor
        exit
    }

    return $response
}

function New-PhoneNumberLookupTable($apiResponses)
{
    $lookupTable = @{}

    foreach ($response in $apiResponses)
    {
        foreach ($phoneNumber in $response.items)
        {
            $lookupTable.Add($phoneNumber.number, $phoneNumber.id)
        }
    }

    return $lookupTable
}

function Get-AllExtensions($authToken, $accountKey)
{
    $url = "https://api.goto.com/voice-admin/v1/extensions"

    $headers = @{
        Authorization = "Bearer $authToken"
        Accept = "application/json"
    }

    $queryParams = @{
        accountKey = $accountKey
        pageSize = 100
    }

    $responses = New-Object -TypeName System.Collections.Generic.List[PSObject]
    do
    {
        $response = SafelyInvoke-RestMethod -Method "Get" -Uri $url -Headers $headers -Body $queryParams
        $responses.Add($response)

        if ($response.nextPageMarker)
        {
            $queryParams["pageMarker"] = $response.nextPageMarker
        }
    }
    while ($response.nextPageMarker)

    return $responses
}

function New-ExtensionLookupTable($apiResponses)
{
    $lookupTable = @{}

    foreach ($response in $apiResponses)
    {
        foreach ($extension in $response.items)
        {
            if ($null -eq $extension.number) { continue }

            $lookupTable.Add($extension.number, $extension.id)
        }
    }

    return $lookupTable
}

function Assign-PhoneNumbers($authToken, $accountKey, $importedCsv, $phoneNumberLookupTable, $extensionLookupTable)
{
    $recordsProcessed = 0
    $amountRouted = 0
    $amountSmsGranted = 0
    foreach ($record in $importedCsv)
    {
        Write-Progress -Activity "Assigning phone numbers..." -Status "$recordsProcessed records processed"
        $recordsProcessed++

        if ($null -eq $record) { continue }
        if ($null -eq $record."Phone Number") { continue }

        if ($record.Email)
        {
            $phoneNumberId = $phoneNumberLookupTable[$record."Phone Number"]
            $extId = $extensionLookupTable[$record.UserInfo.results[0].settings.JIVE.primaryExtensionNumber]

            $successful = Route-PhoneNumber $authToken $record."Phone Number" $phoneNumberId $extId $record.Email
            if ($successful) { $amountRouted++ }
        }

        if ($record."SMS Users")
        {
            $smsUsers = Parse-StringWithDelimiter -String $record."SMS Users" -Delimiter ","
            $amountGranted = Grant-SMSPermissions $authToken $accountKey $record."Phone Number" $phoneNumberId $smsUsers       
            if ($amountGranted -gt 0) { $amountSmsGranted++ } 
        }
    }
    Write-Progress -Activity "Assigning phone numbers..." -Status "$recordsProcessed records processed"

    Write-Host "Finished assigning phone numbers." -ForegroundColor $successColor
    Write-Host "$amountRouted numbers were routed to an extension." -ForegroundColor $successColor
    Write-Host "$amountSmsGranted numbers had SMS permissions granted." -ForegroundColor $successColor
}

function Route-PhoneNumber($authToken, $phoneNumber, $phoneNumberId, $extensionId, $email)
{
    $url = "https://api.goto.com/voice-admin/v1/phone-numbers/$phoneNumberId"

    $headers = @{
        Authorization = "Bearer $authToken"
        "Content-Type" = "application/json"
        Accept = "application/json"
    }

    $body = @{
        name = ConvertTo-Name $email
        routeTo = @{
            id = $extensionId
            type = "EXTENSION"
        }
    } | ConvertTo-Json
    
    try
    {
        Invoke-RestMethod -Method "Patch" -Uri $url -Headers $headers -Body $body -ErrorVariable "responseError" | Out-Null
        $successful = $true
    }
    catch
    {
        Write-Host $responseError[0].Message -ForegroundColor $warningColor
        Write-Warning "Error occurred routing phone number: $phoneNumber"
        $successful = $false
    }

    return $successful
}

function ConvertTo-Name($email)
{
    # Function expects email in format of word1.word2@domain.com where word1 is first name and word2 is last name.    
    $emailRegex = '^\s*[\w\.-]+\.[\w\.-]+@[\w\.-]+\.\w{2,4}\s*$'

    if ($email -inotmatch $emailRegex)
    {
        Write-Warning ("Email is invalid: $email `n" +
                      "Expected format is firstname.lastname@domain.com `n")
        return $null        
    }

    $namePart = $email.Split('@')[0]
    $fullName = $namePart.Replace('.', " ")
    $fullNameCapitalized = $fullName.Split(" ") | Foreach-Object { $_.SubString(0, 1).ToUpper() + $_.SubString(1).ToLower() }

    return $fullNameCapitalized -Join " "
}

function Parse-StringWithDelimiter($string, $delimiter)
{
    return ($string.Split("$delimiter")).Trim()
}

function Grant-SMSPermissions($authToken, $accountKey, $phoneNumber, $phoneNumberId, $smsUsers)
{
    $url = "https://api.goto.com/voice-admin/v1/phone-numbers/$phoneNumberId/permissions"

    $headers = @{
        Authorization = "Bearer $authToken"
        "Content-Type" = "application/json"
        Accept = "application/json"
    }
    
    $amountGranted = 0
    foreach ($email in $smsUsers)
    {
        $goToUser = Get-GoToUser -AuthToken $authToken -AccountKey $accountKey -Email $email
        if ($null -eq $goToUser) { continue }

        $userKey = $goToUser.results[0].key

        $body = @{
            userKey = $userKey
            permissions = @("TEXTING")
        } | ConvertTo-Json

        try
        {
            Invoke-RestMethod -Method "Post" -Uri $url -Headers $headers -Body $body -ErrorVariable "responseError" | Out-Null
            $amountGranted++
        }
        catch
        {
            Write-Warning ("There was an error granting SMS permissions. `n" +
                            "    Phone Number $phoneNumber `n" +
                            "    User: $email")            
            Write-Host $responseError[0].Message -ForegroundColor $warningColor
        }
    }

    return $amountGranted
}

# main
Initialize-ColorScheme
Show-Introduction
$needHelp = Prompt-YesOrNo "Need help obtaining an access token for the GoTo API?"
if ($needHelp -eq "Y") { Show-HelpMessage }
$authToken = Prompt-AuthToken
$accountKey = Get-AccountKey $authToken
$expectedHeaders = Get-ExpectedHeaders
$importedCsv = Prompt-Csv $expectedHeaders

Write-Host "Parsing Csv..." -ForegroundColor $infoColor
Add-UserInfo -AuthToken $authToken -AccountKey $accountKey -ImportedCsv $importedCsv # Adds user info to the importedCsv.
Format-PhoneNumbers $importedCsv # Formats the phone numbers in the importedCsv.

Write-Host "Gathering info from your GoTo account..." -ForegroundColor $infoColor
$phoneNumbers = Get-AllPhoneNumbers $authToken $accountKey
$phoneNumberLookupTable = New-PhoneNumberLookupTable $phoneNumbers
$extensions = Get-AllExtensions $authToken $accountKey
$extensionLookupTable = New-ExtensionLookupTable $extensions

Assign-PhoneNumbers $authToken $accountKey $importedCsv $phoneNumberLookupTable $extensionLookupTable

Read-Host "Press Enter to exit"