<#
- Problem statement
- Use cases and features
- Minimum viable product
- Inputs
- Outputs
- Program flow
- Functions
- Classes and namespaces
- Input validation
    - Auth token valid but lacks permissions
    - Phone number left blank
    - Phone number invalid format
    - Phone number not found
    - Email left blank (should still be able to grant SMS users)
    - Email invalid format
    - Email not found
    - SMS users left blank
    - SMS users invalid format
    - SMS user not found
- Output validation
- To Do
    - Prompt for authToken as secure string
- Done but not tested
- Done and tested 
#>

BeforeAll {
    # Optional
    # BeforeAll runs once at the beginning of the file.

    function Get-Functions($filePath)
    {
        $script = Get-Command $filePath
        return $script.ScriptBlock.AST.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
    }

    $path = "..\Assign-GoToPhoneNumbers.ps1"
    Get-Functions $path | Invoke-Expression

    Initialize-ColorScheme    
    $validToken = Get-Content "..\Private\authToken.txt"
    $validAccountKey = Get-AccountKey $validToken
    $validCsv = Import-Csv "..\Private\ValidData.csv"
    $validEmail = Get-Content "..\Private\validEmail.txt"
    $validExtensionId = Get-Content "..\Private\validExtensionId.txt"


    $invalidHeaders = Import-Csv "..\Private\InvalidHeaders.csv"
    $invalidUsers = Import-Csv "..\Private\InvalidUsers.csv"
    
    mock SafelyInvoke-RestMethod {
        param($method, $uri, $headers, $body)
        
        try
        {
            $response = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
        }
        catch
        {
            Write-Host $responseError[0].Message -ForegroundColor $failColor
            Write-Host "Script would normally exit here" -ForegroundColor $failColor
            return $null
        }

        return $response
    }
}

Describe "Function-Name" {
    BeforeEach {
        # Optional
        # Runs once before each test (It block) within the current Describe or Context block.
    }

    Context "When passing a something" {
        It "Should do/return something" {
            # Pipe values you want to test to Should
            # i.e: $result | Should -Contain $expected
            # More assertion examples: https://pester.dev/docs/assertions/
            # -Be, -Contain (value present in collection), -Not -Be, -BeExactly (tests for object equality), -BeGreaterThan, -BeGreaterOrEqual
            # -BeLessThan, -BeLessOrEqual, -BeIn (value is present in array/collection), -BeLike (wildcard pattern), -BeNullOrEmpty, -BeOfType
            # -HaveCount, -Match (regex comparison)
            # Mock behavior of existing function with an alternate implementation. Mock FunctionToMock { # alternate implementaton } 
            # Skipping: You can skip describe or context block with -skip operator. i.e. Describe "Some-Function" -Skip {
        }
    }

    AfterEach {
        # Optional
        # Runs once after each test (It block) within the current Describe or Context block.
    }
}

Describe "Validate-AuthToken" {
    Context "When passed valid token" {
        It "Should return true" {
            Validate-AuthToken $validToken | Should -Be $true
        }
    }
    Context "When passed invalid token" {
        It "Should return false" {
            Validate-AuthToken "Invalid Token" | Should -Be $false
        }
    }
}

Describe "Get-AccountKey" {
    Context "When passed valid token" {
        It "Should not return null" {
            $key = Get-AccountKey $validToken

            Write-Host "accountKey is $key"

            $key  | Should -Not -BeNullOrEmpty
        }
    }
    Context "When passed invalid token" {
        It "Shoudld return null" {
            Get-AccountKey "Invalid Token" | Should -Be $null
        }
    }
    Context "When passed invalid token with exitOnFailure" -Skip {
        It "Should exit the program" {
            Get-AccountKey "Invalid Token" -ExitOnFailure
        }
    }
}

Describe "Validate Headers" {
    BeforeEach{
        $expectedHeaders = Get-ExpectedHeaders
    }

    Context "When passed csv with invalid headers" {
        It "Should return false" {            
            Validate-CsvHeaders $invalidHeaders $expectedHeaders | Should -Be $false
        }
    }
    Context "When passed valid csv" {
        It "Should return true" {
            Validate-CsvHeaders $validCsv $expectedHeaders | Should -Be $true
        }
    }
}

Describe "Add-UserInfo" {
    Context "When passed valid data" {
        It "Should add a property to the records called UserInfo" {
            $validCsvCopy = $validCsv.Clone()
            Add-UserInfo -ImportedCsv $validCsvCopy -AuthToken $validToken -AccountKey $validAccountKey

            foreach ($record in $validCsvCopy)
            {
                $hasProperty = $record.PSObject.Properties.Name -Contains "UserInfo"
                $hasProperty | Should -Be $true
            }
        }
    }
    Context "When passed all invalid users" {
        It "All records should remain without a UserInfo property" {
            $invalidUsersCopy = $invalidUsers.Clone()
            Add-UserInfo -ImportedCsv $invalidUsersCopy -AuthToken $validToken -AccountKey $validAccountKey

            foreach ($record in $invalidUsersCopy)
            {
                $containsUserInfoProp = $record.PSObject.Properties.Name -Contains "UserInfo"
                $containsUserInfoProp | Should -Be $false
            }
        }        
    }
}

Describe "TryGet-GoTouser" {
    Context "When passed valid email and valid authToken" {
        It "Should not return null" {
            TryGet-GoToUser -AuthToken $validToken -AccountKey $validAccountKey -Email $validEmail | Should -Not -BeNullOrEmpty
        }
    }
    Context "When passed invalid authToken" {
        It "Should return null" {
            TryGet-GoToUser -Email $validEmail -AuthToken "Invalid token" -AccountKey $validAccountKey | Should -Be $null
        }
    }
    Context "When passed invalid email" {
        It "Should return null" {
            TryGet-GoToUser -Email "Invalid email" -AuthToken $validToken -AccountKey $validAccountKey | Should -Be $null
        }
    }
    Context "When passed invalid accountKey" {
        It "Should return null" {
            TryGet-GoToUser -Email $validEmail -AuthToken $validToken -AccountKey "invalid key" | Should -Be $null
        }
    }
}

Describe "Format-PhoneNumbers" {
    Context "When passed valid csv" {
        It "Should properly format phone numbers" {
            $validCsvCopy = $validCsv.Clone()
            $validCsv | Out-Host
            $validCsvCopy | Out-Host

            Format-PhoneNumbers $validCsvCopy

            $regex = '^\+\d{11,14}$'

            foreach ($record in $validCsvCopy)
            {
                $record."Phone Number" | Out-Host
                $validNumber = $record."Phone Number" -imatch $regex
                $validNumber | Should -Be $true
            }   
        }
    }
}

Describe "Get-AllPhoneNumbers" -Skip {
    Context "When passed valid authToken" {
        It "Responses should not be null" {                       
            $responses = Get-AllPhoneNumbers $validToken $validAccountKey
            $responses | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "New-PhoneNumberLookupTable" -Skip {
    Context "When passed valid apiResponses" {
        It "Should return a sizeable hashtable" {
            $responses = Get-AllPhoneNumbers $validToken
            $lookupTable = New-PhoneNumberLookupTable $responses
            $lookupTable.Count | Should -BeGreaterThan 2
        }
    }
}

Describe "Get-AllExtensions" -Skip {
    Context "When passed valid authToken" {
        It "Responses should not be null" {
            $responses = Get-AllExtensions $validToken
            $responses | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "New-ExtensionLookupTable" -Skip {
    Context "When passed valid apiResponses" {
        It "Should return a sizeable hashtable" {
            $responses = Get-AllExtensions $validToken
            $lookupTable = New-ExtensionLookupTable $responses
            $lookupTable.Count | Should -BeGreaterThan 2
        }
    }
}

# Assign-PhoneNumbers
# Route-PhoneNumber

Describe "TryRoute-PhoneNumber" {
    Context "When passed invalid phone number" {
        It "Should return false and throw a warning" {
            TryRoute-PhoneNumber -AuthToken $validToken -PhoneNumber "Invalid Phone Number" -PhoneNumberId "Invalid ID" -ExtensionId $validExtensionId -Email $validEmail |
            Should -Be $false
        }
    }
}

Describe "TryGrant-SMSPermissions" {
    Context "When passed invalid data" {
        It "Should return 0 amountGranted" {
            TryGrant-SMSPermissions -AuthToken $validToken -AccountKey $validAccountKey -PhoneNumber "Invalid Phone Number" -PhoneNumberId "Invalid PN ID" -SmsUsers "Invalid users" |
            Should -Be 0
        }
    }
}

# Grant-SMSPermissions

Describe "ConvertTo-Name" {
    Context "When passed john.doe@domain.com" {
        It "Should return John Doe" {
            ConvertTo-Name "john.doe@domain.com" | Should -Be "John Doe"
        }
    }
    Context "When passed John.Doe@domain.com" {
        It "Should return John Doe" {
            ConvertTo-Name "John.Doe@domain.com" | Should -Be "John Doe"
        }
    }
    Context "When passed invalid email" {
        It "Should throw warning and return null" {
            ConvertTo-Name "Invalid Email" | Should -Be $null
        }
    }
}

AfterAll {
    # Optional
    # Runs once at the end of the file.
}