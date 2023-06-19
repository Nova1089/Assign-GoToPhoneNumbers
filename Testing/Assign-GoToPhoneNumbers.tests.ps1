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
    - What if number was already routed to same person or someone else?
    - What if person already had SMS perms?
- Output validation
- To Do    
    - When phone numbers are invalid, give option to exit and fix script. give option to say N to all.
    - Input validation of SMS users
    - Input validation of emails
    - What happens when phone number invalid?
    - What happens when email invalid?
    - What happens when SMS users invalid?
    - Prompt for authToken as secure string
- Done but not tested
    - Explain CSV requirements.
    - Showing counts of everything processes. Granting SMS should return true if sms was granted to 1 or more users.
    - Show how many phone numbers were assigned
    - Show how many phone numbers had SMS granted
    - Assign users to write progress
- Done and tested 
    - Convert SMS users into string array
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
    $accountKey = Get-AccountKey $validToken
    $validCsv = Import-Csv "..\Private\ValidData.csv"
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
            $accountKey = Get-AccountKey $validToken

            Write-Host "accountKey is $accountKey"

            $accountKey | Should -Not -BeNullOrEmpty
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
            Add-UserInfo -ImportedCsv $validCsvCopy -AuthToken $validToken -AccountKey $accountKey

            foreach ($record in $validCsvCopy)
            {
                $hasProperty = $record.PSObject.Properties.Name -Contains "UserInfo"
                $hasProperty | Should -Be $true
            }
        }
    }
    Context "When passed all invalid users" {
        It "Should return an array of null records" {
            $invalidUsersCopy = $invalidUsers.Clone()
            Add-UserInfo -ImportedCsv $invalidUsersCopy -AuthToken $validToken -AccountKey $accountKey

            foreach ($record in $invalidUsersCopy)
            {
                $record | Should -Be $null
            }
        }        
    }
}

Describe "Get-GoTouser" {
    Context "When passed valid email and valid authToken" {
        It "Should not return null" {
            $email = Get-Content "..\Private\validEmail.txt"

            Get-GoToUser -Email $email -AuthToken $validToken -AccountKey $accountKey | Should -Not -BeNullOrEmpty
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
            $responses = Get-AllPhoneNumbers $validToken
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

Describe "ConvertTo-Name" {
    Context "When passed john.doe@domain.com" {
        It "Should return John Doe" {
            ConvertTo-Name "john.doe@domain.com" | Should -Be "John Doe"
        }
    }
    Context "When passed invalid email" {
        It "Should throw warning and return null" {
            ConvertTo-Name "Invalid Email" | Should -Be $null
        }
    }
    Context "When passed John.Doe@domain.com" {
        It "Should return John Doe" {
            ConvertTo-Name "John.Doe@domain.com" | Should -Be "John Doe"
        }
    }
}

AfterAll {
    # Optional
    # Runs once at the end of the file.
}