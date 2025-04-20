package main

import "fmt"

func writeEnabledADComputers(targetFile string) error {
	// TODO - Add option to use native LDAP query instead of PowerShell
	script := fmt.Sprintf(`
$outputFile = "%s";
$searcher = New-Object System.DirectoryServices.DirectorySearcher;
$searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))";
$searcher.PageSize = 100000;$searcher.PropertiesToLoad.Add("name") | Out-Null;
$results = $searcher.FindAll();
if (Test-Path $outputFile) {
    Clear-Content $outputFile;
};
foreach ($computer in $results) {
    $hostname = $computer.Properties["name"][0];
    Add-Content -Path $outputFile -Value $hostname;
};
`, targetFile)
	// Execute the PowerShell script
	err := runPowerShell(script)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error writing enabled AD computers: %s", err.Error()), ERROR)
		return err
	}
	printFormattedMessage(fmt.Sprintf("AD computers written to %s", targetFile), INFO)
	return nil
}
