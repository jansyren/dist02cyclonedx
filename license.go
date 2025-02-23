package main

import (
    "bufio"
    "embed"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

//go:embed spdx.schema.json
var spdxSchema embed.FS

var spdxLicenses map[string]struct{}
var licenseCorrections = map[string]string{
    "GPL-3+":        "GPL-3.0+",
    "BSD-2-clause":  "BSD-2-Clause",
    "BSD-3-clause":  "BSD-3-Clause",
    "GPL-3":         "GPL-3.0",
	"GPL-2+":        "GPL-2.0+",
	"GPL-2":         "GPL-2.0",
	"GPL-1":         "GPL-1.0",
	"GPL-1+":        "GPL-1.0+",
	"LGPL-1":        "LGPL-1.0",
	"LGPL-1+": 	     "LGPL-1.0+",
	"LGPL-2":        "LGPL-2.0",
	"LGPL-2+":       "LGPL-2.0+",
	"LGPL-3":        "LGPL-3.0",
	"LGPL-3+":       "LGPL-3.0+",
	"AGPL-1":        "AGPL-1.0",
	"AGPL-2":        "AGPL-2.0",
	"AGPL-3":        "AGPL-3.0",
	"WTFPL-2":       "WTFPL",
	"APACHE-2-LLVM-EXCEPTIONS": "Apache-2.0",
	"Artistic":	  "Artistic-2.0",
    // Add more corrections as need
}

func init() {
    // Load SPDX licenses from the embedded schema
    data, err := spdxSchema.ReadFile("spdx.schema.json")
    if err != nil {
        fmt.Printf("Failed to read SPDX schema: %v\n", err)
        os.Exit(1)
    }

    var schema map[string]interface{}
    if err := json.Unmarshal(data, &schema); err != nil {
        fmt.Printf("Failed to parse SPDX schema: %v\n", err)
        os.Exit(1)
    }

    spdxLicenses = make(map[string]struct{})
    if definitions, ok := schema["definitions"].(map[string]interface{}); ok {
        if licenseEnum, ok := definitions["license"].(map[string]interface{}); ok {
            if enum, ok := licenseEnum["enum"].([]interface{}); ok {
                for _, license := range enum {
                    if licenseStr, ok := license.(string); ok {
                        spdxLicenses[licenseStr] = struct{}{}
                    }
                }
            }
        }
    }
}

func FetchPackageLicense(packageManager, packageName string) []string {
    var cmd *exec.Cmd
    switch packageManager {
    case "dpkg":
        cmd = exec.Command("dpkg-query", "-W", "-f=${License}", packageName)
    case "apk":
        cmd = exec.Command("apk", "info", "-L", packageName)
    case "rpm":
        cmd = exec.Command("rpm", "-q", "--qf", "%{LICENSE}", packageName)
    default:
        return correctLicenses(fallbackFetchLicense(packageName))
    }

    output, err := cmd.Output()
    if err != nil || len(output) == 0 {
        // Fallback method
        licenses := fallbackFetchLicense(packageName)
        return correctLicenses(licenses)
    }

    licenses := strings.TrimSpace(string(output))
    return correctLicenses(licenses)
}

func fallbackFetchLicense(packageName string) string {
    // Check common locations for license files
    licensePaths := []string{
        fmt.Sprintf("/usr/share/doc/%s/copyright", packageName),
        fmt.Sprintf("/usr/share/licenses/%s/LICENSE", packageName),
        fmt.Sprintf("/usr/share/%s/LICENSE", packageName),
    }

    for _, licensePath := range licensePaths {
        if content, err := os.ReadFile(licensePath); err == nil {
            scanner := bufio.NewScanner(strings.NewReader(string(content)))
            for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if strings.HasPrefix(line, "License:") {
                    return strings.TrimSpace(strings.TrimPrefix(line, "License:"))
                }
            }
        }
    }

    return "UNKNOWN"
}

func correctLicenses(licenses string) []string {
    // Split licenses by common delimiters
    licenseList := strings.FieldsFunc(licenses, func(r rune) bool {
        return r == ',' || r == '|' || r == '/' || r == '&' || r == ' ' || r == ';'
    })

    // Filter out bind words and correct licenses
    validLicenses := []string{}
    bindWords := map[string]struct{}{
        "and": {},
        "or":  {},
    }

    for _, license := range licenseList {
        license = strings.TrimSpace(license)
        if _, isBindWord := bindWords[license]; !isBindWord {
            if correctedLicense, exists := licenseCorrections[license]; exists {
                license = correctedLicense
            }
            if _, isValid := spdxLicenses[license]; isValid {
                validLicenses = append(validLicenses, license)
            }
        }
    }
    return validLicenses
}