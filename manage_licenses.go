package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var spdxLicenses map[string]struct{}
var licenseCorrections = map[string]string{
	"GPL-3+":                   "GPL-3.0+",
	"BSD-2-clause":             "BSD-2-Clause",
	"BSD-3-clause":             "BSD-3-Clause",
	"GPL-3":                    "GPL-3.0",
	"GPL-2+":                   "GPL-2.0+",
	"GPL-2":                    "GPL-2.0",
	"GPL-2)":                   "GPL-2.0",
	"GPL-1":                    "GPL-1.0",
	"GPL-1+":                   "GPL-1.0+",
	"LGPL-1":                   "LGPL-1.0",
	"LGPL-1+":                  "LGPL-1.0+",
	"LGPL-2":                   "LGPL-2.0",
	"LGPL-2+":                  "LGPL-2.0+",
	"LGPL-3":                   "LGPL-3.0",
	"LGPL-3+":                  "LGPL-3.0+",
	"AGPL-1":                   "AGPL-1.0",
	"AGPL-2":                   "AGPL-2.0",
	"AGPL-3":                   "AGPL-3.0",
	"WTFPL-2":                  "WTFPL",
	"APACHE-2-LLVM-EXCEPTIONS": "Apache-2.0",
	"Artistic":                 "Artistic-2.0",
	"GPL":                      "GPL-3.0",
	"GPL-any":                  "GPL-3.0",
	"BSD-2":                    "BSD-2-Clause",
	"BSD-3":                    "BSD-3-Clause",
	"BSD-4":                    "BSD-4-Clause",
	"BSD-4-clause":             "BSD-4-Clause",
	"Apache-2":                 "Apache-2.0",
	"GFDL-NIV-1.3+":            "GFDL-1.3",
	"SIL-OFL-1.1":              "OFL-1.1",
	"SIL-1.1":                  "OFL-1.1",
	"AGPL-3+":                  "AGPL-3.0-or-later",
	"OpenLDAP-2.8":             "OLDAP-2.8",
	"LPGL-2.1+":                "LGPL-2.1-or-later",
	"MIT-1":                    "MIT",
	"BSD-3-clauses":            "BSD-3-Clause",

	// Add more corrections as needed
}

// loadSPDXSchema loads the SPDX license schema from the specified file path.
//
// It takes a schemaPath string as a parameter, which is the path to the SPDX schema file.
//
// It returns an error if there is any issue opening or reading the file, or if the schema file cannot be parsed.
//
// The function opens the file specified by the schemaPath and reads its contents.
// It then unmarshals the JSON data into a struct with an "enum" field.
// The function then creates a map to store the SPDX licenses.
// It iterates over the "enum" field of the schema and adds each license to the map.
// Finally, it logs the number of loaded SPDX licenses and returns nil.
func loadSPDXSchema(schemaPath string) error {
	file, err := os.Open(schemaPath)
	if err != nil {
		return fmt.Errorf("error opening SPDX schema file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading SPDX schema file: %v", err)
	}

	var schema struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("failed to parse SPDX schema: %v", err)
	}

	spdxLicenses = make(map[string]struct{})
	fmt.Println("Parsing SPDX schema...")

	for _, license := range schema.Enum {
		//fmt.Printf("Loaded license: %s\n", license)
		spdxLicenses[license] = struct{}{}
	}

	// Log the loaded SPDX licenses for debugging
	fmt.Printf("Loaded %d SPDX licenses\n", len(spdxLicenses))

	return nil
}

// FetchPackageLicense retrieves the license of a package.
//
// packageManager is the package manager used.
// packageName is the name of the package.
// Returns a slice of strings representing the licenses of the package.
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

// fallbackFetchLicense retrieves the license information of a package from common locations.
//
// It takes a package name as a parameter and returns the license information as a string.
// If the license information is not found in the common locations, it returns "UNKNOWN".
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

// correctLicenses takes a string of licenses and returns a list of valid licenses.
//
// It splits the input string by common delimiters and filters out bind words.
// It also corrects licenses using a map of license corrections.
// If a license is not found in the SPDX license list, it is considered invalid.
//
// Parameters:
// - licenses: a string of licenses, separated by common delimiters.
//
// Returns:
// - a list of valid licenses.
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
			} else {
				fmt.Printf("Invalid license: %s\n", license)
			}
		}
	}

	// Log the valid licenses for debugging
	// fmt.Printf("Valid licenses: %v\n", validLicenses)
	return validLicenses
}
