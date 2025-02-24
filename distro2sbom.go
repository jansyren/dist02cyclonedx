package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Supplier information for each distribution
var supplierInfo = map[string]cyclonedx.OrganizationalEntity{
	"ubuntu": {
		Name: "Ubuntu Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "ubuntu-devel-discuss@lists.ubuntu.com"},
		},
	},
	"debian": {
		Name: "Debian Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "debian-devel@lists.debian.org"},
		},
	},
	"alpine": {
		Name: "Alpine Linux Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "alpine-devel@lists.alpinelinux.org"},
		},
	},
	"centos": {
		Name: "CentOS Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "centos-devel@centos.org"},
		},
	},
	"fedora": {
		Name: "Fedora Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "devel@lists.fedoraproject.org"},
		},
	},
	"rhel": {
		Name: "Red Hat Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "devel@redhat.com"},
		},
	},
	"opensuse": {
		Name: "openSUSE Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "opensuse-devel@opensuse.org"},
		},
	},
	"rocky": {
		Name: "Rocky Linux Developers",
		Contact: &[]cyclonedx.OrganizationalContact{
			{Email: "devel@lists.rockylinux.org"},
		},
	},
}

func main() {
	viper.SetConfigName("dist02cyclonedx")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/")
	viper.AutomaticEnv()

	// Read the config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
	}

	var distro string
	var output string
	var apiURL string
	var apiKey string

	var rootCmd = &cobra.Command{
		Use:   "distro2sbom",
		Short: "Generate SBOM for a Linux distribution.",
		Long:  `distro2sbom generates a Software Bill of Materials (SBOM) for a given Linux distribution using CycloneDX format.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("distro") {
				distro = viper.GetString("distro")
			} else {
				distro, _ = cmd.Flags().GetString("distro")
			}
			if !cmd.Flags().Changed("output") {
				output = viper.GetString("output")
			} else {
				output, _ = cmd.Flags().GetString("output")
			}
			if !cmd.Flags().Changed("api-url") {
				apiURL = viper.GetString("api-url")
			} else {
				apiURL, _ = cmd.Flags().GetString("api-url")
			}
			if !cmd.Flags().Changed("api-key") {
				apiKey = viper.GetString("api-key")
			} else {
				apiKey, _ = cmd.Flags().GetString("api-key")
			}

			if distro == "" {
				fmt.Println("Please specify a distribution using the --distro flag.")
				return
			}

			sbom, err := generateSBOM(distro, "1.0")
			if err != nil {
				log.Fatalf("Error generating SBOM: %v", err)
			}

			sbomJSON, err := json.MarshalIndent(sbom, "", "  ")
			if err != nil {
				log.Fatalf("Error marshaling SBOM to JSON: %v", err)
			}

			if output == "" {
				fmt.Println(string(sbomJSON))
			} else {
				if err := os.WriteFile(output, sbomJSON, 0644); err != nil {
					log.Fatalf("Error writing SBOM to file: %v", err)
				}
			}

			if apiURL != "" && apiKey != "" {
				hostname, err := os.Hostname()
				if err != nil {
					log.Fatalf("Error getting hostname: %v", err)
				}

				osVersion := getOSVersion()

				err = uploadSBOM(apiURL, apiKey, distro, hostname, osVersion, sbomJSON)
				if err != nil {
					log.Fatalf("Error uploading SBOM: %v", err)
				}
			} else if apiURL != "" || apiKey != "" {
				fmt.Println("Both api-url and api-key must be provided to upload the SBOM.")
			}
		},
	}

	rootCmd.Flags().StringVarP(&distro, "distro", "d", "", "Linux distribution (e.g., ubuntu, debian)")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "Output file for SBOM (default: stdout)")
	rootCmd.Flags().StringVar(&apiURL, "api-url", "", "Dependency-Track API URL")
	rootCmd.Flags().StringVar(&apiKey, "api-key", "", "Dependency-Track API Key")

	viper.BindPFlag("distro", rootCmd.Flags().Lookup("distro"))
	viper.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	viper.BindPFlag("api-url", rootCmd.Flags().Lookup("api-url"))
	viper.BindPFlag("api-key", rootCmd.Flags().Lookup("api-key"))

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generateSBOM(distro string, version string) (*cyclonedx.BOM, error) {
	bom := cyclonedx.NewBOM()
	bom.Version = 1
	bom.SpecVersion = cyclonedx.SpecVersion1_6
	bom.SerialNumber = uuid.New().URN()
	bom.BOMFormat = "CycloneDX"

	// Set Metadata with lifecycles
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Lifecycles: &[]cyclonedx.Lifecycle{
			{Phase: "operations"},
		},
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:    cyclonedx.ComponentTypeApplication,
					Name:    "distro2sbom",
					Version: "0.5.2",
				},
			},
		},
		Component: &cyclonedx.Component{
			Type:    cyclonedx.ComponentTypeOS,
			Name:    distro,
			Version: version,
			BOMRef:  "CDXRef-DOCUMENT",
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{
					URL:     "https://www." + strings.ToLower(distro) + ".com/",
					Type:    cyclonedx.ERTypeWebsite,
					Comment: "Home page for project",
				},
			},
		},
	}

	// Create a root component for the entire system or project
	rootComponent := cyclonedx.Component{
		Type:    cyclonedx.ComponentTypeApplication,
		Name:    "RootComponent",
		Version: version,
		BOMRef:  "CDXRef-RootComponent",
	}

	// Determine package manager
	var packageManager string
	switch strings.ToLower(distro) {
	case "ubuntu", "debian":
		packageManager = "dpkg"
	case "alpine":
		packageManager = "apk"
	case "centos", "fedora", "rhel", "opensuse", "rocky":
		packageManager = "rpm"
	default:
		return nil, fmt.Errorf("unsupported distribution: %s", distro)
	}

	// Retrieve installed packages
	packages, err := listPackages(packageManager)
	if err != nil {
		return nil, fmt.Errorf("error listing packages: %v", err)
	}

	components := []cyclonedx.Component{rootComponent}
	componentMap := make(map[string]string)

	for i, pkg := range packages {
		bomRef := fmt.Sprintf("%d-%s", i+1, pkg.Name)
		licenses := FetchPackageLicense(packageManager, pkg.Name)

		// Construct CPE
		cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", strings.ReplaceAll(distro, " ", "_"), pkg.Name, pkg.Version)

		// Construct External References
		externalRefs := []cyclonedx.ExternalReference{
			{
				URL:     "https://packages." + strings.ToLower(distro) + ".org/" + pkg.Name,
				Type:    cyclonedx.ERTypeDistribution,
				Comment: "Package distribution reference",
			},
		}

		// Build License struct
		licenseChoices := cyclonedx.Licenses{}
		for _, license := range licenses {
			if license != "UNKNOWN" {
				licenseChoices = append(licenseChoices, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						ID:              license,
						URL:             "https://spdx.org/licenses/" + license + ".html",
						Acknowledgement: cyclonedx.LicenseAcknowledgementConcluded,
					},
				})
			}
		}

		// Get supplier information based on the distribution
		supplier := supplierInfo[strings.ToLower(distro)]

		component := cyclonedx.Component{
			Type:               cyclonedx.ComponentTypeLibrary,
			Name:               pkg.Name,
			Version:            pkg.Version,
			BOMRef:             bomRef,
			Supplier:           &supplier,
			PackageURL:         fmt.Sprintf("pkg:%s/%s@%s", packageManager, pkg.Name, pkg.Version),
			CPE:                cpe,
			ExternalReferences: &externalRefs,
			Licenses:           &licenseChoices,
		}

		components = append(components, component)
		componentMap[pkg.Name] = bomRef
	}

	bom.Components = &components

	// Process Dependencies
	bomDependencies := []cyclonedx.Dependency{
		{
			Ref:          "CDXRef-DOCUMENT",
			Dependencies: &[]string{},
		},
	}
	packageNames := make([]string, len(components)-1)
	for i, comp := range components[1:] {
		packageNames[i] = comp.Name
	}

	dependencyMap, err := getDependencies(packageManager, packageNames)
	if err != nil {
		return nil, fmt.Errorf("error getting dependencies: %v", err)
	}

	for _, comp := range components[1:] {
		deps := dependencyMap[comp.Name]
		depSet := make(map[string]struct{})
		for _, dep := range deps {
			if ref, exists := componentMap[dep]; exists {
				depSet[ref] = struct{}{}
			}
		}

		depRefs := []string{}
		for ref := range depSet {
			depRefs = append(depRefs, ref)
		}

		if len(depRefs) > 0 {
			bomDependencies = append(bomDependencies, cyclonedx.Dependency{
				Ref:          comp.BOMRef,
				Dependencies: &depRefs,
			})
		}

		// Link all components as dependencies of the root component
		rootDeps := *bomDependencies[0].Dependencies
		rootDeps = append(rootDeps, comp.BOMRef)
		bomDependencies[0].Dependencies = &rootDeps
	}

	bom.Dependencies = &bomDependencies

	return bom, nil
}

func parseLicenseInfo(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "License:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		}
	}
	return ""
}

func listPackages(packageManager string) ([]struct {
	Name    string
	Version string
}, error) {
	var cmd *exec.Cmd
	switch packageManager {
	case "dpkg":
		cmd = exec.Command("dpkg-query", "-W", "-f=${Package} ${Version}\n")
	case "apk":
		cmd = exec.Command("apk", "info", "-v")
	case "rpm":
		cmd = exec.Command("rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n")
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error executing command: %v", err)
	}

	var packages []struct {
		Name    string
		Version string
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) == 2 {
			packages = append(packages, struct {
				Name    string
				Version string
			}{
				Name:    parts[0],
				Version: parts[1],
			})
		}
	}

	return packages, nil
}

func getDependencies(packageManager string, packageNames []string) (map[string][]string, error) {
	dependencyMap := make(map[string][]string)

	switch packageManager {
	case "dpkg":
		// Check if apt-rdepends is available
		if _, err := exec.LookPath("apt-rdepends"); err == nil {
			for _, packageName := range packageNames {
				cmd := exec.Command("apt-rdepends", packageName)
				output, err := cmd.Output()
				if err != nil {
					return nil, fmt.Errorf("error executing apt-rdepends: %v", err)
				}
				dependencies := parseAptRdependsOutput(string(output))
				dependencyMap[packageName] = dependencies
			}
		} else {
			// Fallback to apt-cache
			for _, packageName := range packageNames {
				cmd := exec.Command("apt-cache", "depends", packageName)
				output, err := cmd.Output()
				if err != nil {
					return nil, fmt.Errorf("error executing apt-cache: %v", err)
				}
				dependencies := parseAptCacheOutput(string(output))
				dependencyMap[packageName] = dependencies
			}
		}
	case "rpm":
		for _, packageName := range packageNames {
			cmd := exec.Command("rpm", "-qR", packageName)
			output, err := cmd.Output()
			if err != nil {
				return nil, fmt.Errorf("error executing rpm: %v", err)
			}
			dependencies := parseRpmOutput(string(output))
			dependencyMap[packageName] = dependencies
		}
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}

	return dependencyMap, nil
}

func parseAptRdependsOutput(output string) []string {
	var dependencies []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "  Depends:") {
			dependency := strings.TrimSpace(strings.TrimPrefix(line, "  Depends:"))
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func parseAptCacheOutput(output string) []string {
	var dependencies []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "  Depends:") {
			dependency := strings.TrimSpace(strings.TrimPrefix(line, "  Depends:"))
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func parseRpmOutput(output string) []string {
	var dependencies []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "rpmlib(") {
			dependencies = append(dependencies, line)
		}
	}
	return dependencies
}

func getOSVersion() string {
	if runtime.GOOS == "linux" {
		file, err := os.Open("/etc/os-release")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "VERSION_ID=") {
					return strings.Trim(line[11:], "\"")
				}
			}
		}
		cmd := exec.Command("uname", "-r")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func fetchDependencies(packageManager, packageName string) ([]string, error) {
	var cmd *exec.Cmd
	switch packageManager {
	case "dpkg":
		cmd = exec.Command("apt-cache", "depends", packageName)
	case "apk":
		cmd = exec.Command("apk", "info", "-d", packageName)
	case "rpm":
		cmd = exec.Command("rpm", "-qR", packageName)
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error executing dependency command: %v", err)
	}

	var dependencies []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		dependencies = append(dependencies, strings.TrimSpace(scanner.Text()))
	}

	return dependencies, nil
}
