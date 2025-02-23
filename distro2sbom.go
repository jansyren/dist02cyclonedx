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
)


func main() {
    var distro string
    var output string

    var rootCmd = &cobra.Command{
        Use:   "distro2sbom",
        Short: "Generate SBOM for a Linux distribution.",
        Long:  `distro2sbom generates a Software Bill of Materials (SBOM) for a given Linux distribution using CycloneDX format.`,
        Run: func(cmd *cobra.Command, args []string) {
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
        },
    }

    rootCmd.Flags().StringVarP(&distro, "distro", "d", "", "Linux distribution (e.g., ubuntu, debian)")
    rootCmd.Flags().StringVarP(&output, "output", "o", "", "Output file for SBOM (default: stdout)")

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
    case "centos", "fedora", "rhel", "opensuse":
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

        component := cyclonedx.Component{
            Type:    cyclonedx.ComponentTypeLibrary,
            Name:    pkg.Name,
            Version: pkg.Version,
            BOMRef:  bomRef,
            Supplier: &cyclonedx.OrganizationalEntity{
                Name: "Ubuntu Developers",
                Contact: &[]cyclonedx.OrganizationalContact{
                    {Email: "ubuntu-devel-discuss@lists.ubuntu.com"},
                },
            },
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
            Ref:          "CDXRef-RootComponent",
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
		return nil, fmt.Errorf("error executing package list command: %v", err)
	}

	var packages []struct {
		Name    string
		Version string
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
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

func getDependencies(packageManager string, packageNames []string) (map[string][]string, error) {
    type result struct {
        packageName  string
        dependencies []string
        err          error
    }

    numWorkers := 8
    jobs := make(chan string, len(packageNames))
    results := make(chan result, len(packageNames))

    // Worker function
    worker := func() {
        for packageName := range jobs {
            dependencies, err := fetchDependencies(packageManager, packageName)
            results <- result{packageName, dependencies, err}
        }
    }

    // Start workers
    for i := 0; i < numWorkers; i++ {
        go worker()
    }

    // Send jobs
    for _, packageName := range packageNames {
        jobs <- packageName
    }
    close(jobs)

    // Collect results
    dependencyMap := make(map[string][]string)
    for i := 0; i < len(packageNames); i++ {
        res := <-results
        if res.err != nil {
            return nil, res.err
        }
        dependencyMap[res.packageName] = res.dependencies
    }

    return dependencyMap, nil
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
