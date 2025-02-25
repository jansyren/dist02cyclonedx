package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GetDependencies fetches the dependencies of a list of packages using a specified package manager.
//
// Parameters:
// - packageManager: the package manager to use for fetching dependencies.
// - packageNames: a list of package names for which to fetch dependencies.
//
// Returns:
// - a map of package names to their dependencies.
// - an error if there was a problem fetching the dependencies.
func GetDependencies(packageManager string, packageNames []string) (map[string][]string, error) {
	type result struct {
		packageName  string
		dependencies []string
		err          error
	}

	fmt.Fprintf(os.Stderr, "Fetching dependencies for %d packages using %s...\n", len(packageNames), packageManager)

	numWorkers := 4
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
	for range numWorkers {
		go worker()
	}

	// Send jobs
	for _, packageName := range packageNames {
		jobs <- packageName
	}
	close(jobs)

	// Collect results
	dependencyMap := make(map[string][]string)
	for range packageNames {
		res := <-results
		if res.err != nil {
			return nil, res.err
		}
		dependencyMap[res.packageName] = res.dependencies
	}

	return dependencyMap, nil
}

/*************  ✨ Codeium AI Suggestion  *************/
// fetchDependencies fetches the dependencies of a package using the specified package manager.
//
// Parameters:
// - packageManager: the package manager to use for fetching dependencies.
// - packageName: the name of the package for which to fetch dependencies.
//
// Returns:
// - a slice of strings representing the dependencies of the package.
// - an error if there was a problem executing the command.
/****  bot-606125c3-00c4-4551-9a52-eedb7516de21  *****/
func fetchDependencies(packageManager, packageName string) ([]string, error) {
	var cmd *exec.Cmd
	switch packageManager {
	case "dpkg":
		fmt.Println("Fetching dependencies for", packageName)
		cmd = exec.Command("apt-cache", "depends", packageName)
	case "apk":
		cmd = exec.Command("apk", "info", "-d", packageName)
	case "rpm":
		cmd = exec.Command("rpm", "-qR", packageName)
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error executing dependency command: %v, stderr: %s", err, stderr.String())
	}

	var dependencies []string
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			dependencies = append(dependencies, line)
		}
	}

	return dependencies, nil
}
