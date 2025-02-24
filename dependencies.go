package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

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
