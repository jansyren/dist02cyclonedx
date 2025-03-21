package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Project struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Parent     *UUID  `json:"parent,omitempty"`
	Classifier string `json:"classifier"`
}

type UUID struct {
	UUID string `json:"uuid"`
}

type SBOMUpload struct {
	ProjectUUID string `json:"project"`
	AutoCreate  bool   `json:"autoCreate"`
	BOM         string `json:"bom"`
}

// getProjectUUID retrieves the UUID of a project from the Dependency-Track API.
//
// Parameters:
// - apiURL: the URL of the Dependency-Track API.
// - apiKey: the API key for authentication.
// - name: the name of the project.
// - tlsVerify: a boolean indicating whether to verify the TLS certificate.
//
// Returns:
// - *UUID: the UUID of the project.
// - error: an error if the request fails or the response is not OK.
func getProjectUUID(apiURL, apiKey, name string, tlsVerify bool) (*UUID, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/project?name=%s", apiURL, name), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(body))
	}

	var projects []UUID
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	if len(projects) == 0 {
		return nil, fmt.Errorf("project not found")
	}

	return &projects[0], nil
}

// createProject creates a new project in the Dependency-Track API.
//
// Parameters:
// - apiURL: the URL of the Dependency-Track API.
// - apiKey: the API key for authentication.
// - name: the name of the project.
// - version: the version of the project.
// - classifier: the classifier of the project.
// - parentUUID: the UUID of the parent project.
// - tlsVerify: a boolean indicating whether to verify the TLS certificate.
//
// Returns:
// - *UUID: the UUID of the created project.
// - error: an error if the request fails or the response is not OK.
func createProject(apiURL, apiKey, name, version, classifier string, parentUUID *UUID, tlsVerify bool) (*UUID, error) {
	project := Project{
		Name:       name,
		Version:    version,
		Classifier: classifier,
		Parent:     parentUUID,
	}

	projectJSON, err := json.Marshal(project)
	if err != nil {
		return nil, fmt.Errorf("error marshaling project JSON: %v", err)
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/project", apiURL), bytes.NewBuffer(projectJSON))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Project already exists, retrieve its UUID
		existingUUID, err := getProjectUUID(apiURL, apiKey, name, tlsVerify)
		if err != nil {
			return nil, fmt.Errorf("error retrieving existing project UUID: %v", err)
		}
		return existingUUID, nil
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(body))
	}

	var projectUUID UUID
	if err := json.NewDecoder(resp.Body).Decode(&projectUUID); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &projectUUID, nil
}

// uploadSBOM uploads a Software Bill of Materials (SBOM) to the Dependency-Track API.
//
// Parameters:
// - apiURL: the URL of the Dependency-Track API.
// - apiKey: the API key for authentication.
// - distro: the name of the operating system distribution.
// - hostname: the hostname of the system.
// - osVersion: the version of the operating system.
// - sbomJSON: the SBOM in JSON format.
// - tlsVerify: a boolean indicating whether to verify the TLS certificate.
//
// Returns:
// - error: an error if the upload fails.
func uploadSBOM(apiURL, apiKey, distro, hostname, osVersion string, sbomJSON []byte, tlsVerify bool) error {
	// Create or get the parent project for the distro
	parentProjectUUID, err := createProject(apiURL, apiKey, distro, "", "OPERATING_SYSTEM", nil, tlsVerify)
	if err != nil {
		return fmt.Errorf("error creating or getting parent project: %v", err)
	}

	// Create or get the project for the hostname
	projectUUID, err := createProject(apiURL, apiKey, hostname, osVersion, "OPERATING_SYSTEM", parentProjectUUID, tlsVerify)
	if err != nil {
		return fmt.Errorf("error creating or getting project: %v", err)
	}

	// Base64 encode the SBOM
	sbomBase64 := base64.StdEncoding.EncodeToString(sbomJSON)

	// Upload the SBOM
	sbomUpload := SBOMUpload{
		ProjectUUID: projectUUID.UUID,
		AutoCreate:  true,
		BOM:         sbomBase64,
	}

	sbomUploadJSON, err := json.Marshal(sbomUpload)
	if err != nil {
		return fmt.Errorf("error marshaling SBOM upload JSON: %v", err)
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/bom", apiURL), bytes.NewBuffer(sbomUploadJSON))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}
