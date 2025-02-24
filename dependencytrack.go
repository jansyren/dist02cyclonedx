package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func createProject(apiURL, apiKey, name, version, classifier string, parentUUID *UUID) (*UUID, error) {
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var projectUUID UUID
	if err := json.NewDecoder(resp.Body).Decode(&projectUUID); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &projectUUID, nil
}

func uploadSBOM(apiURL, apiKey, distro, hostname, osVersion string, sbomJSON []byte) error {
	// Create or get the parent project for the distro
	parentProjectUUID, err := createProject(apiURL, apiKey, distro, "", "ComponentTypeOS", nil)
	if err != nil {
		return fmt.Errorf("error creating or getting parent project: %v", err)
	}

	// Create or get the project for the hostname
	projectUUID, err := createProject(apiURL, apiKey, hostname, osVersion, "ComponentTypeOS", parentProjectUUID)
	if err != nil {
		return fmt.Errorf("error creating or getting project: %v", err)
	}

	// Upload the SBOM
	sbomUpload := SBOMUpload{
		ProjectUUID: projectUUID.UUID,
		AutoCreate:  true,
		BOM:         string(sbomJSON),
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
