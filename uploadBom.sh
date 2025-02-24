#!/bin/bash
# This script processes all *.json BOM files in the current directory.
# For each file:
#   1. If the file is empty, it skips to the next one.
#   2. Otherwise, it extracts the project name (filename without .json),
#      checks if the project exists under parent "Something", creates it if missing,
#      and uploads the BOM to Dependency-Track.

# Update these configuration variables as needed.
DTRACK_URL=""
API_KEY=""

# Lookup the parent project "Something"
echo "Looking up parent project 'Something'..."
PARENT_RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" "$DTRACK_URL/project?name=Something")
PARENT_UUID=$(echo "$PARENT_RESPONSE" | jq -r '.[0].uuid')

if [ "$PARENT_UUID" == "null" ] || [ -z "$PARENT_UUID" ]; then
    echo "Error: Parent project 'Something' not found. Please create it first."
    exit 1
fi
echo "Found parent project 'Something' with UUID: $PARENT_UUID"

# Process each BOM JSON file in the current directory.
for bom in *.json; do
    # Check if file is empty (zero size). If so, skip it.
    if [ ! -s "$bom" ]; then
        echo "File $bom is empty, skipping..."
        continue
    fi

    # Extract project name by removing the .json suffix.
    PROJECT_NAME="${bom%.json}"
    echo "Processing BOM file: $bom (project: $PROJECT_NAME)"

    # Check if the project already exists.
    PROJECT_RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" "$DTRACK_URL/project?name=${PROJECT_NAME}")
    PROJECT_UUID=$(echo "$PROJECT_RESPONSE" | jq -r '.[0].uuid')

    if [ "$PROJECT_UUID" == "null" ] || [ -z "$PROJECT_UUID" ]; then
        echo "Project '$PROJECT_NAME' not found. Creating new project..."
        # Prepare a JSON payload for project creation.
        CREATE_PAYLOAD=$(jq -n --arg name "$PROJECT_NAME" --arg parent "$PARENT_UUID" '{
            name: $name,
            version: "1.0.0",
            classifier: "CONTAINER",
            parent: { uuid: $parent }
        }')
        CREATE_RESPONSE=$(curl -s -X PUT -H "X-API-Key: $API_KEY" \
                          -H "Content-Type: application/json" -d "$CREATE_PAYLOAD" "$DTRACK_URL/project")
        PROJECT_UUID=$(echo "$CREATE_RESPONSE" | jq -r '.uuid')
        if [ "$PROJECT_UUID" == "null" ] || [ -z "$PROJECT_UUID" ]; then
            echo "Error: Failed to create project '$PROJECT_NAME'. Skipping BOM upload."
            continue
        fi
        echo "Created project '$PROJECT_NAME' with UUID: $PROJECT_UUID"
    else
        echo "Project '$PROJECT_NAME' already exists with UUID: $PROJECT_UUID"
    fi

    # Upload the BOM to Dependency-Track using multipart/form-data.
    echo "Uploading BOM '$bom' to project '$PROJECT_NAME'..."
    UPLOAD_RESPONSE=$(curl -s -X POST \
        -H "X-API-Key: $API_KEY" \
        -F "project=$PROJECT_UUID" \
        -F "autoCreate=false" \
        -F "bom=@$bom;type=application/json" \
        "$DTRACK_URL/bom")
    echo "Upload response: $UPLOAD_RESPONSE"
    echo "--------------------------------------"
done
