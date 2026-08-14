package main

import (
	"log"
	"os"
	"os/exec"

	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1"
	"gopkg.in/yaml.v3"
)

func main() {
	// 1. Generate _bundled.yaml
	swagger := apiv1.BuildSpec()
	yamlData, err := yaml.Marshal(swagger)
	if err != nil {
		log.Fatalf("failed to marshal: %v", err)
	}

	bundledPath := "api/openapi/v1/_bundled.yaml"
	err = os.WriteFile(bundledPath, yamlData, 0644)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
	log.Println("Successfully generated api/openapi/v1/_bundled.yaml!")

	// 2. Generate Go Code (replacing genapi.sh)
	outputCodePath := "api/openapi/v1/generated/api.gen.go"

	// Ensure output folder exists
	err = os.MkdirAll("api/openapi/v1/generated", 0755)
	if err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	// Run oapi-codegen
	cmd := exec.Command("go", "run", "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest",
		"-package", "apiv1",
		"-generate", "types,chi-server,spec",
		bundledPath,
	)

	// Direct stdout of the command to the target file
	outFile, err := os.Create(outputCodePath)
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	defer outFile.Close()
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to generate Go code: %v", err)
	}

	log.Println("Successfully generated api/openapi/v1/generated/api.gen.go!")
}
