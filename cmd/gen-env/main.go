package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type EnvItem struct {
	Section     string
	Key         string
	Default     string
	Description string
	Required    bool
	Line        int
}

func extractFallbackValue(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		val, _ := strconv.Unquote(v.Value)
		if v.Kind == token.STRING {
			return val
		}
		return v.Value
	case *ast.Ident:
		return v.Name
	case *ast.CallExpr:
		// Handles nested calls like EnvKey("APP_NAME", "app") as a fallback
		if len(v.Args) >= 2 {
			return extractFallbackValue(v.Args[1])
		}
	}
	return ""
}

func findSourceEnvFile(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		return "", fmt.Errorf("source file %q not found", customPath)
	}

	candidates := []string{
		"config/env.go",
		"backend/config/env.go",
		"../config/env.go",
		"../../config/env.go",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", errors.New("unable to locate config/env.go automatically; use -source flag")
}

func parseEnvConfig(sourcePath string) ([]EnvItem, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, sourcePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", sourcePath, err)
	}

	// Map line numbers to comments
	commentByLine := make(map[int]string)
	for _, cg := range node.Comments {
		endLine := fset.Position(cg.End()).Line
		text := strings.TrimSpace(cg.Text())
		if text != "" {
			commentByLine[endLine] = text
		}
	}

	// Track mandatory variables from validateMandatoryEnv calls
	mandatory := make(map[string]bool)
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "validateMandatoryEnv" {
			if len(call.Args) >= 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					key, _ := strconv.Unquote(lit.Value)
					mandatory[key] = true
				}
			}
		}
		return true
	})

	var items []EnvItem
	seenKeys := make(map[string]bool)

	var traverseComposite func(section string, comp *ast.CompositeLit)
	traverseComposite = func(section string, comp *ast.CompositeLit) {
		for _, elt := range comp.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}

			fieldName := ""
			if id, ok := kv.Key.(*ast.Ident); ok {
				fieldName = id.Name
			}

			switch val := kv.Value.(type) {
			case *ast.CompositeLit:
				newSec := section
				if newSec == "" {
					newSec = fieldName
				} else {
					newSec = section + " " + fieldName
				}
				traverseComposite(newSec, val)
			case *ast.CallExpr:
				funcName := ""
				if fn, ok := val.Fun.(*ast.Ident); ok {
					funcName = fn.Name
				}
				if funcName == "EnvKey" || funcName == "EnvKeyInt" || funcName == "EnvKeyBool" {
					if len(val.Args) >= 2 {
						if keyLit, ok := val.Args[0].(*ast.BasicLit); ok {
							key, _ := strconv.Unquote(keyLit.Value)
							defVal := extractFallbackValue(val.Args[1])

							currSec := section
							if currSec == "" {
								if fieldName == "EncryptionKey" {
									currSec = "Security"
								} else {
									currSec = "Application"
								}
							}

							pos := fset.Position(kv.Pos())
							desc := commentByLine[pos.Line-1]

							items = append(items, EnvItem{
								Section:     currSec,
								Key:         key,
								Default:     defVal,
								Description: desc,
								Required:    mandatory[key],
								Line:        pos.Line,
							})
							seenKeys[key] = true
						}
					}
				}
			}
		}
	}

	// Find the Cfg = &Env{ ... } assignment
	ast.Inspect(node, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range assign.Rhs {
			unary, ok := rhs.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			comp, ok := unary.X.(*ast.CompositeLit)
			if !ok {
				continue
			}
			if id, ok := comp.Type.(*ast.Ident); ok && id.Name == "Env" {
				traverseComposite("", comp)
			}
		}
		return true
	})

	// Collect any additional standalone EnvKey calls not in the Cfg literal
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		funcName := ""
		if fn, ok := call.Fun.(*ast.Ident); ok {
			funcName = fn.Name
		}
		if (funcName == "EnvKey" || funcName == "EnvKeyInt" || funcName == "EnvKeyBool") && len(call.Args) >= 2 {
			if lit, ok := call.Args[0].(*ast.BasicLit); ok {
				key, _ := strconv.Unquote(lit.Value)
				if !seenKeys[key] {
					defVal := extractFallbackValue(call.Args[1])
					pos := fset.Position(call.Pos())
					items = append(items, EnvItem{
						Section:     "General",
						Key:         key,
						Default:     defVal,
						Description: commentByLine[pos.Line-1],
						Required:    mandatory[key],
						Line:        pos.Line,
					})
					seenKeys[key] = true
				}
			}
		}
		return true
	})

	return items, nil
}

func generateEnvContent(items []EnvItem, sourceFile string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Auto-generated from %s\n", filepath.ToSlash(sourceFile)))
	sb.WriteString("# Single Source of Truth: update defaults or validations in config/env.go directly.\n\n")

	currentSection := ""
	for _, it := range items {
		if it.Section != currentSection {
			if currentSection != "" {
				sb.WriteString("\n")
			}
			currentSection = it.Section
			sb.WriteString(fmt.Sprintf("# %s\n", currentSection))
		}

		if it.Description != "" {
			for _, line := range strings.Split(it.Description, "\n") {
				sb.WriteString(fmt.Sprintf("# %s\n", strings.TrimSpace(line)))
			}
		}

		if it.Required {
			sb.WriteString(fmt.Sprintf("# [Required]\n"))
		}

		sb.WriteString(fmt.Sprintf("%s=%s\n", it.Key, it.Default))
	}

	return sb.String()
}

func writeEnvFile(targetPath string, content string, force bool) error {
	if fi, err := os.Stat(targetPath); err == nil && fi.Size() > 0 && !force {
		return fmt.Errorf("file %s already exists and is not empty (use -force to overwrite)", targetPath)
	}

	if dir := filepath.Dir(targetPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(targetPath, []byte(content), 0644)
}

func main() {
	sourcePath := flag.String("source", "", "Path to config/env.go source file (optional, auto-discovered)")
	outputPath := flag.String("out", ".env", "Output path for generated environment file")
	generateExample := flag.Bool("example", true, "Also generate .env.example alongside target file")
	force := flag.Bool("force", false, "Force overwrite if output file already exists")
	flag.Parse()

	src, err := findSourceEnvFile(*sourcePath)
	if err != nil {
		log.Fatalf("Error locating source: %v", err)
	}

	items, err := parseEnvConfig(src)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}

	content := generateEnvContent(items, src)

	if err := writeEnvFile(*outputPath, content, *force); err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Successfully generated %s from %s (%d variables)", *outputPath, src, len(items))

	if *generateExample {
		examplePath := filepath.Join(filepath.Dir(*outputPath), ".env.example")
		if err := writeEnvFile(examplePath, content, true); err != nil {
			log.Printf("Warning: failed to write %s: %v", examplePath, err)
		} else {
			log.Printf("Successfully generated %s from %s", examplePath, src)
		}
	}
}
