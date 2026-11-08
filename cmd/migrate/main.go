package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/misbakhul29/backend-framework/config"
	dbPkg "github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/security"
	"github.com/pressly/goose/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const migrationsDir = "migrations"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		cmdInit()
	case "make", "create":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: go run ./cmd/migrate make <migration_name>")
		}
		cmdMake(os.Args[2])
	case "push", "up":
		cmdPush()
	case "rollback", "down":
		cmdRollback()
	case "status":
		cmdStatus()
	case "seed":
		cmdSeed()
	case "reset":
		cmdReset()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: go run ./cmd/migrate <command> [args]")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  init             Initialize migrations directory and baseline schema")
	fmt.Println("  make <name>      Create a new timestamped migration SQL file")
	fmt.Println("  push, up         Apply all pending migrations and seed default roles")
	fmt.Println("  rollback, down   Rollback the most recent migration")
	fmt.Println("  status           Show migration status (applied vs pending)")
	fmt.Println("  seed             Seed registered roles and permissions")
	fmt.Println("  reset            Rollback all applied migrations")
}

func getDB() (*gorm.DB, error) {
	env := config.LoadEnv()
	db, err := gorm.Open(postgres.Open(env.Database.DatabaseUrl()), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return db, nil
}

func cmdInit() {
	if err := os.MkdirAll(migrationsDir, 0755); err != nil {
		log.Fatalf("failed to create migrations directory: %v", err)
	}

	baselineFile := filepath.Join(migrationsDir, "000001_init_auth_schema.sql")
	if _, err := os.Stat(baselineFile); err == nil {
		fmt.Printf("✓ Migrations directory and baseline '%s' already initialized.\n", baselineFile)
		return
	}

	fmt.Printf("✓ Initialized migrations directory: %s\n", migrationsDir)
	fmt.Printf("✓ Baseline schema present at %s\n", baselineFile)
}

func cmdMake(name string) {
	if err := os.MkdirAll(migrationsDir, 0755); err != nil {
		log.Fatalf("failed to create migrations directory: %v", err)
	}

	sanitized := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	sanitized = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, sanitized)

	timestamp := time.Now().UTC().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s.sql", timestamp, sanitized)
	filePath := filepath.Join(migrationsDir, filename)

	content := `-- +goose Up
-- SQL in this section is executed when the migration is applied.


-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

`

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		log.Fatalf("failed to write migration file: %v", err)
	}

	fmt.Printf("✓ Created new migration: %s\n", filePath)
}

func cmdPush() {
	db, err := getDB()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Error getting sql.DB: %v", err)
	}
	defer sqlDB.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("Error setting goose dialect: %v", err)
	}

	fmt.Println("Applying pending migrations...")
	if err := goose.Up(sqlDB, migrationsDir); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	fmt.Println("✓ All migrations successfully applied.")

	// Auto-seed default roles and permissions
	fmt.Println("Seeding roles and permissions...")
	if err := dbPkg.SeedRolesAndPermissions(db, security.RegisteredPermissions); err != nil {
		log.Fatalf("Failed to seed roles and permissions: %v", err)
	}
	fmt.Println("✓ Seed completed.")
}

func cmdRollback() {
	db, err := getDB()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Error getting sql.DB: %v", err)
	}
	defer sqlDB.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("Error setting goose dialect: %v", err)
	}

	fmt.Println("Rolling back last migration...")
	if err := goose.Down(sqlDB, migrationsDir); err != nil {
		log.Fatalf("Rollback failed: %v", err)
	}
	fmt.Println("✓ Successfully rolled back 1 migration.")
}

func cmdStatus() {
	db, err := getDB()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Error getting sql.DB: %v", err)
	}
	defer sqlDB.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("Error setting goose dialect: %v", err)
	}

	fmt.Println("Migration status:")
	if err := goose.Status(sqlDB, migrationsDir); err != nil {
		log.Fatalf("Failed to get status: %v", err)
	}
}

func cmdReset() {
	db, err := getDB()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Error getting sql.DB: %v", err)
	}
	defer sqlDB.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("Error setting goose dialect: %v", err)
	}

	fmt.Println("Resetting all migrations...")
	if err := goose.Reset(sqlDB, migrationsDir); err != nil {
		log.Fatalf("Reset failed: %v", err)
	}
	fmt.Println("✓ All migrations reset to zero.")
}

func cmdSeed() {
	db, err := getDB()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Error getting sql.DB: %v", err)
	}
	defer sqlDB.Close()

	fmt.Println("Seeding registered roles and permissions...")
	if err := dbPkg.SeedRolesAndPermissions(db, security.RegisteredPermissions); err != nil {
		log.Fatalf("Seed failed: %v", err)
	}
	fmt.Println("✓ Seed completed.")
}

