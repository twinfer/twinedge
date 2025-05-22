package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/config"
	"github.com/twinfer/edgetwin/internal/database"
	"github.com/twinfer/edgetwin/internal/service"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "edgetwin-cli",
	Short: "Edgetwin CLI for administration",
	Long:  "Command line interface for managing Edgetwin edge gateway",
}

var configPath string

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "config file path")
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(configCmd)
}

// User management commands
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management commands",
}

var createUserCmd = &cobra.Command{
	Use:   "create [username] [password] [subscription]",
	Short: "Create a new user",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		svc := initService()
		user, err := svc.CreateUser(cmd.Context(), args[0], args[1], args[2])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User created: %s (API Key: %s)\n", user.Username, user.APIKey)
	},
}
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
}

func init() {
	userCmd.AddCommand(createUserCmd)
	configCmd.AddCommand(listConfigsCmd)
}

var listConfigsCmd = &cobra.Command{
	Use:   "list",
	Short: "List Benthos configurations",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Configuration management not implemented yet")
	},
}

func initService() service.ServiceManager {
	logger := zap.NewNop()

	configManager, _ := config.NewConfigManager(logger)
	configManager.Load(configPath)
	cfg := configManager.GetConfig()

	dbClient, _ := database.NewDuckDBClient(cfg.Database.Path)

	return service.NewManager(dbClient, nil, logger)
}
