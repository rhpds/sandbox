package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Sandbox API",
	Long: `Exchange a login token for an access token and save credentials locally.

The server URL and login token can be provided via flags, environment
variables (SANDBOX_API_ROUTE, SANDBOX_LOGIN_TOKEN), or will be read
from the saved config (~/.local/sandbox-cli/config.json).

Examples:
  sandbox-cli login --server https://sandbox-api.example.com --token eyJ...
  sandbox-cli login   # uses saved or env config`,
	RunE: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove saved credentials",
	Long:  `Delete the saved config file (~/.local/sandbox-cli/config.json).`,
	RunE:  runLogout,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	if cfg.Server == "" {
		return fmt.Errorf("server not set; use --server or SANDBOX_API_ROUTE")
	}
	if cfg.LoginToken == "" {
		return fmt.Errorf("login token not set; use --token or SANDBOX_LOGIN_TOKEN")
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Authenticating with %s...\n", cfg.Server)

	loginResp, err := Login(cfg.Server, cfg.LoginToken)
	if err != nil {
		return fmt.Errorf("%w%s", err, connectionErrorHint(err))
	}

	cfg.AccessToken = loginResp.AccessToken
	cfg.AccessExp = loginResp.AccessTokenExp

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Login successful. Access token saved to ~/.local/sandbox-cli/config.json\n")
	if loginResp.AccessTokenExp != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Token expires: %s\n", loginResp.AccessTokenExp.Format("2006-01-02 15:04:05 MST"))
	}
	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "Already logged out (no config file found).")
			return nil
		}
		return fmt.Errorf("removing config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Logged out. Removed %s\n", path)
	return nil
}
