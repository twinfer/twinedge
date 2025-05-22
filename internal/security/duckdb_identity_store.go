package security

import (
	"context"
	"fmt"

	"github.com/Contoso/caddyshack/internal/database" // Assuming this is where db models are for mapping if needed
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

// DuckDBIdentityStoreAdapter adapts UserProvider to ids.IdentityStore.
type DuckDBIdentityStoreAdapter struct {
	UserProvider // Embed our existing UserProvider interface
	logger       *zap.Logger
	name         string
	realm        string
}

// NewDuckDBIdentityStoreAdapter creates a new DuckDBIdentityStoreAdapter.
func NewDuckDBIdentityStoreAdapter(name, realm string, provider UserProvider, logger *zap.Logger) *DuckDBIdentityStoreAdapter {
	return &DuckDBIdentityStoreAdapter{
		UserProvider: provider,
		logger:       logger,
		name:         name,
		realm:        realm,
	}
}

// GetName returns the name of the identity store.
func (d *DuckDBIdentityStoreAdapter) GetName() string {
	return d.name
}

// GetRealm returns the realm of the identity store.
func (d *DuckDBIdentityStoreAdapter) GetRealm() string {
	return d.realm
}

// GetKind returns the kind of the identity store.
func (d *DuckDBIdentityStoreAdapter) GetKind() string {
	return "duckdb_custom_store"
}

// GetConfig returns the configuration of the identity store.
func (d *DuckDBIdentityStoreAdapter) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"name":  d.name,
		"realm": d.realm,
		"kind":  d.GetKind(),
	}
}

// Configure configures the identity store.
func (d *DuckDBIdentityStoreAdapter) Configure() error {
	d.logger.Info("DuckDBIdentityStoreAdapter is pre-configured via constructor")
	return nil
}

// Configured checks if the identity store is configured.
func (d *DuckDBIdentityStoreAdapter) Configured() bool {
	return true // Assuming configuration happens at instantiation
}

// GetLoginIcon returns the login icon for the identity store.
func (d *DuckDBIdentityStoreAdapter) GetLoginIcon() *icons.LoginIcon {
	return &icons.LoginIcon{
		Enabled:    true,
		ClassNames: "las la-database", // Example icon class
		ColorName:  "blue",
		Message:    fmt.Sprintf("Login with %s", d.name),
	}
}

// Request handles various operations for the identity store.
func (d *DuckDBIdentityStoreAdapter) Request(opType operator.Type, r *requests.Request) error {
	d.logger.Debug("DuckDBIdentityStoreAdapter received request",
		zap.String("op_type", opType.String()),
		zap.String("username", r.Username),
		zap.String("realm", r.Realm),
		zap.String("token_name", r.TokenName),
	)

	if r.Realm != "" && r.Realm != d.realm {
		d.logger.Warn("Realm mismatch", zap.String("request_realm", r.Realm), zap.String("store_realm", d.realm))
		return errors.ErrRealmMismatch.WithArgs(r.Realm, d.realm)
	}

	switch opType {
	case operator.FetchUser:
		// FetchUser typically gets user details without authentication (e.g. for profile display)
		// If password is in r.Password, it might be an implicit authentication attempt or misconfiguration.
		// For now, let's assume GetUserByCredentials handles username lookup if password is empty,
		// or we'd need a GetUserByUsername method on UserProvider.
		// Given the current UserProvider, GetUserByCredentials is the closest fit.
		// If r.Password is empty, our current GetUserByCredentials will fail the password check.
		// This might need adjustment in UserProvider or here.
		// For strict FetchUser (no password check), we'd ideally call something like GetUserByUsername.
		// Let's proceed assuming GetUserByCredentials is the intended call,
		// and it's up to the caller to provide credentials or not.
		// If no password in request, it will likely fail unless UserProvider handles empty password.

		// Let's assume for FetchUser, we are trying to get user by username if available,
		// or by ID if that's what's in r.User.ID (though r.User is usually for output).
		// The problem description implies r.Username is the input for FetchUser.
		// Our UserProvider does not have GetUserByUsername without password.
		// Let's use GetUserByID if r.ID is provided, otherwise this case is problematic
		// without a password.
		// For now, let's assume FetchUser means "fetch by username if password is also given for some reason"
		// or "fetch by ID". Caddy-security might use FetchUser with an ID after an initial auth.

		var appUser *User // Our security.User
		var err error

		if r.Username != "" {
			// FetchUser should primarily use username if available, without password.
			d.logger.Debug("FetchUser: Attempting to get user by username", zap.String("username", r.Username))
			appUser, err = d.UserProvider.GetUserByUsername(r.Context, r.Username)
		} else if r.User != nil && r.User.GetID() != "" {
			// Fallback to UserID if username is not provided in the request
			d.logger.Debug("FetchUser: Attempting to get user by ID", zap.String("userID", r.User.GetID()))
			appUser, err = d.UserProvider.GetUserByID(r.Context, r.User.GetID())
		} else {
			d.logger.Error("FetchUser called without Username or UserID", zap.Any("request", r))
			return errors.ErrFetchUserFailed.WithMsg("Username or UserID required for FetchUser")
		}

		if err != nil {
			// Assuming GetUserByUsername and GetUserByID return sql.ErrNoRows or a compatible error
			// that can be checked by err.Error() == "sql: no rows in result set"
			// or by a specific error type like database.ErrUserNotFound if defined and used.
			if err.Error() == "sql: no rows in result set" { // TODO: Standardize error checking, e.g. errors.Is(err, sql.ErrNoRows) or errors.Is(err, database.ErrUserNotFound)
				d.logger.Warn("User not found during FetchUser operation",
					zap.String("username_attempted", r.Username),
					zap.String("userid_attempted", func() string {
						if r.User != nil {
							return r.User.GetID()
						}
						return ""
					}()),
					zap.Error(err))
				return errors.ErrUserNotFound
			}
			d.logger.Error("Error fetching user during FetchUser operation", zap.Error(err))
			return errors.ErrFetchUserFailed.Wrap(err)
		}

		claims := &user.Claims{
			Subject: appUser.ID,
			Email:   appUser.Email,    // Use new Email field
			Name:    appUser.FullName, // Use new FullName field
			Roles:   appUser.Roles,
			Origin:  d.GetRealm(),
			Issuer:  d.GetName(),
		}
		// Add custom claims like SubscriptionType
		claims.SetClaim("sub_type", appUser.SubscriptionType)

		authUser := user.NewUser()
		authUser.SetID(appUser.ID)
		authUser.SetClaims(claims)
		r.User = authUser
		return nil

	case operator.AuthenticateUser:
		if r.Username == "" || r.Password == "" {
			return errors.ErrAuthorizationFailed.WithMsg("username and password required")
		}
		appUser, err := d.UserProvider.GetUserByCredentials(r.Context, r.Username, r.Password)
		if err != nil {
			// Check for sql.ErrNoRows which our GetUserByCredentials returns for not found or bad password
			if err.Error() == database.ErrUserNotFound.ErrorString() || err.Error() == "sql: no rows in result set" {
				d.logger.Warn("Authentication failed (user not found or invalid password)", zap.String("username", r.Username))
				return errors.ErrAuthenticationFailed
			}
			d.logger.Error("Error during authentication", zap.Error(err), zap.String("username", r.Username))
			return errors.ErrAuthenticationFailed.Wrap(err)
		}

		claims := &user.Claims{
			Subject: appUser.ID,
			Email:   appUser.Email,    // Use new Email field
			Name:    appUser.FullName, // Use new FullName field
			Roles:   appUser.Roles,
			Origin:  d.GetRealm(),
			Issuer:  d.GetName(),
		}
		claims.SetClaim("sub_type", appUser.SubscriptionType)
		// Mark that user was authenticated by password
		claims.SetClaim("authenticated_by", "password")


		authUser := user.NewUser()
		authUser.SetID(appUser.ID)
		authUser.SetClaims(claims)
		r.User = authUser
		return nil

	case operator.IdentifyUserToken: // Handling API Key
		if r.TokenName != "api_key" && r.TokenName != "apikey" { // common variations
			d.logger.Debug("Token name not 'api_key', skipping API key auth", zap.String("token_name", r.TokenName))
			return errors.ErrOperatorNotImplemented.WithArgs(opType.String() + " for token_name " + r.TokenName)
		}
		if r.Token == "" {
			return errors.ErrAuthorizationFailed.WithMsg("api key token required")
		}

		appUser, err := d.UserProvider.GetUserByAPIKey(r.Context, r.Token)
		if err != nil {
			if err.Error() == database.ErrUserNotFound.ErrorString() || err.Error() == "sql: no rows in result set" {
				d.logger.Warn("API key authentication failed (key not found or invalid)", zap.String("token", r.Token[:min(10, len(r.Token))]+"...")) // Log a snippet
				return errors.ErrAPIKeyInvalid
			}
			d.logger.Error("Error during API key authentication", zap.Error(err))
			return errors.ErrAPIKeyInvalid.Wrap(err)
		}

		claims := &user.Claims{
			Subject: appUser.ID,
			Email:   appUser.Email,    // Use new Email field
			Name:    appUser.FullName, // Use new FullName field
			Roles:   appUser.Roles,
			Origin:  d.GetRealm(),
			Issuer:  d.GetName(),
		}
		claims.SetClaim("sub_type", appUser.SubscriptionType)
		claims.SetClaim("authenticated_by", "api_key")


		authUser := user.NewUser()
		authUser.SetID(appUser.ID)
		authUser.SetClaims(claims)
		r.User = authUser
		return nil

	default:
		d.logger.Warn("Operator not implemented", zap.String("op_type", opType.String()))
		return errors.ErrOperatorNotImplemented.WithArgs(opType.String())
	}
}

// Helper for logging API key snippet safely
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// Ensure DuckDBIdentityStoreAdapter implements IdentityStore
var _ ids.IdentityStore = (*DuckDBIdentityStoreAdapter)(nil)
var _ ids.UserIdentityTransformer = (*DuckDBIdentityStoreAdapter)(nil) // Placeholder if we need to implement TransformUser

// TransformUser is part of UserIdentityTransformer. If we need to transform claims
// after they are loaded by another store, this can be used.
// For now, it's a placeholder.
func (d *DuckDBIdentityStoreAdapter) TransformUser(ctx context.Context, r *requests.Request) error {
    if r.User == nil {
        return errors.ErrInternalServerError.WithMsg("user object is nil during transformation")
    }
    // Example: Add a default role if none exist, or modify existing claims.
    // claims := r.User.GetClaims()
    // if len(claims.Roles) == 0 {
    //    claims.Roles = append(claims.Roles, "default_user_role")
    // }
    // r.User.SetClaims(claims)
    d.logger.Debug("TransformUser called, no transformation applied by default", zap.String("user_id", r.User.GetID()))
    return nil
}
