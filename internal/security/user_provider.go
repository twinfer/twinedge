package security

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Contoso/caddyshack/internal/database"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system.
type User struct {
	ID               string
	Username         string
	PasswordHash     string
	Email            string // New field
	FullName         string // New field
	SubscriptionType string
	APIKey           string
	Roles            []string
}

// UserProvider defines methods for retrieving and authenticating users.
type UserProvider interface {
	GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error)
	GetUserByCredentials(ctx context.Context, username string, password string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error) // New method
}

// dbUserProvider implements UserProvider using a database backend.
type dbUserProvider struct {
	dbClient database.DBClient
	logger   *zap.Logger
}

// NewUserProvider creates a new UserProvider with the given database client and logger.
func NewUserProvider(dbClient database.DBClient, logger *zap.Logger) UserProvider {
	return &dbUserProvider{
		dbClient: dbClient,
		logger:   logger,
	}
}

// GetUserByAPIKey retrieves a user by their API key.
func (p *dbUserProvider) GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error) {
	dbUser, err := p.dbClient.GetUserByAPIKey(ctx, apiKey)
	if err != nil {
		if err == sql.ErrNoRows {
			p.logger.Info("User not found for API key", zap.String("apiKey", apiKey))
			return nil, err // Or a custom not found error
		}
		p.logger.Error("Error getting user by API key", zap.Error(err), zap.String("apiKey", apiKey))
		return nil, err
	}

	// Assuming database.User and security.User have compatible fields
	// and roles need to be fetched/parsed if stored separately or in a specific format.
	// For now, let's assume roles are not directly mapped or handled here.
	// We also need to get SubscriptionType, which is not directly in database.User.
	// This might require another query or a join in the original query.
	// For this implementation, we'll leave SubscriptionType and Roles empty.
	// Assuming dbUser (database.User) will be updated to include Email and FullName.
	// If not, these will be zero-valued (empty strings).
	// Correcting potential copy-paste error from previous context:
	// Initialize secUser, then populate, then fetch subscription.
	secUser := User{
		ID:           dbUser.ID,
		Username:     dbUser.Username,
		PasswordHash: dbUser.PasswordHash, // Keep the hash; User struct might be used elsewhere
		Email:        dbUser.Email,
		FullName:     dbUser.FullName,
		APIKey:       dbUser.APIKey,
		// Roles:            // Needs to be fetched/parsed
	}

	var subscriptionType string
	if dbUser.SubscriptionID != "" {
		subscription, err := p.dbClient.GetSubscriptionByID(ctx, dbUser.SubscriptionID)
		if err != nil {
			if err == sql.ErrNoRows || err.Error() == fmt.Sprintf("subscription not found: %s", dbUser.SubscriptionID) { // Check for specific error from GetSubscriptionByName if it's used, or a generic not found
				p.logger.Warn("Subscription not found for ID", zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "unknown" // Or ""
			} else {
				p.logger.Error("Error getting subscription by ID", zap.Error(err), zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "error" // Or "" to indicate failure to fetch
			}
		} else {
			subscriptionType = subscription.Name
		}
	} else {
		subscriptionType = "none" // Default if no SubscriptionID
	}
	secUser.SubscriptionType = subscriptionType

	return &secUser, nil
}

// GetUserByCredentials retrieves a user by username and password.
func (p *dbUserProvider) GetUserByCredentials(ctx context.Context, username string, password string) (*User, error) {
	dbUser, err := p.dbClient.GetUserByUsername(ctx, username)
	if err != nil {
		if err == sql.ErrNoRows {
			p.logger.Info("User not found for username", zap.String("username", username))
			return nil, err // Or a custom authentication error
		}
		p.logger.Error("Error getting user by username", zap.Error(err), zap.String("username", username))
		return nil, err
	}

	// Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			p.logger.Warn("Invalid password attempt (mismatched hash and password)", zap.String("username", username))
		} else {
			p.logger.Error("Error comparing password hash", zap.Error(err), zap.String("username", username))
		}
		// Return sql.ErrNoRows for authentication failure to avoid username enumeration,
		// consistent with user not found.
		return nil, sql.ErrNoRows
	}

	// Password is correct, proceed to populate the rest of the user details.
	// Correcting potential copy-paste error from previous context:
	// Initialize secUser, then populate, then fetch subscription.
	secUser := User{
		ID:           dbUser.ID,
		Username:     dbUser.Username,
		PasswordHash: dbUser.PasswordHash, // Include the hash
		Email:        dbUser.Email,
		FullName:     dbUser.FullName,
		APIKey:       dbUser.APIKey,
		// Roles:            // Needs to be fetched/parsed
	}

	var subscriptionType string
	if dbUser.SubscriptionID != "" {
		subscription, err := p.dbClient.GetSubscriptionByID(ctx, dbUser.SubscriptionID)
		if err != nil {
			if err == sql.ErrNoRows || err.Error() == fmt.Sprintf("subscription not found: %s", dbUser.SubscriptionID) {
				p.logger.Warn("Subscription not found for ID", zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "unknown"
			} else {
				p.logger.Error("Error getting subscription by ID", zap.Error(err), zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "error"
			}
		} else {
			subscriptionType = subscription.Name
		}
	} else {
		subscriptionType = "none"
	}
	secUser.SubscriptionType = subscriptionType

	return &secUser, nil
}

// GetUserByID retrieves a user by their ID.
func (p *dbUserProvider) GetUserByID(ctx context.Context, userID string) (*User, error) {
	dbUser, err := p.dbClient.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			p.logger.Info("User not found for ID", zap.String("userID", userID))
			return nil, err // Or a custom not found error
		}
		p.logger.Error("Error getting user by ID", zap.Error(err), zap.String("userID", userID))
		return nil, err
	}

	// Similar to GetUserByAPIKey, SubscriptionType and Roles need handling.
	// Assuming dbUser (database.User) will be updated to include Email and FullName.
	// Correcting potential copy-paste error from previous context:
	// Initialize secUser, then populate, then fetch subscription.
	secUser := User{
		ID:           dbUser.ID,
		Username:     dbUser.Username,
		PasswordHash: dbUser.PasswordHash,
		Email:        dbUser.Email,
		FullName:     dbUser.FullName,
		APIKey:       dbUser.APIKey,
		// Roles:            // Needs to be fetched/parsed
	}

	var subscriptionType string
	if dbUser.SubscriptionID != "" {
		subscription, err := p.dbClient.GetSubscriptionByID(ctx, dbUser.SubscriptionID)
		if err != nil {
			if err == sql.ErrNoRows || err.Error() == fmt.Sprintf("subscription not found: %s", dbUser.SubscriptionID) {
				p.logger.Warn("Subscription not found for ID", zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "unknown"
			} else {
				p.logger.Error("Error getting subscription by ID", zap.Error(err), zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "error"
			}
		} else {
			subscriptionType = subscription.Name
		}
	} else {
		subscriptionType = "none"
	}
	secUser.SubscriptionType = subscriptionType

	return &secUser, nil
}

// GetUserByUsername retrieves a user by their username, without password validation.
func (p *dbUserProvider) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	dbUser, err := p.dbClient.GetUserByUsername(ctx, username)
	if err != nil {
		if err == sql.ErrNoRows {
			p.logger.Info("User not found for username", zap.String("username", username))
			return nil, err // Or database.ErrUserNotFound if that's the preferred error type
		}
		p.logger.Error("Error getting user by username", zap.Error(err), zap.String("username", username))
		return nil, err
	}

	// Assuming dbUser (database.User) will be updated to include Email and FullName.
	// Correcting potential copy-paste error from previous context:
	// Initialize secUser, then populate, then fetch subscription.
	secUser := User{
		ID:           dbUser.ID,
		Username:     dbUser.Username,
		PasswordHash: dbUser.PasswordHash, // Still useful to have, though not used for auth here
		Email:        dbUser.Email,
		FullName:     dbUser.FullName,
		APIKey:       dbUser.APIKey,
		// Roles:            // Needs to be fetched/parsed
	}

	var subscriptionType string
	if dbUser.SubscriptionID != "" {
		subscription, err := p.dbClient.GetSubscriptionByID(ctx, dbUser.SubscriptionID)
		if err != nil {
			if err == sql.ErrNoRows || err.Error() == fmt.Sprintf("subscription not found: %s", dbUser.SubscriptionID) {
				p.logger.Warn("Subscription not found for ID", zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "unknown"
			} else {
				p.logger.Error("Error getting subscription by ID", zap.Error(err), zap.String("subscriptionID", dbUser.SubscriptionID), zap.String("userID", dbUser.ID))
				subscriptionType = "error"
			}
		} else {
			subscriptionType = subscription.Name
		}
	} else {
		subscriptionType = "none"
	}
	secUser.SubscriptionType = subscriptionType

	return &secUser, nil
}
