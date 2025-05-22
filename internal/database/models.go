package database

import (
	"context"
	"time"
)

// User represents a user in the system
type User struct {
	ID             string    `db:"id"`
	Username       string    `db:"username"`
	PasswordHash   string    `db:"password_hash"`
	SubscriptionID string    `db:"subscription_id"`
	APIKey         string    `db:"api_key"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}

// Subscription represents a subscription tier
type Subscription struct {
	ID             string    `db:"id"`
	Name           string    `db:"name"`
	RateLimitPolicy string    `db:"rate_limit_policy"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}

// BenthosConfigDefinition represents a Benthos configuration
type BenthosConfigDefinition struct {
	ID             string    `db:"id"`
	SubscriptionID string    `db:"subscription_id"`
	Name           string    `db:"name"`
	ConfigYAML     string    `db:"config_yaml"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}

// DBClient defines the database interface
type DBClient interface {
	// User operations
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error) 
	GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	
	// Subscription operations
	GetSubscriptionByID(ctx context.Context, id string) (*Subscription, error)
	GetSubscriptionByName(ctx context.Context, name string) (*Subscription, error)
	ListSubscriptions(ctx context.Context) ([]*Subscription, error)
	CreateSubscription(ctx context.Context, sub *Subscription) error
	UpdateSubscription(ctx context.Context, sub *Subscription) error
}
	// Benthos Config operations
	GetBenthosConfigByID(ctx context.Context, id string) (*BenthosConfigDefinition, error)
	GetBenthosConfigsBySubscriptionID(ctx context.Context, subID string) ([]*BenthosConfigDefinition, error)
	ListBenthosConfigs(ctx context.Context) ([]*BenthosConfigDefinition, error)
	CreateBenthosConfig(ctx context.Context, config *BenthosConfigDefinition) error
	UpdateBenthosConfig(ctx context.Context, config *BenthosConfigDefinition) error
	DeleteBenthosConfig(ctx context.Context, id string) error
	
	// Transaction support
	BeginTx(ctx context.Context) (Transaction, error)
	Close() error
}

// Transaction interface for database transactions
type Transaction interface {
	Commit() error
	Rollback() error
}
