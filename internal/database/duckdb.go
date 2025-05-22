// GetSubscriptionByName retrieves a subscription by name
func (c *duckDBClient) GetSubscriptionByName(ctx context.Context, name string) (*Subscription, error) {
	var sub Subscription
	err := c.db.QueryRowContext(ctx, `
		SELECT id, name, rate_limit_policy, created_at, updated_at
		FROM subscriptions WHERE name = ?
	`, name).Scan(
		&sub.ID, &sub.Name, &sub.RateLimitPolicy, &sub.CreatedAt, &sub.UpdatedAt,
	)
	
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("subscription not found: %s", name)
		}
		return nil, err
	}
	
	return &sub, nil
}
