package app

import (
	"context"
	"finance-api/db"
	"time"
)

func (s *Service) UserByID(ctx context.Context, id int) (*db.User, error) {
	return s.db.UserByID(ctx, id)
}

func (s *Service) UserByEmailAddress(ctx context.Context, emailAddress string) (*db.User, error) {
	return s.db.UserByEmailAddress(ctx, emailAddress)
}

func (s *Service) SaveUser(ctx context.Context, user *db.User) (int, error) {
	state := 1
	now := time.Now()

	if user.UserID == 0 {
		user.State = &state
		user.CreatedDate = &now
	}

	user.ModifiedDate = &now

	return s.db.SaveUser(ctx, user)
}
