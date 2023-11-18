package app

import (
	"context"
	"finance-api/db"
)

func (s *Service) UserTokenByUserIDAndAuthUUID(ctx context.Context, userID int, uuid string) (*db.UserToken, error) {
	return s.db.UserTokenByUserIDAndAuthUUID(ctx, userID, uuid)
}

func (s *Service) DeleteUserTokenByUserIDAndAuthUUID(ctx context.Context, userID int, uuid string) error {
	return s.db.DeleteUserTokenByUserIDAndAuthUUID(ctx, userID, uuid)
}
