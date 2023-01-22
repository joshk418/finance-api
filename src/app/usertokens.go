package app

import (
	"context"
	"finance-api/src/db"
)

func (s *Service) UserTokenByUserIDAndAuthUUID(ctx context.Context, userID int, uuid string) (*db.UserToken, error) {
	return s.db.UserTokenByUserIDAndAuthUUID(ctx, userID, uuid)
}
