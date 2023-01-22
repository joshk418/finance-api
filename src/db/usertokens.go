package db

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/joshk418/golactus"
)

type UserToken struct {
	UserTokenID int    `json:"userTokenID"`
	UserID      int    `json:"userID"`
	AuthUUID    string `json:"authUUID"`
	Type        string `json:"type"`
}

const (
	RefreshType     = "refresh"
	AccessTokenType = "access"
)

func (s *Service) UserTokenByUserIDAndAuthUUID(ctx context.Context, userID int, uuid string) (*UserToken, error) {
	row := s.db.QueryRowContext(ctx, "select "+
		"user_token_id, "+
		"user_id, "+
		"auth_uuid, "+
		"type "+
		"from user_tokens "+
		"where user_id = $1 and auth_uuid = $2",
		userID,
		uuid,
	)

	userToken := new(UserToken)
	err := row.Scan(
		&userToken.UserTokenID,
		&userToken.UserID,
		&userToken.AuthUUID,
		&userToken.Type,
	)
	if err != nil {
		if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			return nil, nil
		}

		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}

	return userToken, nil
}

func (s *Service) UserTokensByUserID(ctx context.Context, userID int) ([]*UserToken, error) {
	rows, err := s.db.QueryContext(ctx, "select "+
		"user_token_id, "+
		"user_id, "+
		"auth_uuid, "+
		"type "+
		"from user_tokens "+
		"where user_id = $1 and auth_uuid = $2",
		userID,
	)
	if err != nil {
		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}
	defer rows.Close()

	var userTokens []*UserToken
	for rows.Next() {
		userToken := new(UserToken)
		err := rows.Scan(
			&userToken.UserTokenID,
			&userToken.UserID,
			&userToken.AuthUUID,
			&userToken.Type,
		)
		if err != nil {
			if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
				return nil, nil
			}

			return nil, golactus.NewError(http.StatusInternalServerError, err)
		}
	}

	return userTokens, nil
}

func (s *Service) DeleteUserTokensByUserID(ctx context.Context, userID int) error {
	if _, err := s.db.ExecContext(ctx, "delete from user_tokens where user_id = $1", userID); err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}

func (s *Service) DeleteUserTokenByUserIDAndAuthUUID(ctx context.Context, userID int, uuid string) error {
	if _, err := s.db.ExecContext(ctx, "delete from user_tokens where user_id = $1 and auth_uuid = $2", userID, uuid); err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}

func (s *Service) SaveUserToken(ctx context.Context, userToken *UserToken) (int, error) {
	if userToken.UserTokenID > 0 {
		return userToken.UserTokenID, s.updateUserToken(ctx, userToken)
	}

	return s.insertUserToken(ctx, userToken)
}

func (s *Service) insertUserToken(ctx context.Context, userToken *UserToken) (int, error) {
	row := s.db.QueryRowContext(ctx, "insert into user_tokens ("+
		"user_id, "+
		"auth_uuid, "+
		"type "+
		") values ($1, $2, $3)"+
		"returning user_token_id",
		userToken.UserID,
		userToken.AuthUUID,
		userToken.Type,
	)

	var userTokenID int
	if err := row.Scan(&userTokenID); err != nil {
		return 0, golactus.NewError(http.StatusInternalServerError, err)
	}

	return userTokenID, nil
}

func (s *Service) updateUserToken(ctx context.Context, userToken *UserToken) error {
	_, err := s.db.ExecContext(ctx, "update user_tokens set "+
		"auth_uuid = $1, "+
		"where user_token_id = $2",
		userToken.AuthUUID,
		userToken.UserTokenID,
	)
	if err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}
