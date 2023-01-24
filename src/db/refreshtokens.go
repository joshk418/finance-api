package db

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/joshk418/golactus"
)

type RefreshToken struct {
	RefreshTokenID int        `json:"refreshTokenID"`
	Token          string     `json:"token"`
	UserID         int        `json:"userID"`
	CreatedDate    time.Time  `json:"createdDate"`
	ModifiedDate   *time.Time `json:"modifiedDate"`
}

func (s *Service) RefreshTokenByID(ctx context.Context, refreshTokenID int) (*RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, "select "+
		"refresh_token_id, "+
		"token, "+
		"user_id "+
		"from refresh_tokens "+
		"where refresh_token_id = $1",
		refreshTokenID,
	)

	token := new(RefreshToken)
	err := row.Scan(
		&token.RefreshTokenID,
		&token.Token,
		&token.UserID,
	)
	if err != nil {
		if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			return nil, nil
		}

		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}

	return token, nil
}

func (s *Service) DeleteRefreshTokensByUserID(ctx context.Context, userID int) error {
	if _, err := s.db.ExecContext(ctx, "delete from refresh_tokens where user_id = $1", userID); err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}

func (s *Service) DeleteRefreshTokenByID(ctx context.Context, userID int, tokenID int) error {
	if _, err := s.db.ExecContext(ctx, "delete from refresh_tokens where refresh_token_id = $1", userID, tokenID); err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}

func (s *Service) SaveRefreshToken(ctx context.Context, refreshToken *RefreshToken) (int, error) {
	if refreshToken.RefreshTokenID > 0 {
		return refreshToken.RefreshTokenID, s.updateRefreshToken(ctx, refreshToken)
	}

	return s.insertRefreshToken(ctx, refreshToken)
}

func (s *Service) insertRefreshToken(ctx context.Context, refreshToken *RefreshToken) (int, error) {
	row := s.db.QueryRowContext(ctx, "insert into refresh_tokens ("+
		"token, "+
		"user_id, "+
		"created_date "+
		") values ($1, $2, $3)"+
		"returning refresh_token_id",
		refreshToken.Token,
		refreshToken.UserID,
		time.Now(),
	)

	var tokenID int
	if err := row.Scan(&tokenID); err != nil {
		return 0, golactus.NewError(http.StatusInternalServerError, err)
	}

	return tokenID, nil
}

func (s *Service) updateRefreshToken(ctx context.Context, refreshToken *RefreshToken) error {
	_, err := s.db.ExecContext(ctx, "update refresh_tokens set "+
		"token = $1, "+
		"modified_date = $2 "+
		"where user_token_id = $2",
		refreshToken.Token,
		time.Now(),
	)
	if err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}
