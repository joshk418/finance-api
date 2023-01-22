package db

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/joshk418/golactus"
)

type User struct {
	UserID       int    `json:"userID"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	EmailAddress string `json:"emailAddress"`
	Password     string `json:"password,omitempty"`
	CommonValues
}

func (s *Service) UserByID(ctx context.Context, id int) (*User, error) {
	row := s.db.QueryRowContext(ctx, "select "+
		"user_id, "+
		"first_name, "+
		"last_name, "+
		"email_address, "+
		"created_date, "+
		"modified_date, "+
		"deactivated_date, "+
		"state "+
		"from users where user_id = $1 and state = 1",
		id,
	)

	user := new(User)
	err := row.Scan(
		&user.UserID,
		&user.FirstName,
		&user.LastName,
		&user.EmailAddress,
		&user.CreatedDate,
		&user.ModifiedDate,
		&user.DeactivatedDate,
		&user.State,
	)
	if err != nil {
		if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			return nil, nil
		}

		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}

	return user, nil
}

func (s *Service) UserByEmailAddress(ctx context.Context, emailAddress string) (*User, error) {
	row := s.db.QueryRowContext(ctx, "select "+
		"user_id, "+
		"first_name, "+
		"last_name, "+
		"email_address, "+
		"created_date, "+
		"modified_date, "+
		"deactivated_date, "+
		"state "+
		"from users where lower(email_address) = $1 and state = 1",
		strings.ToLower(emailAddress),
	)

	user := new(User)
	err := row.Scan(
		&user.UserID,
		&user.FirstName,
		&user.LastName,
		&user.EmailAddress,
		&user.CreatedDate,
		&user.ModifiedDate,
		&user.DeactivatedDate,
		&user.State,
	)
	if err != nil {
		if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			return nil, nil
		}

		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}

	return user, nil
}

func (s *Service) UserPasswordHashByEmailAddress(ctx context.Context, emailAddress string) (string, error) {
	row := s.db.QueryRowContext(ctx, "select "+
		"password "+
		"from users where lower(email_address) = $1 and state = 1",
		strings.ToLower(emailAddress),
	)

	var password string
	if err := row.Scan(&password); err != nil {
		if strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			return "", nil
		}

		return "", golactus.NewError(http.StatusInternalServerError, err)
	}

	return password, nil
}

func (s *Service) SaveUser(ctx context.Context, user *User) (int, error) {
	if user.UserID > 0 {
		return user.UserID, s.updateUser(ctx, user)
	}

	return s.insertUser(ctx, user)
}

func (s *Service) insertUser(ctx context.Context, user *User) (int, error) {
	row := s.db.QueryRowContext(ctx, "insert into users ("+
		"first_name, "+
		"last_name, "+
		"email_address, "+
		"password, "+
		"created_date, "+
		"state "+
		") values ($1, $2, $3, $4, $5, $6)"+
		"returning user_id",
		user.FirstName,
		user.LastName,
		user.EmailAddress,
		user.Password,
		user.CreatedDate,
		user.State,
	)

	var userID int
	if err := row.Scan(&userID); err != nil {
		return 0, golactus.NewError(http.StatusInternalServerError, err)
	}

	return userID, nil
}

func (s *Service) updateUser(ctx context.Context, user *User) error {
	_, err := s.db.ExecContext(ctx, "update users set "+
		"first_name = $1, "+
		"last_name = $2, "+
		"email_address = $3, "+
		"modified_date = $4, "+
		"deactivated_date = $5, "+
		"state = $6 "+
		"where user_id = $7",
		user.FirstName,
		user.LastName,
		user.EmailAddress,
		user.Password,
		user.ModifiedDate,
		user.DeactivatedDate,
		user.State,
		user.UserID,
	)
	if err != nil {
		return golactus.NewError(http.StatusInternalServerError, err)
	}

	return nil
}
