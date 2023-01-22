package db

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/joshk418/golactus"
)

type Service struct {
	db *sql.DB
}

type CommonValues struct {
	CreatedDate     *time.Time `json:"createdDate"`
	ModifiedDate    *time.Time `json:"modifiedDate"`
	DeactivatedDate *time.Time `json:"deactivatedDate"`
	State           *int       `json:"state"`
}

func New(connection string) (*Service, error) {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return nil, golactus.NewError(http.StatusInternalServerError, err)
	}

	return &Service{db: db}, nil
}
