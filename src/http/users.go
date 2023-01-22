package http

import (
	"net/http"
	"strconv"

	"github.com/joshk418/golactus"
)

func (s *Service) UserByID(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	userIDVar := golactus.GetVars(r)["userID"]
	if userIDVar == "" {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "UserID cannot be empty")
	}

	userIDParam, err := strconv.Atoi(userIDVar)
	if err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, err)
	}

	return s.app.UserByID(ctx, userIDParam)
}
