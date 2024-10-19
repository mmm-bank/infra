package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

func ExtractPayload(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		parts := strings.Fields(token)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}
		token = parts[1]

		parts = strings.Split(token, ".")
		if len(parts) != 3 {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Failed to decode token", http.StatusUnauthorized)
			return
		}

		user := struct {
			ID string `json:"user_id"`
		}{}
		err = json.Unmarshal(payload, &user)
		if err != nil {
			http.Error(w, "Failed to get user ID", http.StatusUnauthorized)
			return
		}
		id, err := uuid.Parse(user.ID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
