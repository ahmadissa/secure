package Secure

import (
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
)

var isSafe = regexp.MustCompile(`^[a-zA-Z0-9 /:._-]+$`).MatchString

func validateVars(vars map[string]string) bool {
	for _, v := range vars {
		if !isSafe(v) {
			return false
		}
	}
	return true
}

// Secure
func Secure(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validateVars(mux.Vars(r)) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Results": false,"Data": "Invalid URL"}`))
			return
		}

		// Add X-Content-Type-Options header
		w.Header().Add("X-Content-Type-Options", "nosniff")
		// Prevent page from being displayed in an iframe
		w.Header().Add("X-Frame-Options", "sameorigin")
		// Prevent browser from caching responds
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1.
		w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0.
		w.Header().Set("Expires", "0")                                         // Proxies.
		//Enforce Strict Transport Security Policy
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		//X-XSS-Protection Header
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	}
}
