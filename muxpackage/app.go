package main

import (
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

// Define our struct
type authenticationMiddleware struct {
	tokenUsers map[string]string
}

func (amw *authenticationMiddleware) Populate() {
	amw.tokenUsers["00000000"] = "user0"
	amw.tokenUsers["aaaaaaaa"] = "userA"
	amw.tokenUsers["05f717e5"] = "randomUser"
	amw.tokenUsers["deadbeef"] = "user0"
}

func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")
		if user, found := amw.tokenUsers[token]; found {
			log.Panicf("Authenticated user %s\n", user)
			//传递这个请求到下一个中间件或者是最后的handler
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

	})

}
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	amw := authenticationMiddleware{}
	amw.Populate()
	r.Use(amw.Middleware)

}
