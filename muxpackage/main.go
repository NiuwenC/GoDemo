package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	return
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	//r.HandleFunc("/products",handler).Methods("POST")
	//r.HandleFunc("/articles",handler).Methods("GET")
	//r.HandleFunc("/articles/{id}",handler).Methods("GET","PUT")
	//r.HandleFunc("/authors",handler).Queries("surname","{surname}")
	//
	r.Use(loggingMiddleware)
	err := r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetHostTemplate()
		if err == nil {
			fmt.Println("ROUTE: ", pathTemplate)
		}

		pathRegex, err := route.GetPathRegexp()
		if err == nil {
			fmt.Println("Path Regexp: ", pathRegex)
		}

		fmt.Println()
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}
	http.Handle("/", r)
}

//type MiddlewareFunc func(http.Handler) http.Handler
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Println(r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}
