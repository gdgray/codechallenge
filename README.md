Code Challenge App

A REST API for adding, updating, and deleting users. Signup, login, and logout included.

The following routes are implemented:

	router.HandleFunc("/", rootEndpoint).Methods("GET")
	router.HandleFunc("/auth", loginEndpoint).Methods("POST")
	router.HandleFunc("/auth", logoutEndpoint).Methods("DELETE")
	router.HandleFunc("/user", signupEndpoint).Methods("POST")
	router.HandleFunc("/user/{username}", getUserEndpoint).Methods("GET")
	router.HandleFunc("/user/{username}", updateUserEndpoint).Methods("PUT")
	router.HandleFunc("/user/{username}", deleteUserEndpoint).Methods("DELETE")

Login and Signup return an Authorization token that must be placed in an Authorization header for subsequent requests.

Users may only create, view and delete their own accounts.

Signup requests require a JSON-formatted body of the form:

    {"Username":"greg","Password":"greg"}
    {"username":"greg","password":"greg","other":{"email":"greg@greg.com"}}

Update requests require a JSON-formatted body of the form:
    {"other":"{email:greg@greg.com}"}

The "other" field is the only one that allows updating.


Installation

Project dependencies:

go get github.com/gorilla/mux

go get github.com/gorilla/context
go get github.com/mitchellh/mapstructure
go get github.com/dgrijalva/jwt-go
go get github.com/mattn/go-sqlite3
go get -u golang.org/x/crypto/bcrypt
