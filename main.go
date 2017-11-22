package main

import (
	"encoding/json"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Other string `json:"other"`
	Admin int `json:"admin"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

// secret is used for token creation. Another option is to use ssl certificates.
var secret = "This0Is1Our2Secret3And4No5One6Elses7This8Is9Not0Your1Secret2This3Is4Our5Secret"
var dbName = "codechallenge.db"
var redirected = false

// loginEndpoint is the REST endpoint for the login function.
// loginEndpoint is called as a POST on the /auth path.
// username and password can be provided as a JSON-formatted string:
//   example: {"Username":"someuser","Password":"someuserpassword"}
// loginEndpoint returns a JSON-formatted token string:
//   example: {"token","somereallybigbizarrestringrepresentingthetoken"}
// This token should be saved in the browser and used for future queries
// in an Authorization header.
func loginEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)
	if checkUser(user.Username) {
		// User exists so attempt login
		if checkPasswd(user.Username, user.Password) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": user.Username,
				"password": user.Password,
			})
			tokenString, error := token.SignedString([]byte(secret))
			if error != nil {
				fmt.Println(error)
			}
			// Check that the token is active meaning the user is already logged in.
			// If so, do not try to insert the token in the token table.
			if (!checkTokenIsActive(tokenString)) {
				// save the token to the token table
				db, _ := sql.Open("sqlite3", dbName)
				defer db.Close()
				statement, _ := db.Prepare("insert into token (token, username, valid) values (?, ?, ?)")
				_, err := statement.Exec(tokenString, user.Username, 1)
				if err != nil {
					json.NewEncoder(w).Encode(Exception{Message: "Database insert error " + err.Error()})
				}
			}
			json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
		} else {
			// Invalid password
			json.NewEncoder(w).Encode(Exception{Message: "Invalid password"})
		}
	} else {
		// User does not exist
		json.NewEncoder(w).Encode(Exception{Message: "Invalid user"})
	}
}

// logoutEndpoint is the REST endpoint for the logout function.
// logoutEndpoint is called as a DELETE on the /auth path.
// An Authorization header containing the active token is required.
// The token will be deleted from the token table on logout.
func logoutEndpoint(w http.ResponseWriter, req *http.Request) {
	authorizationHeader := req.Header.Get("authorization")
	if authorizationHeader != "" {
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) == 2 {
			tokenString := bearerToken[1];
			db, _ := sql.Open("sqlite3", dbName)
			defer db.Close()
			statement, _ := db.Prepare("delete from token where token = ?")
			_, err := statement.Exec(tokenString)
			if err != nil {
				json.NewEncoder(w).Encode(Exception{Message: "Database update error " + err.Error()})
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Logout success"})
			}
		}
	}
}

// signupEndpoint is the REST endpoint for the signup function.
// signupEndpoint is called as a POST on the /user path.
// username, password and other info can be provided as a JSON-formatted string:
//   example: {"Username":"someuser","Password":"someuserpassword", "Other":{email:someuser@someplace.com}"}
// signupEndpoint returns a JSON-formatted token string:
//   example: {"token","somereallybigbizarrestringrepresentingthetoken"}
// This token should be saved in the browser and used for future queries
// in an Authorization header.
func signupEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)
	if !checkUser(user.Username) {
		// Create user
		db, _ := sql.Open("sqlite3", dbName)
		defer db.Close()
		statement, _ := db.Prepare("insert into user (username, password, other, admin) values (?,?,?,?)")
		_, err := statement.Exec(user.Username, encryptPasswd(user.Password), user.Other, 0)
		if err == nil {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": user.Username,
				"password": user.Password,
			})
			tokenString, error := token.SignedString([]byte(secret))
			if error != nil {
				fmt.Println(error)
			}
			// save the token to the token table
			db, _ := sql.Open("sqlite3", dbName)
			defer db.Close()
			statement, _ := db.Prepare("insert into token (token, username, valid) values (?, ?, ?)")
			_, err := statement.Exec(tokenString, user.Username, 1)
			if err != nil {
				json.NewEncoder(w).Encode(Exception{Message: "Database insert error " + err.Error()})
			} else {
				json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
			}
		} else {
			fmt.Println(err)
		}
	} else {
		// User already exists - using "Invalid user" reply so people won't know.
		json.NewEncoder(w).Encode(Exception{Message: "Invalid user"})
	}
}

// rootEndpoint is the REST endpoint for the default web app directory.
// rootEndpoint is called as a GET on the / path.
// An Authorization header containing the active token is required or
// the system will just return a JSON-formatted "Hello World" message.
func rootEndpoint(w http.ResponseWriter, req *http.Request) {
	authorizationHeader := req.Header.Get("authorization")
	if authorizationHeader == "" {
		json.NewEncoder(w).Encode("Hello World")
		return
	} else {
		redirected = true
		getUserEndpoint(w, req)
	}
}

// getUserEndpoint is the REST endpoint for the viewing of user info.
// getUserEndpoint is called as a GET on the /user/{username} path.
// An Authorization header containing the active token is required.
// User info will returned as a JSON-formatted string:
//   example: {"Username":"someuser","Password":"someuserpassword", "Other":{email:someuser@someplace.com}"}
func getUserEndpoint(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	reqUsername := vars["username"]
	authorizationHeader := req.Header.Get("authorization")
	if authorizationHeader != "" {
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) == 2 {
			if !checkTokenIsActive(bearerToken[1]) {
				json.NewEncoder(w).Encode(Exception{Message: "User access violation"})
				return
			}
			token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(secret), nil
			})
			if error != nil {
				json.NewEncoder(w).Encode(Exception{Message: error.Error()})
				return
			}
			if token.Valid {
			 	var user User
				context.Set(req, "decoded", token.Claims)
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					mapstructure.Decode(claims, &user)
					if redirected {
						// if redirected from rootEndpoint, the username comes from the token
						reqUsername = user.Username
						redirected = false
					} else {
						if user.Username != reqUsername {
							// reject requests from all but the owner of the account (until admin users are implemented)
							json.NewEncoder(w).Encode(Exception{Message: "User access violation (2)"})
							return
						}
					}
				}
				var username string
				var other string
				var admin int
				db, _ := sql.Open("sqlite3", dbName)
				defer db.Close()
				err := db.QueryRow("select username, other, admin from user where username = ?", reqUsername).Scan(&username, &other, &admin)
				if err != nil {
					json.NewEncoder(w).Encode(Exception{Message: "Database select error " + err.Error()})
				}
				user.Username = username
				user.Other = other
				user.Admin = admin
				user.Password = "********"
				json.NewEncoder(w).Encode(user)
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
			}
		}
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
	}
}

// updateUserEndpoint is the REST endpoint for updating user info.
// updateUserEndpoint is called as a PUT on the /user/{username} path.
// An Authorization header containing the active token is required.
// At this time, only the "Other" field can be updated with this function:
//   example: {"Other":{email:someuser@someplace.com}"}
func updateUserEndpoint(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	reqUsername := vars["username"]
	authorizationHeader := req.Header.Get("authorization")
	if authorizationHeader != "" {
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) == 2 {
			if !checkTokenIsActive(bearerToken[1]) {
				json.NewEncoder(w).Encode(Exception{Message: "User access violation"})
				return
			}
			token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(secret), nil
			})
			if error != nil {
				json.NewEncoder(w).Encode(Exception{Message: error.Error()})
				return
			}
			if token.Valid {
			 	var user User
				context.Set(req, "decoded", token.Claims)
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					mapstructure.Decode(claims, &user)
					if (user.Username != reqUsername) {
						// reject requests from all but the owner of the account (until admin users are implemented)
						json.NewEncoder(w).Encode(Exception{Message: "User access violation (2)"})
						return
					}
					var reqUser User
					err := json.NewDecoder(req.Body).Decode(&reqUser)
					if err != nil {
						json.NewEncoder(w).Encode(Exception{Message: "Error decoding request body " + err.Error()})
						return
					}
					// Update db with new "other" column
					db, _ := sql.Open("sqlite3", dbName)
					defer db.Close()
					statement, _ := db.Prepare("update user set other = ? where username = ?")
					_, err = statement.Exec(reqUser.Other, reqUsername)
					if err != nil {
						json.NewEncoder(w).Encode(Exception{Message: "Database update error"})
					}
					mapstructure.Decode(claims, &reqUser)
					reqUser.Password = "********"
					json.NewEncoder(w).Encode(reqUser)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Could not decode claims"})
				}
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
			}
		}
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
	}
}

// deleteUserEndpoint is the REST endpoint for deleting user info.
// updateUserEndpoint is called as a DELETE on the /user/{username} path.
// An Authorization header containing the active token is required.
// This function deletes both the active token and the user records in the database.
func deleteUserEndpoint(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	reqUsername := vars["username"]
	authorizationHeader := req.Header.Get("authorization")
	if authorizationHeader != "" {
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) == 2 {
			if !checkTokenIsActive(bearerToken[1]) {
				json.NewEncoder(w).Encode(Exception{Message: "User access violation"})
				return
			}
			token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(secret), nil
			})
			if error != nil {
				json.NewEncoder(w).Encode(Exception{Message: error.Error()})
			}
			if token.Valid {
			 	var user User
				context.Set(req, "decoded", token.Claims)
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					mapstructure.Decode(claims, &user)
					if (user.Username != reqUsername) {
						// reject requests from all but the owner of the account (until admin users are implemented)
						json.NewEncoder(w).Encode(Exception{Message: "User access violation (2)"})
						return
					}
					// Delete user
					db, _ := sql.Open("sqlite3", dbName)
					defer db.Close()
					statement, _ := db.Prepare("delete from token where username = ?")
					_, err := statement.Exec(reqUsername)
					if err != nil {
						json.NewEncoder(w).Encode(Exception{Message: "Database delete error " + err.Error()})
					}
					statement, _ = db.Prepare("delete from user where username = ?")
					_, err = statement.Exec(reqUsername)
					if err != nil {
						json.NewEncoder(w).Encode(Exception{Message: "Database delete error " + err.Error()})
					} else {
						json.NewEncoder(w).Encode(Exception{Message: "User deleted"})
					}
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Could not decode claims"})
				}
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
			}
		}
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
	}
}

// encryptPasswd encrypts the supplied password string using bcrypt encryption.
// Returns the password hash.
func encryptPasswd(passwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

// checkUser checks for the existance of a user.
// Returns a boolean.
func checkUser(username string) bool {
	// Check if user exists in db
	db, err := sql.Open("sqlite3", dbName)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
		return false
	}
	var username2 string
	err2 := db.QueryRow("select username from user where username = ?", username).Scan(&username2)
	switch {
	case err2 == sql.ErrNoRows:
		return false;
	default: 
	    return true;
	}
}

// checkTokenIsActive checks for the existance of an Authorization token.
// Returns a boolean.
func checkTokenIsActive(token string) bool {
	db, err := sql.Open("sqlite3", dbName)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
		return false
	}
	var existingToken string
	err2 := db.QueryRow("select token from token where token = ?", token).Scan(&existingToken)
	switch {
	case err2 == sql.ErrNoRows:
		return false;
	default: 
	    return true;
	}
}

// getPasswd returns the requested user's encrypted password.
func getPasswd(username string) string {
	// Get passwd from db
	db, err := sql.Open("sqlite3", dbName)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	var passwd string
	err2 := db.QueryRow("select password from user where username = ?", username).Scan(&passwd)
	switch {
	case err2 == sql.ErrNoRows:
		return "";
	default: 
	    return passwd;
	}
}

// createUser creates a new user in the database.
func createUser(username string, passwd string, other string, admin int) {
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()
	statement, _ := db.Prepare("insert into users (username, password, other, admin) values (?,?,?,?)")
	_, err := statement.Exec(username, encryptPasswd(passwd), other, admin)
	if err != nil {
		log.Fatal(err)
	}
}

// checkPasswd verifies a supplied password with the one stored in the user database.
func checkPasswd(username string, passwd string) bool {
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()
	var hash string
	err := db.QueryRow("select password from user where username = ?", username).Scan(&hash)
	if err != nil {
		log.Fatal(err)
		return false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(passwd)); err != nil {
		return false
	}
	return true
}

// createDB creates the initial database structure.
func createDB() {
	// Init the db
	// The challengeadmin user is created as the first admin (admin function isn't implemented yet)
	// Password is hard-coded for this exercise
	var username string
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()
	// Check/create user table
	statement, _ := db.Prepare("create table if not exists user (username text primary key, password text, other text, admin int)")
	_, err := statement.Exec()
	if err != nil {
		log.Fatal("Database table creation error " + err.Error())
		return
	}
	err = db.QueryRow(`select username from user where username = "challengeadmin"`).Scan(&username)
	if (err == sql.ErrNoRows) {
		statement, _ = db.Prepare("insert into user (username, password, other, admin) values (?,?,?,?)")
		_, err = statement.Exec("challengeadmin", encryptPasswd("challengepass"), `{"other":{"email":"myemail@myemail.com"}}`, 1)
		if err != nil {
			log.Fatal("Database insert error " + err.Error())
			return
		}
	}
	// Create token table
	statement, _ = db.Prepare("create table if not exists token (token text primary key, username text, valid int)")
	_, err = statement.Exec()
	if err != nil {
		log.Fatal("Database table creation error " + err.Error())
		return
	}
	log.Println("Database created")
}

// main is main.
// It contains some initialization code and the routes for the REST API.
func main() {
	createDB()
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/", rootEndpoint).Methods("GET")
	router.HandleFunc("/auth", loginEndpoint).Methods("POST")
	router.HandleFunc("/auth", logoutEndpoint).Methods("DELETE")
	router.HandleFunc("/user", signupEndpoint).Methods("POST")
	router.HandleFunc("/user/{username}", getUserEndpoint).Methods("GET")
	router.HandleFunc("/user/{username}", updateUserEndpoint).Methods("PUT")
	router.HandleFunc("/user/{username}", deleteUserEndpoint).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":12345", router))
}
