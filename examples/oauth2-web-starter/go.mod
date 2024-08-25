module github.com/midsbie/authagon/examples/oauth2-web-starter

go 1.21

replace github.com/midsbie/authagon => ../../

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/midsbie/authagon v0.0.0-20240421170743-9d5b236b3b3a
)

require (
	cloud.google.com/go v0.67.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	golang.org/x/oauth2 v0.22.0 // indirect
)
