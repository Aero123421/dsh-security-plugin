module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.9.1

require (
	golang.org/x/net v0.17.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0
)

replace example.com/old => ../old
