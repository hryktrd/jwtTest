//go:generate goagen bootstrap -d github.com/hryktrd/jwtTest/design

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/hryktrd/jwtTest/app"
)

func main() {
	// Create service
	service := goa.New("Secure")

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	// JWTキー用追加コード
	pem, err := ioutil.ReadFile("./jwtkey/jwt.key.pub.pkcs8")
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	key, err := jwtgo.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	jwtHandler := func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			return h(ctx, rw, req)
		}
	}
	app.UseJWTMiddleware(service, jwt.New(jwt.NewSimpleResolver([]jwt.Key{key}), jwtHandler, app.NewJWTSecurity()))

	basicAuthHandler := func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			user, pass, ok := req.BasicAuth()
			if !ok || user != "foo" || pass != "bar" {
				errUnauthorized := goa.NewErrorClass("unauthorized", 401)
				return errUnauthorized("missing auth")
			}
			return h(ctx, rw, req)
		}
	}
	app.UseBasicAuthMiddleware(service, basicAuthHandler)

	// Mount "jwt" controller
	c := NewJWTController(service)
	app.MountJWTController(service, c)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}
