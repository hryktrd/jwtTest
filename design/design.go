package design

import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
)

var _ = API("Secure", func() {
	Title("Secure API")
	Description("Secure API use JWT")
	BasePath("/api")
	Scheme("http")
	Host("localhost:8080")
})

var BasicAuth = BasicAuthSecurity("BasicAuth", func() {
	Description("Use client ID and client secret to authenticate")
})

var JWT = JWTSecurity("jwt", func() {
	Header("Authorization")
	Scope("api:access", "API access")
})

var _ = Resource("jwt", func() { // Resources group related API endpoints
	DefaultMedia(SuccessMedia) // services.
	Security(JWT, func() {
		Scope("api:access")
	})

	Action("signin", func() { // Actions define a single API endpoint together
		Description("Get JWT Token") // with its path, parameters (both path
		Security(BasicAuth)
		Routing(GET("/jwt/signin")) // parameters and querystring values) and payload
		Response(NoContent, func() {
			Headers(func() {
				Header("Authorizatiton", String, "Generated JWT")
			})
		})
		Response(Unauthorized) // of HTTP responses.
	})

	Action("secure", func() {
		Routing(GET("/jwt"))
		Response(OK)
		Response(Unauthorized)
	})
})

var SuccessMedia = MediaType("application/vnd.goa.jwt.test.success", func() {
	Description("A station of mine")
	Attributes(func() { // Attributes define the media type shape.
		Attribute("ok", Boolean, "Always true")
		Required("ok")
	})
	View("default", func() { // View defines a rendering of the media type.
		Attribute("ok") // Media types may have multiple views and must
	})
})
