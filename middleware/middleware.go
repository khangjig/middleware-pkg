package middleware

import (
	"github.com/khangjig/middleware-pkg/model"
	"github.com/khangjig/middleware-pkg/token"
	"github.com/labstack/echo/v4"
	"net/http"
)

func SetClaim(secretKey string, allowedRoutes []model.AllowedRoute) func(next echo.HandlerFunc) echo.HandlerFunc {
	handlerFunc := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Header.Get("Authorization") == "" {
				checkRoute := model.AllowedRoute{
					Method: c.Request().Method,
					Path:   c.Path(),
				}

				if isAllowedRoute(allowedRoutes, checkRoute) {
					claim := &model.DataClaims{}
					c.Set(model.DataClaim, claim)

					return next(c)
				}
			}

			claim, err := token.GetClaim(c, secretKey)
			if err != nil || (claim == nil || claim.UserID == 0) {
				return Response(c, model.DataResponse{
					Status:  http.StatusUnauthorized,
					Message: http.StatusText(http.StatusUnauthorized),
				})
			} else {
				c.Set(model.DataClaim, claim)

				return next(c)
			}
		}
	}
	return handlerFunc
}

func isAllowedRoute(listRoutes []model.AllowedRoute, checkRoute model.AllowedRoute) bool {

	for _, route := range listRoutes {
		if route.Method == checkRoute.Method && route.Path == checkRoute.Path {
			return true
		}
	}

	return false
}

func Response(c echo.Context, responseError model.DataResponse) error {
	return c.JSON(responseError.Status, model.DataResponse{
		Status:  responseError.Status,
		Message: responseError.Message,
	})
}
