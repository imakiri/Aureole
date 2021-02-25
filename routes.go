package main

import (
	"github.com/gin-gonic/gin"
	"gouth/jwt"
	"gouth/storage"
	"net/http"
	"strings"
)

// initRouter initializes router and creates routes for each application
func initRouter() *gin.Engine {
	r := gin.Default()
	v := r.Group("v" + conf.APIVersion)

	for _, app := range conf.Apps {
		appR := v.Group(app.PathPrefix)
		{
			appR.POST("/register", func(c *gin.Context) {
				var regData interface{}

				if err := c.BindJSON(&regData); err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "invalid json"})
					return
				}

				var regConfig = app.Main.Register
				mapKeys := regConfig.Fields

				userUnique, err := GetJSONPath(mapKeys["user_unique"], regData)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_unique didn't passed"},
					)
					return
				}
				if userUnique, ok := userUnique.(string); ok {
					if strings.TrimSpace(userUnique) == "" {
						c.AbortWithStatusJSON(
							http.StatusBadRequest,
							gin.H{"error": "user_unique can't be blank"},
						)
						return
					}
				}

				rawUserConfirm, err := GetJSONPath(mapKeys["user_confirm"], regData)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_confirm didn't passed"},
					)
					return
				}
				userConfirm := rawUserConfirm.(string)
				if strings.TrimSpace(userConfirm) == "" {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_confirm can't be blank"},
					)
					return
				}

				// TODO: add a user existence check

				pwHash, err := app.Hash.HashPw(userConfirm)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusInternalServerError,
						gin.H{"error": err.Error()})
					return
				}

				usersStorage := app.StorageByFeature["users"]
				res, err := usersStorage.InsertUser(
					*app.Main.UserColl,
					*storage.NewInsertUserData(userUnique, pwHash),
				)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusInternalServerError,
						gin.H{"error": err.Error()})
					return
				}

				if regConfig.LoginAfter {
					token := jwt.IssueToken()

					c.JSON(http.StatusOK, gin.H{"token": token})
					return
				}

				c.JSON(http.StatusOK, gin.H{"id": res})
			})

			appR.POST("/login", func(c *gin.Context) {
				var authData interface{}

				if err := c.BindJSON(&authData); err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "invalid json"})
					return
				}

				authConf := app.Main.AuthN

				userUnique, err := GetJSONPath(authConf.PasswdBased.UserUnique, authData)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_unique didn't passed"},
					)
					return
				}
				if userUnique, ok := userUnique.(string); ok {
					if strings.TrimSpace(userUnique) == "" {
						c.AbortWithStatusJSON(
							http.StatusBadRequest,
							gin.H{"error": "user_unique can't be blank"},
						)
						return
					}
				}

				rawUserConfirm, err := GetJSONPath(authConf.PasswdBased.UserConfirm, authData)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_confirm didn't passed"},
					)
					return
				}
				userConfirm := rawUserConfirm.(string)
				if strings.TrimSpace(userConfirm) == "" {
					c.AbortWithStatusJSON(
						http.StatusBadRequest,
						gin.H{"error": "user_confirm can't be blank"},
					)
					return
				}

				// TODO: add a user existence check

				usersStorage := app.StorageByFeature["users"]
				pw, err := usersStorage.GetUserPassword(*app.Main.UserColl, userUnique)
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusInternalServerError,
						gin.H{"error": err.Error()})
					return
				}

				isMatch, err := app.Hash.ComparePw(userConfirm, pw.(string))
				if err != nil {
					c.AbortWithStatusJSON(
						http.StatusInternalServerError,
						gin.H{"error": err.Error()})
					return
				}

				if isMatch {
					token := jwt.IssueToken()
					c.JSON(http.StatusOK, gin.H{"token": token})
				} else {
					c.AbortWithStatusJSON(
						http.StatusUnauthorized,
						gin.H{"error": "invalid data"})
					return
				}
			})
		}
	}

	return r
}
