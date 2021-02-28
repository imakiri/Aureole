package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"gouth/jwt"
	"gouth/pwhash"
	"gouth/storage"
	"net/http"
	"strings"
)

func registerHandler(app AppConfig) func(c *gin.Context) {
	return func(c *gin.Context) {
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

		h, err := pwhash.New(app.Hash.AlgName, &app.Hash.RawHashConf)
		if err != nil {
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{"error": err.Error()})
			return
		}

		pwHash, err := h.HashPw(userConfirm)
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
	}
}

func loginHandler(app AppConfig) func(c *gin.Context) {
	return func(c *gin.Context) {
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

		h, err := pwhash.New(app.Hash.AlgName, &app.Hash.RawHashConf)
		if err != nil {
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{"error": err.Error()})
			return
		}

		usersStorage := app.StorageByFeature["users"]
		pw, err := usersStorage.GetUserPassword(*app.Main.UserColl, userUnique)
		if err != nil {
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{"error": err.Error()})
			return
		}

		isMatch, err := h.ComparePw(userConfirm, pw.(string))
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
	}
}

func restorePasswordHandler(app AppConfig) func(c *gin.Context) {
	return func(c *gin.Context) {
		var resetData interface{}

		if err := c.BindJSON(&resetData); err != nil {
			c.AbortWithStatusJSON(
				http.StatusBadRequest,
				gin.H{"error": "invalid json"})
			return
		}

		resetConf := app.Main.AuthN
		userUnique, err := GetJSONPath(resetConf.PasswdBased.UserUnique, resetData)
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

		usersStorage := app.StorageByFeature["users"]
		_, err = usersStorage.GetUserIdByUserUnique(*app.Main.UserColl, userUnique) // lg , err :=
		fmt.Println()
		if err != nil {
			// TODO: inexistence of user > send status 404
			c.AbortWithStatusJSON(
				http.StatusNotFound,
				gin.H{"error": err.Error()})
			return
		} else {
			// TODO: existence in db check > send email & print ID
			// Add field "hide_user_existance_msg" to the config.go/yaml
			// Think about "Password Recovery Exploitation"
			/*
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}
			*/
		}
	}
}
