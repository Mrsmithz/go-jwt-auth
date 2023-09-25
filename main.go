package main

import (
	"fmt"
	"go-jwt-auth/src/entity"
	"go-jwt-auth/src/service"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Login struct {
	Email string `json:"email"`
}

func main() {

	authService := service.New()

	r := gin.Default()
	r.POST("/login", func(ctx *gin.Context) {
		var login Login
		if ctx.ShouldBind(&login) != nil {
			ctx.JSON(http.StatusBadRequest, &entity.Message{
				Status: "error",
			})

			return
		}

		token, err := authService.GenerateJwt(login.Email)

		if err != nil {
			ctx.JSON(http.StatusBadRequest, &entity.Message{
				Status: "generate token error",
			})
			panic(err)
		}

		ctx.JSON(http.StatusOK, &entity.Message{
			Status: "success",
			Token:  token,
		})
	})

	r.POST("/verify", func(ctx *gin.Context) {
		token := strings.Split(ctx.Request.Header["Authorization"][0], " ")[1]
		data, err := authService.VerifyJwt(token)

		if err != nil {
			ctx.JSON(http.StatusUnauthorized, &entity.Message{
				Status: "error",
			})

			panic(err)
		}

		fmt.Println(data.Email, data.Exp)

		ctx.JSON(http.StatusOK, &entity.Message{
			Status: "success",
		})

	})

	s := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	s.ListenAndServe()
}
