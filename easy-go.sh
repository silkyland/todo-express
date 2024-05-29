#!/bin/bash

# Function to print messages
print_message() {
    echo "-------------------------------------"
    echo $1
    echo "-------------------------------------"
}

# Print starting message
print_message "Starting setup of JWT-based TODO Go application with SQLite"

# Update package list and install Go if not installed
if ! command -v go &> /dev/null
then
    print_message "Go is not installed. Installing Go..."
    wget https://dl.google.com/go/go1.16.4.linux-amd64.tar.gz
    tar -xvf go1.16.4.linux-amd64.tar.gz
    mv go /usr/local
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
else
    print_message "Go is already installed"
fi

# Create a Go project directory
mkdir -p $HOME/go/src/todo-app
cd $HOME/go/src/todo-app

# Initialize the Go module
print_message "Initializing the Go module"
go mod init todo-app

# Install dependencies
print_message "Installing dependencies"
go get -u github.com/gin-gonic/gin
go get -u github.com/jinzhu/gorm
go get -u github.com/jinzhu/gorm/dialects/sqlite
go get -u github.com/dgrijalva/jwt-go
go get -u golang.org/x/crypto/bcrypt

# Create necessary folders and files
print_message "Creating necessary folders and files"
mkdir -p models controllers
touch main.go models/models.go controllers/auth.go controllers/todo.go

# Add main.go
print_message "Adding main.go"
cat <<EOT > main.go
package main

import (
	"github.com/gin-gonic/gin"
	"todo-app/controllers"
	"todo-app/models"
)

func main() {
	r := gin.Default()
	models.ConnectDatabase()

	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)
	r.GET("/todos", controllers.GetTodos)
	r.POST("/todos", controllers.CreateTodo)
	r.PUT("/todos/:id", controllers.UpdateTodo)
	r.DELETE("/todos/:id", controllers.DeleteTodo)

	r.Run()
}
EOT

# Add models/models.go
print_message "Adding models/models.go"
cat <<EOT > models/models.go
package models

import (
	"github.com/jinzhu/gorm"
	"github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var DB *gorm.DB

type User struct {
	ID       uint   `gorm:"primary_key"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type Todo struct {
	ID        uint      `gorm:"primary_key"`
	UserID    uint      `gorm:"not null"`
	Todo      string    `gorm:"not null"`
	Completed bool      `gorm:"default:false"`
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP"`
}

func ConnectDatabase() {
	database, err := gorm.Open("sqlite3", "todo.db")
	if err != nil {
		panic("Failed to connect to database!")
	}

	database.AutoMigrate(&User{}, &Todo{})

	DB = database
}

func (user *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)
	return nil
}

func (user *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
}
EOT

# Add controllers/auth.go
print_message "Adding controllers/auth.go"
cat <<EOT > controllers/auth.go
package controllers

import (
	"net/http"
	"time"
	"todo-app/models"
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("super-secret-key")

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

func Register(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := models.User{Username: input.Username}
	if err := user.SetPassword(input.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not set password"})
		return
	}

	models.DB.Create(&user)
	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

func Login(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := models.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := user.CheckPassword(input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}
EOT

# Add controllers/todo.go
print_message "Adding controllers/todo.go"
cat <<EOT > controllers/todo.go
package controllers

import (
	"net/http"
	"strconv"
	"todo-app/models"
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
)

func GetTodos(c *gin.Context) {
	userID, _ := getUserID(c)
	var todos []models.Todo
	models.DB.Where("user_id = ?", userID).Find(&todos)
	c.JSON(http.StatusOK, todos)
}

func CreateTodo(c *gin.Context) {
	userID, _ := getUserID(c)
	var input struct {
		Todo string `json:"todo"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	todo := models.Todo{UserID: userID, Todo: input.Todo}
	models.DB.Create(&todo)
	c.JSON(http.StatusCreated, todo)
}

func UpdateTodo(c *gin.Context) {
	userID, _ := getUserID(c)
	var input struct {
		Todo      string `json:"todo"`
		Completed bool   `json:"completed"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	var todo models.Todo
	if err := models.DB.Where("id = ? AND user_id = ?", id, userID).First(&todo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	todo.Todo = input.Todo
	todo.Completed = input.Completed
	models.DB.Save(&todo)
	c.JSON(http.StatusOK, todo)
}

func DeleteTodo(c *gin.Context) {
	userID, _ := getUserID(c)
	id, _ := strconv.Atoi(c.Param("id"))
	if err := models.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.Todo{}).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Todo deleted"})
}

func getUserID(c *gin.Context) (uint, error) {
	tokenString := c.GetHeader("Authorization")[7:]
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return 0, err
	}
	return claims.UserID, nil
}
EOT

# Run the server
print_message "Starting the server"
go run main.go
