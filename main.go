package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-playground/validator/v10"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
)

type LoginForm struct {
	Username string `form:"username" binding:"required,validusername"`
	Password string `form:"password" binding:"required"`
}

const UsernameRegex = "^[a-z][a-z\\d\\-_]+$"
const serverAddress = "ldaps://ank.chnet"
const filenamePattern = "/data/%s.zip"
const downloadName = "ch-homedir-%s.zip"

var roots = x509.NewCertPool()

func main() {
	// Load LDAP CA root
	cert, err := ioutil.ReadFile("static/wisvch.crt")
	if err != nil {
		log.Fatalf("could not read CA root: %v", err)
	}
	roots.AppendCertsFromPEM(cert)

	// Set up validators
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("validusername", usernameValidator); err != nil {
			log.Fatal(err)
		}
	}

	// Set up router
	r := gin.New()
	r.Use(gin.Recovery())
	r.LoadHTMLFiles("static/form.html")
	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Set up main routes
	g := r.Group("/homedir")
	g.Static("/assets", "static/assets")
	g.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "form.html", gin.H{"username": c.Query("u")})
	})
	g.POST("/", func(c *gin.Context) {
		var form LoginForm
		if err := c.ShouldBindWith(&form, binding.FormPost); err == nil {
			err = validatePassword(form.Username, form.Password)
			if err != nil {
				log.Printf("failure for %s: %v", form.Username, err)
				c.HTML(http.StatusOK, "form.html", gin.H{
					"username": form.Username,
					"error":    "Could not authenticate",
				})
				return
			} else {
				log.Printf("success for %s", form.Username)
				filename := fmt.Sprintf(filenamePattern, form.Username)
				if _, err := os.Stat(filename); os.IsNotExist(err) {
					c.HTML(http.StatusOK, "form.html", gin.H{
						"username": form.Username,
						"error":    fmt.Sprintf("No home directory found for %s", form.Username),
					})
					return
				}
				c.FileAttachment(filename, fmt.Sprintf(downloadName, form.Username))
			}
		} else {
			c.HTML(http.StatusOK, "form.html", gin.H{
				"username": form.Username,
				"error":    "Invalid username (must be lowercase)",
			})
			return
		}
	})

	// Start server
	log.Fatal(r.Run())
}

func usernameValidator(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	b, _ := regexp.MatchString(UsernameRegex, username)
	return b
}

func validatePassword(username string, password string) error {
	opts := ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots})
	conn, err := ldap.DialURL(serverAddress, opts)
	if err != nil {
		return fmt.Errorf("could dial LDAP server: %w", err)
	}
	defer conn.Close()

	dn := fmt.Sprintf("uid=%s,ou=People,dc=ank,dc=chnet", ldap.EscapeFilter(username))
	err = conn.Bind(dn, password)
	if err != nil {
		return fmt.Errorf("LDAP bind error: %w", err)
	}
	return nil
}
