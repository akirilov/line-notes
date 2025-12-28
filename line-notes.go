package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load the environment variables from a .env file if it exists
	godotenv.Load()

	// Create a Gin router with default middleware (logger and recovery)
	r := gin.Default()

	// Define a simple GET endpoint
	r.GET("/ping", func(c *gin.Context) {
		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// Define a webhook for a LINE message API bot
	r.POST("/line/webhook", handleLineWebhook)

	// Start server on port 8080 (default)
	// Server will listen on 0.0.0.0:8080 (localhost:8080 on Windows)
	r.Run()
}

func handleLineWebhook(c *gin.Context) {
	// 1. Verify the request signature
	// Get the "x-line-signature" header from the request and decode it from base64
	req := c.Request
	body, err := c.GetRawData()
	if err != nil {
		println("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read request body"})
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Header.Get("x-line-signature"))
	if err != nil {
		println("Failed to decode x-line-signature header")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}
	hash := hmac.New(sha256.New, []byte(os.Getenv("LINE_CHANNEL_SECRET")))
	hash.Write(body)
	assessed := hash.Sum(nil)
	if !hmac.Equal(decoded, assessed) {
		println("Signature mismatch")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Signature mismatch"})
		return
	}

	// 2. Read the request body
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(body, &bodyMap); err != nil {
		println("Failed to parse JSON body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// 3. Print the received JSON body to the console
	jsonBytes, _ := json.MarshalIndent(bodyMap, "", "  ")
	fmt.Println(string(jsonBytes))

	// 4. Respond with 200 OK
	c.Status(http.StatusOK)
}
