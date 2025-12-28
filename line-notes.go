package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/docs/v1"
	"google.golang.org/api/option"
)

// Retrieves a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Channel to receive the authorization code from the callback
// Buffered channel (size 1) so the HTTP handler doesn't block
var authCodeChan = make(chan string, 1)

// Global Google Docs service client
var docsService *docs.Service

// Requests a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser to authorize:\n%v\n", authURL)
	fmt.Println("Waiting for authorization callback...")

	// Wait for the authorization code from the callback endpoint
	authCode := <-authCodeChan

	tok, err := config.Exchange(oauth2.NoContext, authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache OAuth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// Add a bullet point to the top of the Google Doc
func writeToGoogleDoc(text string) error {
	// Add a newline if the text does not end with one
	if len(text) == 0 || text[len(text)-1] != '\n' {
		text += "\n"
	}

	docId := os.Getenv("GOOGLE_DOC_ID")
	if docId != "" && docsService != nil {
		// Insert text at index 1 (right after the title)
		requests := []*docs.Request{
			// Insert the text at index 1
			{
				InsertText: &docs.InsertTextRequest{
					Location: &docs.Location{Index: 1},
					Text:     text,
				},
			},
			// Create a bullet for the paragraph we just inserted
			{
				CreateParagraphBullets: &docs.CreateParagraphBulletsRequest{
					Range: &docs.Range{
						StartIndex: 1,
						EndIndex:   int64(len(text) + 1),
					},
					BulletPreset: "BULLET_DISC_CIRCLE_SQUARE",
				},
			},
		}

		batchUpdateRequest := &docs.BatchUpdateDocumentRequest{
			Requests: requests,
		}

		_, err := docsService.Documents.BatchUpdate(docId, batchUpdateRequest).Do()
		if err != nil {
			return fmt.Errorf("Unable to update document: %v", err)
		} else {
			return nil
		}
	} else {
		return fmt.Errorf("Google Docs service not initialized or GOOGLE_DOC_ID not set")
	}
}

func handleOAuthCallback(c *gin.Context) {
	// Get the authorization code from the query parameter
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization code received"})
		return
	}

	// Send the code to the waiting OAuth flow
	authCodeChan <- code

	// Respond to the user
	log.Println("Authorization successful! You can close this window and return to the application.")
}

func handleLineWebhook(c *gin.Context) {
	// 1. Verify the request signature
	// Get the "x-line-signature" header from the request and decode it from base64
	req := c.Request
	body, err := c.GetRawData()
	if err != nil {
		log.Fatalf("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read request body"})
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Header.Get("x-line-signature"))
	if err != nil {
		log.Fatalf("Failed to decode x-line-signature header")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}
	hash := hmac.New(sha256.New, []byte(os.Getenv("LINE_CHANNEL_SECRET")))
	hash.Write(body)
	assessed := hash.Sum(nil)
	if !hmac.Equal(decoded, assessed) {
		log.Fatalf("Signature mismatch")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Signature mismatch"})
		return
	}

	// 2. Read the request body
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(body, &bodyMap); err != nil {
		log.Fatalf("Failed to parse JSON body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// 2.5. (DEBUG) Print the received JSON body to the console
	jsonBytes, _ := json.MarshalIndent(bodyMap, "", "  ")
	fmt.Println(string(jsonBytes))

	// 3. Get teh message text
	events, ok := bodyMap["events"].([]interface{})
	if !ok || len(events) == 0 {
		log.Printf("No events found in the request")
		c.Status(http.StatusOK)
		return
	}
	for _, event := range events {
		eventMap, ok := event.(map[string]interface{})
		if !ok {
			continue
		}
		if eventMap["type"] != "message" {
			continue
		}
		message, ok := eventMap["message"].(map[string]interface{})
		if !ok {
			continue
		}
		if message["type"] != "text" {
			continue
		}
		text, ok := message["text"].(string)
		if !ok {
			continue
		}
		err = writeToGoogleDoc(text)
		if err != nil {
			log.Printf("Failed to write to Google Doc: %v", err)
		}
	}

	// 4. Respond with 200 OK
	c.Status(http.StatusOK)
}

func main() {
	// Load the environment variables from a .env file if it exists
	godotenv.Load()

	// Set Gin to release mode unless otherwise specified
	ginMode := os.Getenv("GIN_MODE")
	if ginMode == "" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(ginMode)
	}

	// Create a Gin router with default middleware (logger and recovery)
	r := gin.Default()

	// OAuth callback endpoint
	r.GET("/oauth/callback", handleOAuthCallback)

	// Define a webhook for a LINE message API bot
	r.POST("/line/webhook", handleLineWebhook)

	// Initialize Google Docs client in background
	go func() {
		ctx := context.Background()
		b, err := os.ReadFile("credentials.json")
		if err != nil {
			log.Fatalf("Unable to read client secret file: %v", err)
		}

		// If modifying these scopes, delete your previously saved token.json.
		config, err := google.ConfigFromJSON(b, "https://www.googleapis.com/auth/documents")
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
		}

		// Set the redirect URL (change this to your reverse proxy URL)
		config.RedirectURL = os.Getenv("OAUTH_REDIRECT_URL")
		if config.RedirectURL == "" {
			log.Fatalf("OAUTH_REDIRECT_URL environment variable is not set")
		}

		client := getClient(config)

		srv, err := docs.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			log.Fatalf("Unable to retrieve Docs client: %v", err)
		}

		// Set the global service
		docsService = srv
		log.Println("Google Docs client initialized successfully")
	}()

	// Start server on port 8080 (default)
	// Server will listen on 0.0.0.0:8080 (localhost:8080 on Windows)
	r.Run()
}
