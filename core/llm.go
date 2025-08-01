package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

// LLMClient abstracts LLM chat completion
type LLMClient interface {
	Chat(prompt string) (string, error)
	ChatWithTimeout(ctx context.Context, prompt string, timeout time.Duration) (string, error)
}

// OpenAIClient implements LLMClient for OpenAI API
type OpenAIClient struct {
	client *openai.Client
	model  string
}

// ChatWithTimeout implements LLMClient interface for OpenAIClient
func (c *OpenAIClient) ChatWithTimeout(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	// Create a new context with the provided timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		response string
		err      error
	}

	resultCh := make(chan result, 1)

	go func() {
		// Use the existing Chat method but with our timeout context
		req := openai.ChatCompletionRequest{
			Model: c.model,
			Messages: []openai.ChatCompletionMessage{
				{Role: openai.ChatMessageRoleSystem, Content: "You are a penetration testing orchestration agent."},
				{Role: openai.ChatMessageRoleUser, Content: prompt},
			},
			Temperature: 0.7,
			MaxTokens:   500,
		}

		resp, err := c.client.CreateChatCompletion(timeoutCtx, req)
		if err != nil {
			resultCh <- result{response: "", err: fmt.Errorf("OpenAI API error: %v", err)}
			return
		}

		if len(resp.Choices) == 0 {
			resultCh <- result{response: "", err: fmt.Errorf("OpenAI returned empty choices")}
			return
		}

		responseText := strings.TrimSpace(resp.Choices[0].Message.Content)
		fmt.Printf("[DEBUG] OpenAI response: %s\n", responseText)
		resultCh <- result{response: responseText, err: nil}
	}()

	select {
	case <-timeoutCtx.Done():
		if timeoutCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("OpenAI request timed out after %v", timeout)
		}
		return "", timeoutCtx.Err()
	case res := <-resultCh:
		return res.response, res.err
	}
}

func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		client: openai.NewClient(apiKey),
		model:  model,
	}
}

func (c *OpenAIClient) Chat(prompt string) (string, error) {
	fmt.Printf("[DEBUG] OpenAI prompt: %s\n", prompt)

	req := openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You are a penetration testing orchestration agent."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature: 0.7,
		MaxTokens:   500,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("OpenAI API error: %v", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("OpenAI returned empty choices")
	}

	result := strings.TrimSpace(resp.Choices[0].Message.Content)
	fmt.Printf("[DEBUG] OpenAI response: %s\n", result)
	return result, nil
}

// OllamaClient implements LLMClient for Ollama API
type OllamaClient struct {
	Endpoint string
	Model    string
}

func NewOllamaClient(endpoint, model string) *OllamaClient {
	// Ensure endpoint doesn't end with a slash
	endpoint = strings.TrimSuffix(endpoint, "/")
	return &OllamaClient{
		Endpoint: endpoint,
		Model:    model,
	}
}

// Updated Ollamaclient method:

func (c *OllamaClient) Chat(prompt string) (string, error) {
	fmt.Printf("[DEBUG] Ollama prompt: %s\n", prompt)

	// For Ollama, we'll use the completions endpoint which is more reliable for JSON responses
	type Req struct {
		Model       string  `json:"model"`
		Prompt      string  `json:"prompt"`
		System      string  `json:"system"`
		Stream      bool    `json:"stream"`
		Temperature float32 `json:"temperature"`
		Format      string  `json:"format,omitempty"`
	}

	req := Req{
		Model:       c.Model,
		Prompt:      prompt,
		System:      "You are a penetration testing orchestration agent. Always respond with valid JSON.",
		Stream:      false,  // Important: set to false to get a complete response
		Temperature: 0.1,    // Lower temperature for more deterministic JSON responses
		Format:      "json", // Request JSON format if the model supports it
	}

	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %v", err)
	}

	fmt.Printf("[DEBUG] Sending to Ollama endpoint: %s\n", c.Endpoint+"/api/generate")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(c.Endpoint+"/api/generate", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("Ollama API error: %v", err)
	}
	defer resp.Body.Close()

	// Read the full response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	fmt.Printf("[DEBUG] Ollama raw response: %s\n", string(body))

	// Parse the response - Ollama returns a single JSON object for non-streaming requests
	var res struct {
		Response string `json:"response"`
		Error    string `json:"error,omitempty"`
	}

	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	if res.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", res.Error)
	}

	result := strings.TrimSpace(res.Response)
	fmt.Printf("[DEBUG] Ollama parsed response: %s\n", result)

	// Try to extract JSON from the response
	jsonStr := extractJSON(result)
	if jsonStr != "" {
		fmt.Printf("[DEBUG] Extracted JSON: %s\n", jsonStr)
		return jsonStr, nil
	}

	// If we couldn't extract JSON, return the full response
	return result, nil
}

func (c *OllamaClient) ChatWithTimeout(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		response string
		err      error
	}

	resultCh := make(chan result, 1)

	go func() {
		resp, err := c.Chat(prompt)
		resultCh <- result{response: resp, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("LLM request timed out after %v", timeout)
	case res := <-resultCh:
		return res.response, res.err
	}
}

// Add this helper function if it doesn't exist already
func extractJSON(text string) string {
	// Find the first { and last }
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")

	if start >= 0 && end > start {
		return text[start : end+1]
	}
	return ""
}
