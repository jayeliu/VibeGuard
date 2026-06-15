package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/admin"
	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestMcpServer_Initialize(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %v", resp["jsonrpc"])
	}
	if resp["id"] != float64(1) {
		t.Errorf("expected id=1, got %v", resp["id"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %T", resp["result"])
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("expected protocolVersion=2024-11-05, got %v", result["protocolVersion"])
	}
	capabilities, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("expected capabilities object")
	}
	if _, hasTools := capabilities["tools"]; !hasTools {
		t.Error("expected capabilities to include tools")
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("expected serverInfo object")
	}
	if serverInfo["name"] != "vibeguard" {
		t.Errorf("expected name=vibeguard, got %v", serverInfo["name"])
	}
	if serverInfo["version"] != "test-version" {
		t.Errorf("expected version=test-version, got %v", serverInfo["version"])
	}
}

func TestMcpServer_ToolsList(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}
	resp := postJSON(t, srv, reqBody, token)

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object")
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools array")
	}
	if len(tools) == 0 {
		t.Error("expected at least one tool")
	}

	first := tools[0].(map[string]any)
	if first["name"] != "get_proxy_status" {
		t.Errorf("expected first tool=get_proxy_status, got %v", first["name"])
	}
}

func TestMcpServer_GetProxyStatus(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "get_proxy_status",
			"arguments": map[string]any{},
		},
		"id": 3,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object")
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("expected content array")
	}
	textItem := content[0].(map[string]any)
	if textItem["type"] != "text" {
		t.Errorf("expected type=text, got %v", textItem["type"])
	}

	// 验证 text 内容中的 JSON 结构
	var status map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &status); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}
	requiredFields := []string{"version", "started_at", "uptime", "total_requests", "redacted_count", "restored_count", "errors", "intercept_mode", "listen_address"}
	for _, f := range requiredFields {
		if _, ok := status[f]; !ok {
			t.Errorf("missing field: %s", f)
		}
	}
	if status["version"] != "test-version" {
		t.Errorf("expected version=test-version, got %v", status["version"])
	}
}

func TestMcpServer_InvalidJSON(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32700) {
		t.Errorf("expected error code -32700, got %v", errObj["code"])
	}
}

func TestMcpServer_MethodNotAllowed(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestMcpServer_EmptyMethod(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601 (method not found), got %v", errObj["code"])
	}
}

func TestMcpServer_UnknownMethod(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "nonexistent/method",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601, got %v", errObj["code"])
	}
}

func TestMcpServer_ToolNotFound(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nonexistent_tool",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601 (tool not found), got %v", errObj["code"])
	}
}

func TestMcpServer_ToolCallMissingName(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32602) {
		t.Errorf("expected error code -32602 (invalid params), got %v", errObj["code"])
	}
}

func TestMcpServer_ValidTokenMultipleRequests(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	for i := 0; i < 3; i++ {
		resp := postJSON(t, srv, reqBody, token)
		if _, hasError := resp["error"]; hasError {
			t.Errorf("request %d: unexpected error: %v", i, resp["error"])
		}
		if resp["jsonrpc"] != "2.0" {
			t.Errorf("request %d: expected jsonrpc=2.0, got %v", i, resp["jsonrpc"])
		}
	}
}

func TestMcpServer_AuthRequired(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", w.Code)
	}
}

func TestMcpServer_InvalidToken(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", w.Code)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.NewManager()
	caCertPath := dir + "/ca-cert.pem"
	caKeyPath := dir + "/ca-key.pem"
	ca, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	sess := session.NewManager(0, 1000)
	adm := admin.New(cfg, sess, ca, "", "")

	return NewServer(cfg, adm, "test-version")
}

func postJSON(t *testing.T, srv *Server, reqBody map[string]any, token string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()

	handler := AuthMiddleware(srv.Handler())
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			return map[string]any{"_status": w.Code}
		}
		t.Fatalf("unexpected status: %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v, body: %s", err, w.Body.String())
	}
	return resp
}
