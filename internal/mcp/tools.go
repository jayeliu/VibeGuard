package mcp

import (
	"encoding/json"
	"time"
)

// Tool 表示一个 MCP 工具定义
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

func (s *Server) registerTools() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tools["get_proxy_status"] = s.handleGetProxyStatus
}

func (s *Server) listTools() []Tool {
	return []Tool{
		{
			Name:        "get_proxy_status",
			Description: "获取 VibeGuard 代理的运行状态，包括启动时间、请求统计、拦截模式等",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

func (s *Server) handleGetProxyStatus(_ json.RawMessage) (any, error) {
	stats := s.admin.GetStats()
	cfg := s.cfg.Get()

	started := s.admin.StartedTime()
	uptime := ""
	if started > 0 {
		uptime = time.Since(time.Unix(started, 0)).Round(time.Second).String()
	}

	return map[string]any{
		"version":          s.version,
		"started_at":       time.Unix(started, 0).Format(time.RFC3339),
		"uptime":           uptime,
		"total_requests":   stats.TotalRequests.Load(),
		"redacted_count":   stats.RedactedRequests.Load(),
		"restored_count":   stats.RestoredRequests.Load(),
		"errors":           stats.Errors.Load(),
		"intercept_mode":   cfg.Proxy.InterceptMode,
		"websocket_beta":   cfg.Proxy.WebSocketRedactionBeta,
		"listen_address":   cfg.Proxy.Listen,
	}, nil
}
