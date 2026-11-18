package agent

// ReproductionToolSchema is the report_finding `reproduction` JSON-schema fragment.
func ReproductionToolSchema() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "【强烈建议填】结构化复现过程：供人工从零复现与交付报告。每步 request 写成标准 HTTP 请求报文（非 curl 命令），response 写状态行与关键 body，逐字取自真实执行；可自动关联录制流量。",
		"properties": map[string]any{
			"entry_point": str("触发漏洞的关键接口（方法+URL）"),
			"prerequisites": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "复现前置：账号/角色/前序步骤；测试账号需写清如何注册",
			},
			"steps": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"request":  str("该步真实 HTTP 请求报文（逐字，勿改写）"),
						"response": str("该步真实响应：状态行 + 关键 body 片段"),
						"expected": str("该步预期/结论（一句话）"),
						"proves":   str("这一步证明了什么"),
					},
				},
				"description": "有序复现步骤",
			},
			"provenance": str("攻击链来源/依赖"),
		},
	}
}
