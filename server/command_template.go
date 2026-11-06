package server

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command placeholders are identifiers with optional dots and hyphens.
// Other braces retain their ordinary shell meaning.
var commandPlaceholderPattern = regexp.MustCompile("\\{([A-Za-z_][A-Za-z0-9_.-]*)\\}")

type commandQuoteStyle uint8

const (
	commandUnquoted commandQuoteStyle = iota
	commandSingleQuoted
	commandDoubleQuoted
)

type commandLiteralSpan struct {
	start, end int
	quote      commandQuoteStyle
}

type commandPlaceholder struct {
	commandLiteralSpan
	name string
}

type commandTemplate struct {
	source       string
	placeholders []commandPlaceholder
}

// parseCommandToolExec is shared by create/update validation and execution.
// Runtime validation also protects old database rows and unsaved editor tests.
func parseCommandToolExec(raw json.RawMessage) (commandExec, *commandTemplate, error) {
	var spec commandExec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return spec, nil, fmt.Errorf("command exec 必须是包含 command 字符串的 JSON 对象")
	}
	if strings.TrimSpace(spec.Command) == "" {
		return spec, nil, fmt.Errorf("command 不能为空")
	}
	template, err := compileCommandTemplate(spec.Command, runtime.GOOS)
	return spec, template, err
}

// compileCommandTemplate accepts parameter substitution only in literal parts
// of ordinary command arguments. The AST establishes the quoting context;
// unsupported syntax never falls back to a handwritten shell lexer.
//
// Static commands remain operator-authored code in the platform's shell.
// Parameterized templates intentionally invoking eval or an interpreter's -c
// remain operator-granted code execution, beyond argument quoting.
func compileCommandTemplate(source, goos string) (*commandTemplate, error) {
	template := &commandTemplate{source: source}
	matches := commandPlaceholderPattern.FindAllStringSubmatchIndex(source, -1)
	if len(matches) == 0 {
		return template, nil
	}
	// Norma uses PowerShell on Windows and bash -c elsewhere. Bash quoting
	// must never be presented as safe interpolation for a different dialect.
	if goos == "windows" {
		return nil, fmt.Errorf("Windows 暂不支持带参数占位符的 command 工具（执行器使用 PowerShell）")
	}
	// Removing a continuation can create a dollar-quote or expansion across
	// source spans. Keep that syntax outside the supported template subset.
	if strings.Contains(source, "\\\n") {
		return nil, fmt.Errorf("带参数占位符的 command 模板不支持反斜杠续行，请使用单行或普通换行")
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return nil, fmt.Errorf("command 模板的 Bash 语法无效: %w", err)
	}
	var spans []commandLiteralSpan
	var literalParts func([]syntax.WordPart, commandQuoteStyle)
	literalParts = func(parts []syntax.WordPart, quote commandQuoteStyle) {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				spans = append(spans, commandLiteralSpan{int(part.Pos().Offset()), int(part.End().Offset()), quote})
			case *syntax.SglQuoted:
				if !part.Dollar {
					spans = append(spans, commandLiteralSpan{int(part.Pos().Offset()) + 1, int(part.End().Offset()) - 1, commandSingleQuoted})
				}
			case *syntax.DblQuoted:
				if !part.Dollar {
					literalParts(part.Parts, commandDoubleQuoted)
				}
			}
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.File, *syntax.Stmt, *syntax.BinaryCmd:
			// Ordinary statements, command sequences and pipelines.
			return true
		case *syntax.CallExpr:
			for _, word := range node.Args {
				literalParts(word.Parts, commandUnquoted)
			}
			// Never descend into assignments or nested command/process
			// substitutions, even when they contain another CallExpr.
		}
		return false
	})
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	spanIndex := 0
	for _, match := range matches {
		start, end := match[0], match[1]
		name := source[match[2]:match[3]]
		for spanIndex < len(spans) && spans[spanIndex].end <= start {
			spanIndex++
		}
		if spanIndex == len(spans) || start < spans[spanIndex].start || end > spans[spanIndex].end {
			return nil, fmt.Errorf("占位符 {%s} 必须位于普通命令参数中，不支持 shell 展开、重定向或复合语法中的占位符", name)
		}
		quote := spans[spanIndex].quote
		if quote != commandSingleQuoted {
			backslashes := 0
			for index := start - 1; index >= 0 && source[index] == '\\'; index-- {
				backslashes++
			}
			if backslashes%2 != 0 {
				return nil, fmt.Errorf("占位符 {%s} 前不能有未配对的反斜杠", name)
			}
		}
		template.placeholders = append(template.placeholders, commandPlaceholder{
			commandLiteralSpan: commandLiteralSpan{start, end, quote}, name: name,
		})
	}
	return template, nil
}

// render substitutes source spans once. Inserted values are never parsed as
// more template text, and absent parameters retain their literal placeholder.
func (template *commandTemplate) render(params map[string]any) (string, error) {
	var out strings.Builder
	out.Grow(len(template.source))
	position := 0
	for _, placeholder := range template.placeholders {
		out.WriteString(template.source[position:placeholder.start])
		if value, ok := params[placeholder.name]; ok {
			text := valToStr(value)
			if strings.IndexByte(text, 0) >= 0 {
				return "", fmt.Errorf("参数 %s 不能包含 NUL 字符", placeholder.name)
			}
			switch placeholder.quote {
			case commandUnquoted:
				out.WriteString(shellQuote(text))
			case commandSingleQuoted:
				out.WriteString(strings.ReplaceAll(text, "'", "'\\''"))
			case commandDoubleQuoted:
				for index := range len(text) {
					char := text[index]
					if char == '\\' || char == '$' || char == '"' || char == 0x60 {
						out.WriteByte('\\')
					}
					out.WriteByte(char)
				}
			}
		} else {
			out.WriteString(template.source[placeholder.start:placeholder.end])
		}
		position = placeholder.end
	}
	out.WriteString(template.source[position:])
	return out.String(), nil
}
