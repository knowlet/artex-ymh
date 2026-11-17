package agent

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Keep the page/Markdown and optional RECON contract of WebFetch independent
// from the HTTP client so transport policy never depends on fetched content.
func webFetchContent(body []byte, contentType string, extract bool) string {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return strings.TrimSpace(string(body))
	}
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return strings.TrimSpace(string(body))
	}
	var output strings.Builder
	var render func(*html.Node, bool)
	render = func(n *html.Node, pre bool) {
		if n.Type == html.TextNode {
			if pre {
				output.WriteString(n.Data)
			} else {
				output.WriteString(webFetchWhitespace.ReplaceAllString(n.Data, " "))
			}
			return
		}
		if n.Type != html.ElementNode && n.Type != html.DocumentNode {
			return
		}
		var before, after string
		switch n.Data {
		case "script", "style", "noscript", "svg", "template":
			return
		case "title", "h1", "h2", "h3", "h4", "h5", "h6":
			level := 1
			if len(n.Data) == 2 {
				level = int(n.Data[1] - '0')
			}
			before, after = "\n\n"+strings.Repeat("#", level)+" ", "\n\n"
		case "p", "div", "section", "article", "header", "footer", "main", "ul", "ol", "table", "tr", "blockquote":
			before, after = "\n\n", "\n\n"
		case "li":
			before, after = "\n- ", "\n"
		case "br":
			after = "\n"
		case "hr":
			before = "\n\n---\n\n"
		case "pre":
			before, after, pre = "\n\n```\n", "\n```\n\n", true
		case "code":
			if !pre {
				before, after = "`", "`"
			}
		case "strong", "b":
			before, after = "**", "**"
		case "em", "i":
			before, after = "*", "*"
		case "a":
			if href := webFetchAttr(n, "href"); href != "" {
				before, after = "[", "]("+href+")"
			}
		case "img":
			if src := webFetchAttr(n, "src"); src != "" {
				before = "![" + webFetchAttr(n, "alt") + "](" + src + ")"
			}
		case "td", "th":
			after = " | "
		}
		output.WriteString(before)
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			render(child, pre)
		}
		output.WriteString(after)
	}
	render(doc, false)
	text := strings.TrimSpace(webFetchBlankLines.ReplaceAllString(output.String(), "\n\n"))
	if extract {
		text += webFetchRecon(doc)
	}
	return strings.TrimSpace(text)
}

var (
	webFetchWhitespace = regexp.MustCompile(`[\t\n\r ]+`)
	webFetchBlankLines = regexp.MustCompile(`\n(?:[\t ]*\n){2,}`)
	webFetchEndpoints  = regexp.MustCompile("[\"'`](https?://[^\"'`\\s]+|/[^\"'`\\s]{2,})[\"'`]")
)

func webFetchAttr(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func webFetchRecon(doc *html.Node) string {
	labels := []string{"COMMENTS", "SCRIPTS (src)", "INLINE ENDPOINTS", "FORMS", "META", "LINKS"}
	sections := make([][]string, len(labels))
	seen := make([]map[string]bool, len(labels))
	for i := range seen {
		seen[i] = make(map[string]bool)
	}
	add := func(section int, value string) {
		value = limitWebFetchText(strings.Join(strings.Fields(value), " "), 600)
		if value != "" && len(sections[section]) < 100 && !seen[section][value] {
			seen[section][value] = true
			sections[section] = append(sections[section], value)
		}
	}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.CommentNode {
			add(0, n.Data)
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script":
				add(1, webFetchAttr(n, "src"))
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						for _, match := range webFetchEndpoints.FindAllStringSubmatch(c.Data, 40) {
							add(2, match[1])
						}
					}
				}
			case "form":
				method := strings.ToUpper(webFetchAttr(n, "method"))
				if method == "" {
					method = "GET"
				}
				var fields []string
				var collect func(*html.Node)
				collect = func(field *html.Node) {
					if field.Type == html.ElementNode && (field.Data == "input" || field.Data == "select" || field.Data == "textarea") && len(fields) < 100 {
						typ := webFetchAttr(field, "type")
						if typ == "" {
							typ = field.Data
						}
						if typ == "hidden" {
							typ += "=" + webFetchAttr(field, "value")
						}
						fields = append(fields, webFetchAttr(field, "name")+"("+typ+")")
					}
					for c := field.FirstChild; c != nil; c = c.NextSibling {
						collect(c)
					}
				}
				collect(n)
				add(3, fmt.Sprintf("%s %s → %s", method, webFetchAttr(n, "action"), strings.Join(fields, ", ")))
			case "meta":
				name := webFetchAttr(n, "name")
				if name == "" {
					name = webFetchAttr(n, "property")
				}
				if name != "" {
					add(4, name+"="+webFetchAttr(n, "content"))
				}
			case "a", "link":
				add(5, webFetchAttr(n, "href"))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	var result strings.Builder
	for i, entries := range sections {
		if len(entries) == 0 {
			continue
		}
		if result.Len() == 0 {
			result.WriteString("\n\n=== RECON ===")
		}
		fmt.Fprintf(&result, "\n\n## %s\n", labels[i])
		for _, entry := range entries {
			result.WriteString("- " + entry + "\n")
		}
	}
	return result.String()
}

func limitWebFetchText(text string, max int) string {
	if len(text) <= max {
		return text
	}
	for max > 0 && !utf8.RuneStart(text[max]) {
		max--
	}
	return text[:max] + "\n[truncated]"
}
