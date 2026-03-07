package main

import (
	"fmt"
	"io"
	"strings"
)

// replWriter wraps an io.Writer and applies REPL-specific formatting:
//   - Inserts a blank line before "Found N entries" and "No entries" summary lines
//   - When pretty is true, reformats Mangle struct/list values with indentation
type replWriter struct {
	out    io.Writer
	pretty bool
}

func (w *replWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(string(p), "\n")
	var out strings.Builder
	for i, line := range lines {
		isSummary := strings.HasPrefix(line, "Found ") || strings.HasPrefix(line, "No entries")
		if isSummary {
			out.WriteByte('\n')
		}
		if w.pretty && line != "" && !isSummary {
			line = prettyFormatAtom(line)
		}
		out.WriteString(line)
		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}
	_, err = fmt.Fprint(w.out, out.String())
	return len(p), err
}

// prettyFormatAtom reformats a single Mangle atom string by expanding
// struct ({...}) and list ([...]) values with newlines and indentation.
// Content inside string literals is left untouched.
// Top-level atom arguments (inside the outer parentheses) are not expanded,
// keeping the predicate name and scalar args on readable lines.
func prettyFormatAtom(s string) string {
	var b strings.Builder
	depth := 0
	indent := func(d int) string { return strings.Repeat("  ", d) }
	i := 0
	for i < len(s) {
		ch := s[i]
		switch ch {
		case '"':
			// Copy the string literal verbatim, respecting backslash escapes.
			b.WriteByte(ch)
			i++
			for i < len(s) {
				c := s[i]
				b.WriteByte(c)
				i++
				if c == '\\' && i < len(s) {
					b.WriteByte(s[i])
					i++
				} else if c == '"' {
					break
				}
			}
		case '{', '[':
			b.WriteByte(ch)
			depth++
			b.WriteByte('\n')
			b.WriteString(indent(depth))
			i++
		case '}', ']':
			depth--
			b.WriteByte('\n')
			b.WriteString(indent(depth))
			b.WriteByte(ch)
			i++
		case ',':
			b.WriteByte(ch)
			i++
			if depth > 0 {
				b.WriteByte('\n')
				b.WriteString(indent(depth))
				// Skip the space that DisplayString puts after each comma.
				if i < len(s) && s[i] == ' ' {
					i++
				}
			}
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}
