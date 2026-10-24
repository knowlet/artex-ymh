package skillprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const maxLicenseBytes = 64 << 10

type preparedSkill struct {
	entry     Entry
	name      string
	source    []byte
	converted []byte
}

// Import converts an explicit selection from a local, reviewed source snapshot.
// destination is a NEW library root, not an existing ARTEX skill directory.
// Publication is one atomic no-replace rename: existing user files, including
// empty directories, are never merged or replaced. Import writes no DB records.
func Import(ctx context.Context, c *Catalog, sourceDir, destination string, ids []string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if len(ids) == 0 || len(ids) > MaxSkills {
		return fmt.Errorf("select between 1 and %d skill IDs", MaxSkills)
	}
	entries := make(map[string]Entry, len(c.Skills))
	for _, e := range c.Skills {
		entries[e.ID] = e
	}
	selected, seen := make([]Entry, 0, len(ids)), map[string]bool{}
	for _, id := range ids {
		e, ok := entries[id]
		if !ok || seen[id] {
			return fmt.Errorf("unknown or duplicate selected skill %q", id)
		}
		seen[id] = true
		if e.Provenance != "verified" || e.ImportPolicy != "allowed" {
			return fmt.Errorf("skill %s is metadata-only: provenance must be verified before import", id)
		}
		selected = append(selected, e)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	src, err := openDirectory(sourceDir)
	if err != nil {
		return fmt.Errorf("source directory: %w", err)
	}
	defer src.Close()
	license, err := src.readFile(c.Source.License.Path, maxLicenseBytes)
	if err != nil {
		return fmt.Errorf("source license: %w", err)
	}
	if !utf8.Valid(license) || len(bytes.TrimSpace(license)) == 0 || hashBytes(license) != c.Source.License.SHA256 {
		return fmt.Errorf("source license UTF-8, content or SHA256 mismatch")
	}
	prepared := make([]preparedSkill, 0, len(selected))
	var total int64
	for _, e := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		original, err := src.readFile(e.SourcePath, MaxSourceBytes)
		if err != nil {
			return fmt.Errorf("skill %s: %w", e.ID, err)
		}
		if int64(len(original)) != e.SourceBytes || hashBytes(original) != e.SourceSHA256 {
			return fmt.Errorf("skill %s source size or SHA256 mismatch", e.ID)
		}
		converted, err := convert(c, e, original)
		if err != nil {
			return fmt.Errorf("skill %s: %w", e.ID, err)
		}
		total += int64(len(original) + len(converted) + len(license))
		if total > MaxTotalBytes {
			return fmt.Errorf("selected import output exceeds total byte limit")
		}
		prepared = append(prepared, preparedSkill{e, SkillName(c, e), original, converted})
	}
	dig, err := CatalogDigest(c)
	if err != nil {
		return err
	}
	var libraryNonce [16]byte
	if _, err := rand.Read(libraryNonce[:]); err != nil {
		return err
	}
	receipt := Receipt{LibraryID: hex.EncodeToString(libraryNonce[:]), SchemaVersion: SchemaVersion, Provider: c.Provider, Namespace: c.Namespace, Revision: c.Source.Revision, CatalogSHA256: dig, Skills: make([]ImportedSkill, 0, len(prepared))}
	for _, p := range prepared {
		receipt.Skills = append(receipt.Skills, ImportedSkill{ID: p.entry.ID, Name: p.name, SourceSHA256: p.entry.SourceSHA256, SkillSHA256: hashBytes(p.converted), LicenseSHA256: c.Source.License.SHA256})
	}
	receiptJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	receiptJSON = append(receiptJSON, '\n')
	libraryID := []byte(receipt.LibraryID + "\n")
	if total+int64(len(receiptJSON)+len(libraryID)) > MaxTotalBytes {
		return fmt.Errorf("import receipt exceeds total byte limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parentPath, target, err := destinationParts(destination)
	if err != nil {
		return err
	}
	parent, err := openDirectory(parentPath)
	if err != nil {
		return fmt.Errorf("destination parent: %w", err)
	}
	defer parent.Close()
	// Reject existing files, directories and symlinks before creating staging.
	if err := parent.requireAbsent(target); err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	stageName := ".provider-stage-" + hex.EncodeToString(random[:])
	if err := parent.mkdir(stageName); err != nil {
		return err
	}
	outer, err := parent.child(stageName)
	if err != nil {
		return err
	}
	defer outer.Close()
	if err := outer.requirePrivate(); err != nil {
		// An unexpected replacement is not ours to clean up. Do not create or
		// recursively remove anything beneath an unverified outer directory.
		return err
	}
	// Keep the rename's source parent pinned as well as the output parent.
	// Moving/replacing the visible outer staging name must neither publish the
	// replacement nor let cleanup recurse into somebody else's replacement.
	defer func() {
		_ = outer.removeTree("library")
		_ = parent.removeEmptyIfSame(stageName, outer)
	}()
	if err := outer.mkdir("library"); err != nil {
		return err
	}
	stage, err := outer.child("library")
	if err != nil {
		return err
	}
	defer stage.Close()
	for _, p := range prepared {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := stage.mkdir(p.name); err != nil {
			return err
		}
		dir, err := stage.child(p.name)
		if err != nil {
			return err
		}
		err = writePrepared(dir, p, license)
		dir.Close()
		if err != nil {
			return err
		}
	}
	if err := stage.writeFile(LibraryIDFilename, libraryID); err != nil {
		return err
	}
	if err := stage.writeFile(ReceiptFilename, receiptJSON); err != nil {
		return err
	}
	if err := stage.sync(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := outer.renameNoReplaceTo("library", parent, target); err != nil {
		return fmt.Errorf("publish without replacement: %w", err)
	}
	// Rename is the commit point. Once it succeeds, return success; a later
	// cancellation must not ambiguously report that an existing library was absent.
	return nil
}

func writePrepared(dir *safeDir, p preparedSkill, license []byte) error {
	if err := dir.mkdir("references"); err != nil {
		return err
	}
	refs, err := dir.child("references")
	if err != nil {
		return err
	}
	defer refs.Close()
	if err := refs.writeFile("source.md", p.source); err != nil {
		return err
	}
	if err := refs.writeFile("LICENSE", license); err != nil {
		return err
	}
	if err := refs.sync(); err != nil {
		return err
	}
	if err := dir.writeFile("SKILL.md", p.converted); err != nil {
		return err
	}
	return dir.sync()
}

func destinationParts(destination string) (string, string, error) {
	if destination == "" || len(destination) > 4096 || strings.ContainsAny(destination, "\\\x00") {
		return "", "", fmt.Errorf("invalid destination path")
	}
	for _, part := range strings.Split(filepath.ToSlash(destination), "/") {
		if part == ".." {
			return "", "", fmt.Errorf("destination traversal is forbidden")
		}
	}
	// Keep relative parents relative so openDirectory can pin "." directly.
	// All traversal components were rejected before this lexical cleanup.
	clean := filepath.Clean(destination)
	base := filepath.Base(clean)
	if base == "." || base == string(filepath.Separator) || len(base) > 240 {
		return "", "", fmt.Errorf("invalid destination root")
	}
	return filepath.Dir(clean), base, nil
}

// convert keeps the body byte-for-byte and retains the complete original source
// separately. Only inert metadata is emitted as active frontmatter: upstream
// mcps, tool permissions and hooks can never activate ARTEX execution features.
func convert(c *Catalog, e Entry, original []byte) ([]byte, error) {
	if !utf8.Valid(original) || len(bytes.TrimSpace(original)) == 0 || bytes.ContainsRune(original, '\x00') {
		return nil, fmt.Errorf("source must be nonempty UTF-8 text")
	}
	body := original
	description := e.Description
	licenseName := c.Source.License.SPDX
	if e.Format == "frontmatter" {
		header, rest, err := splitFrontmatter(original)
		if err != nil {
			return nil, err
		}
		var metadata map[string]any
		dec := yaml.NewDecoder(bytes.NewReader(header))
		if err := dec.Decode(&metadata); err != nil {
			return nil, fmt.Errorf("invalid YAML frontmatter: %w", err)
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("frontmatter must contain one YAML mapping")
		}
		description, _ = metadata["description"].(string)
		if !validText(description, 4096) {
			return nil, fmt.Errorf("frontmatter description must be nonempty text")
		}
		// A document's own notice may differ from the repository root license.
		// Retain that attribution instead of relabelling every document as the
		// root license; the full original header remains in references/source.md.
		if originalLicense, ok := metadata["license"]; ok {
			value, ok := originalLicense.(string)
			if !ok || !validText(value, 4096) {
				return nil, fmt.Errorf("frontmatter license must be nonempty text")
			}
			licenseName = value
		}
		body = rest
	} else if bytes.HasPrefix(original, []byte("---\n")) || bytes.HasPrefix(original, []byte("---\r\n")) {
		return nil, fmt.Errorf("legacy format unexpectedly contains YAML frontmatter")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("skill body is empty")
	}
	header := struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		License     string `yaml:"license"`
	}{SkillName(c, e), description, licenseName}
	fm, err := yaml.Marshal(header)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("---\n")
	out.Write(fm)
	out.WriteString("---\n")
	out.Write(body)
	if out.Len() > MaxSourceBytes {
		return nil, fmt.Errorf("converted skill exceeds byte limit")
	}
	return out.Bytes(), nil
}

func splitFrontmatter(b []byte) ([]byte, []byte, error) {
	first := bytes.IndexByte(b, '\n')
	if first < 0 || strings.TrimSuffix(string(b[:first]), "\r") != "---" {
		return nil, nil, fmt.Errorf("frontmatter opening delimiter missing")
	}
	start := first + 1
	for pos := start; pos < len(b); {
		n := bytes.IndexByte(b[pos:], '\n')
		end := len(b)
		next := len(b)
		if n >= 0 {
			end = pos + n
			next = end + 1
		}
		if strings.TrimSuffix(string(b[pos:end]), "\r") == "---" {
			return b[start:pos], b[next:], nil
		}
		pos = next
	}
	return nil, nil, fmt.Errorf("frontmatter closing delimiter missing")
}
