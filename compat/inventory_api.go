// inventory_api extracts the public declaration surface of the pinned Go oracle.
//
// It deliberately uses only the Go standard library and parses source without
// loading, importing, type-checking, or building the upstream module.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pinnedRevision       = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
	expectedPackageCount = 16

	// Updated only after reviewing a deliberate upstream pin change. The digest
	// covers every stable key and every semantic declaration/build variant, not
	// merely the number of records.
	expectedIdentityCount  = 607
	expectedIdentitySHA256 = "de2e917190f3fdcc24c3db77e3e0a5c7fdd09aff97805b066273f4a7b6e96e6b"
)

type evidence struct {
	Source    string `json:"source"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line"`
	EndColumn int    `json:"end_column"`
}

type variant struct {
	Declaration     string     `json:"declaration"`
	BuildConstraint string     `json:"build_constraint"`
	Evidence        []evidence `json:"evidence"`
}

type record struct {
	Key            string    `json:"key"`
	Kind           string    `json:"kind"`
	Package        string    `json:"package"`
	PackageName    string    `json:"package_name"`
	Owner          string    `json:"owner,omitempty"`
	Name           string    `json:"name"`
	Exported       bool      `json:"exported"`
	Variants       []variant `json:"variants"`
	Identity       string    `json:"identity"`
	IdentitySHA256 string    `json:"identity_sha256"`
}

type packageRecord struct {
	ImportPath  string   `json:"import_path"`
	RelativeDir string   `json:"relative_dir"`
	Name        string   `json:"name"`
	Files       []string `json:"files"`
	RecordCount int      `json:"record_count"`
}

type inventory struct {
	SchemaVersion     int             `json:"schema_version"`
	UpstreamRevision  string          `json:"upstream_revision"`
	Module            string          `json:"module"`
	Packages          []packageRecord `json:"packages"`
	Records           []record        `json:"records"`
	Identities        []string        `json:"identities"`
	IdentityCount     int             `json:"identity_count"`
	IdentitySetSHA256 string          `json:"identity_set_sha256"`
}

type checkResult struct {
	Mode               string `json:"mode"`
	UpstreamRevision   string `json:"upstream_revision"`
	PackageCount       int    `json:"package_count"`
	IdentityCount      int    `json:"identity_count"`
	IdentitySetSHA256  string `json:"identity_set_sha256"`
	SameCountMutation  string `json:"same_count_mutation,omitempty"`
	ExpectedIdentities int    `json:"expected_identity_count"`
	Status             string `json:"status"`
}

type rawVariant struct {
	key             string
	kind            string
	packagePath     string
	packageName     string
	owner           string
	name            string
	declaration     string
	buildConstraint string
	evidence        evidence
}

type parsedFile struct {
	relativeDir     string
	relativePath    string
	packagePath     string
	packageName     string
	buildConstraint string
	fset            *token.FileSet
	file            *ast.File
}

func main() {
	var (
		root   = flag.String("root", "../gitleaks", "path to the pinned upstream checkout")
		mode   = flag.String("mode", "extract", "extract, check, or self-test")
		pretty = flag.Bool("pretty", false, "indent JSON output")
	)
	flag.Parse()

	if flag.NArg() != 0 {
		fatalf("unexpected positional arguments: %v", flag.Args())
	}

	inv, err := extract(*root)
	if err != nil {
		fatalf("extract API inventory: %v", err)
	}

	var output any
	switch *mode {
	case "extract":
		output = inv
	case "check":
		if err := checkPinnedInventory(inv); err != nil {
			fatalf("check API inventory: %v", err)
		}
		output = newCheckResult("check", inv, "")
	case "self-test":
		if err := checkPinnedInventory(inv); err != nil {
			fatalf("self-test baseline: %v", err)
		}
		if err := proveSameCountSubstitutionDetection(inv.Identities); err != nil {
			fatalf("self-test substitution guard: %v", err)
		}
		output = newCheckResult("self-test", inv, "detected")
	default:
		fatalf("unknown mode %q (want extract, check, or self-test)", *mode)
	}

	var data []byte
	if *pretty {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}
	if err != nil {
		fatalf("encode output: %v", err)
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		fatalf("write output: %v", err)
	}
}

func newCheckResult(mode string, inv inventory, mutation string) checkResult {
	return checkResult{
		Mode:               mode,
		UpstreamRevision:   inv.UpstreamRevision,
		PackageCount:       len(inv.Packages),
		IdentityCount:      inv.IdentityCount,
		IdentitySetSHA256:  inv.IdentitySetSHA256,
		SameCountMutation:  mutation,
		ExpectedIdentities: expectedIdentityCount,
		Status:             "ok",
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "inventory_api: "+format+"\n", args...)
	os.Exit(1)
}

func extract(root string) (inventory, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return inventory{}, err
	}
	revision, err := gitRevision(absRoot)
	if err != nil {
		return inventory{}, err
	}
	if revision != pinnedRevision {
		return inventory{}, fmt.Errorf("upstream revision mismatch: got %s, want %s", revision, pinnedRevision)
	}
	if err := verifyProductionSourceClean(absRoot); err != nil {
		return inventory{}, err
	}

	module, err := readModulePath(filepath.Join(absRoot, "go.mod"))
	if err != nil {
		return inventory{}, err
	}
	files, err := parseProductionFiles(absRoot, module)
	if err != nil {
		return inventory{}, err
	}
	reachableTypes := publicReachableTypes(files)

	raw := make([]rawVariant, 0, 1024)
	packages := make(map[string]*packageRecord)
	for _, file := range files {
		pkg := packages[file.packagePath]
		if pkg == nil {
			dir := file.relativeDir
			if dir == "." {
				dir = ""
			}
			pkg = &packageRecord{
				ImportPath:  file.packagePath,
				RelativeDir: dir,
				Name:        file.packageName,
			}
			packages[file.packagePath] = pkg
		} else if pkg.Name != file.packageName {
			return inventory{}, fmt.Errorf("directory %s contains packages %s and %s", file.relativeDir, pkg.Name, file.packageName)
		}
		pkg.Files = append(pkg.Files, file.relativePath)

		found, err := declarations(file, reachableTypes[file.packagePath])
		if err != nil {
			return inventory{}, err
		}
		raw = append(raw, found...)
	}

	records, err := mergeVariants(raw)
	if err != nil {
		return inventory{}, err
	}
	for i := range records {
		packages[records[i].Package].RecordCount++
	}

	packageList := make([]packageRecord, 0, len(packages))
	for _, pkg := range packages {
		sort.Strings(pkg.Files)
		packageList = append(packageList, *pkg)
	}
	sort.Slice(packageList, func(i, j int) bool { return packageList[i].ImportPath < packageList[j].ImportPath })

	identities := make([]string, len(records))
	for i := range records {
		identities[i] = records[i].Identity
	}
	setDigest := digestLines(identities)

	return inventory{
		SchemaVersion:     1,
		UpstreamRevision:  revision,
		Module:            module,
		Packages:          packageList,
		Records:           records,
		Identities:        identities,
		IdentityCount:     len(identities),
		IdentitySetSHA256: setDigest,
	}, nil
}

func gitRevision(root string) (string, error) {
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("git rev-parse failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git rev-parse failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func verifyProductionSourceClean(root string) error {
	command := exec.Command("git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all", "--", ":(glob)**/*.go", "go.mod")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("git status for production sources failed: %w", err)
	}
	if len(bytes.TrimSpace(output)) != 0 {
		return fmt.Errorf("upstream production Go sources are dirty:\n%s", strings.TrimSpace(string(output)))
	}
	return nil
}

func readModulePath(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}
	return "", errors.New("go.mod has no module directive")
}

func parseProductionFiles(root, module string) ([]parsedFile, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path == root {
				return nil
			}
			name := entry.Name()
			if name == ".git" || name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk production Go files: %w", err)
	}
	sort.Strings(paths)

	files := make([]parsedFile, 0, len(paths))
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		relative = filepath.ToSlash(relative)
		relativeDir := filepath.ToSlash(filepath.Dir(relative))
		packagePath := module
		if relativeDir != "." {
			packagePath += "/" + relativeDir
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", relative, err)
		}
		buildConstraint, err := canonicalBuildConstraint(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", relative, err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, data, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", relative, err)
		}
		files = append(files, parsedFile{
			relativeDir:     relativeDir,
			relativePath:    relative,
			packagePath:     packagePath,
			packageName:     parsed.Name.Name,
			buildConstraint: buildConstraint,
			fset:            fset,
			file:            parsed,
		})
	}
	return files, nil
}

func canonicalBuildConstraint(data []byte) (string, error) {
	lines := strings.Split(string(data), "\n")
	var oldConstraints []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
		if strings.HasPrefix(trimmed, "//go:build ") {
			expr, err := constraint.Parse(trimmed)
			if err != nil {
				return "", fmt.Errorf("parse build constraint %q: %w", trimmed, err)
			}
			return expr.String(), nil
		}
		if strings.HasPrefix(trimmed, "// +build ") {
			oldConstraints = append(oldConstraints, trimmed)
		}
	}
	if len(oldConstraints) == 0 {
		return "all", nil
	}
	var expressions []string
	for _, line := range oldConstraints {
		expr, err := constraint.Parse(line)
		if err != nil {
			return "", fmt.Errorf("parse build constraint %q: %w", line, err)
		}
		expressions = append(expressions, "("+expr.String()+")")
	}
	return strings.Join(expressions, " && "), nil
}

// publicReachableTypes finds local named types whose exported members are part
// of a usable package surface. Exported types seed the graph. Exported
// functions, variables, methods, and exported fields may make an unexported
// named type reachable even though callers cannot spell its name. This is the
// case for the raw Viper allowlist element types in the pinned oracle.
func publicReachableTypes(files []parsedFile) map[string]map[string]bool {
	type packageTypes struct {
		known     map[string][]*ast.TypeSpec
		reachable map[string]bool
		files     []parsedFile
	}
	packages := make(map[string]*packageTypes)
	for _, file := range files {
		pkg := packages[file.packagePath]
		if pkg == nil {
			pkg = &packageTypes{known: make(map[string][]*ast.TypeSpec), reachable: make(map[string]bool)}
			packages[file.packagePath] = pkg
		}
		pkg.files = append(pkg.files, file)
		for _, decl := range file.file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				pkg.known[typeSpec.Name.Name] = append(pkg.known[typeSpec.Name.Name], typeSpec)
				if ast.IsExported(typeSpec.Name.Name) {
					pkg.reachable[typeSpec.Name.Name] = true
				}
			}
		}
	}

	for _, pkg := range packages {
		// Package-level exported function and explicitly typed variable
		// signatures are roots independent of any receiver type.
		for _, file := range pkg.files {
			for _, decl := range file.file.Decls {
				switch node := decl.(type) {
				case *ast.FuncDecl:
					if node.Recv == nil && ast.IsExported(node.Name.Name) {
						addFieldListTypeReferences(node.Type.Params, pkg.known, pkg.reachable)
						addFieldListTypeReferences(node.Type.Results, pkg.known, pkg.reachable)
					}
				case *ast.GenDecl:
					if node.Tok != token.VAR && node.Tok != token.CONST {
						continue
					}
					for _, spec := range node.Specs {
						valueSpec, ok := spec.(*ast.ValueSpec)
						if !ok || valueSpec.Type == nil || !hasExportedName(valueSpec.Names) {
							continue
						}
						addTypeReferences(valueSpec.Type, pkg.known, pkg.reachable)
					}
				}
			}
		}

		changed := true
		for changed {
			before := len(pkg.reachable)
			for name := range pkg.reachable {
				for _, spec := range pkg.known[name] {
					addPublicShapeReferences(spec.Type, pkg.known, pkg.reachable)
				}
			}
			for _, file := range pkg.files {
				for _, decl := range file.file.Decls {
					method, ok := decl.(*ast.FuncDecl)
					if !ok || method.Recv == nil || !ast.IsExported(method.Name.Name) {
						continue
					}
					receiver, err := receiverName(method.Recv)
					if err != nil || !pkg.reachable[receiver] {
						continue
					}
					addFieldListTypeReferences(method.Type.Params, pkg.known, pkg.reachable)
					addFieldListTypeReferences(method.Type.Results, pkg.known, pkg.reachable)
				}
			}
			changed = len(pkg.reachable) != before
		}
	}

	result := make(map[string]map[string]bool, len(packages))
	for path, pkg := range packages {
		result[path] = pkg.reachable
	}
	return result
}

func hasExportedName(names []*ast.Ident) bool {
	for _, name := range names {
		if ast.IsExported(name.Name) {
			return true
		}
	}
	return false
}

func addPublicShapeReferences(expression ast.Expr, known map[string][]*ast.TypeSpec, reachable map[string]bool) {
	switch node := expression.(type) {
	case *ast.StructType:
		for _, field := range node.Fields.List {
			if len(field.Names) == 0 {
				if ast.IsExported(embeddedName(field.Type)) {
					addTypeReferences(field.Type, known, reachable)
				}
				continue
			}
			if hasExportedName(field.Names) {
				addTypeReferences(field.Type, known, reachable)
			}
		}
	case *ast.InterfaceType:
		for _, field := range node.Methods.List {
			if len(field.Names) == 0 {
				if ast.IsExported(embeddedName(field.Type)) {
					addTypeReferences(field.Type, known, reachable)
				}
				continue
			}
			if hasExportedName(field.Names) {
				addTypeReferences(field.Type, known, reachable)
			}
		}
	default:
		addTypeReferences(expression, known, reachable)
	}
}

func addFieldListTypeReferences(fields *ast.FieldList, known map[string][]*ast.TypeSpec, reachable map[string]bool) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		addTypeReferences(field.Type, known, reachable)
	}
}

func addTypeReferences(expression ast.Expr, known map[string][]*ast.TypeSpec, reachable map[string]bool) {
	switch node := expression.(type) {
	case *ast.Ident:
		if len(known[node.Name]) != 0 {
			reachable[node.Name] = true
		}
	case *ast.StarExpr:
		addTypeReferences(node.X, known, reachable)
	case *ast.ArrayType:
		addTypeReferences(node.Elt, known, reachable)
	case *ast.MapType:
		addTypeReferences(node.Key, known, reachable)
		addTypeReferences(node.Value, known, reachable)
	case *ast.ChanType:
		addTypeReferences(node.Value, known, reachable)
	case *ast.Ellipsis:
		addTypeReferences(node.Elt, known, reachable)
	case *ast.ParenExpr:
		addTypeReferences(node.X, known, reachable)
	case *ast.IndexExpr:
		addTypeReferences(node.X, known, reachable)
		addTypeReferences(node.Index, known, reachable)
	case *ast.IndexListExpr:
		addTypeReferences(node.X, known, reachable)
		for _, index := range node.Indices {
			addTypeReferences(index, known, reachable)
		}
	case *ast.FuncType:
		addFieldListTypeReferences(node.TypeParams, known, reachable)
		addFieldListTypeReferences(node.Params, known, reachable)
		addFieldListTypeReferences(node.Results, known, reachable)
	case *ast.StructType, *ast.InterfaceType:
		addPublicShapeReferences(expression, known, reachable)
	case *ast.UnaryExpr:
		addTypeReferences(node.X, known, reachable)
	case *ast.BinaryExpr:
		addTypeReferences(node.X, known, reachable)
		addTypeReferences(node.Y, known, reachable)
	}
}

func declarations(file parsedFile, reachableTypes map[string]bool) ([]rawVariant, error) {
	collector := declarationCollector{file: file, reachableTypes: reachableTypes}
	for _, decl := range file.file.Decls {
		switch node := decl.(type) {
		case *ast.GenDecl:
			if err := collector.genDecl(node); err != nil {
				return nil, err
			}
		case *ast.FuncDecl:
			if ast.IsExported(node.Name.Name) {
				if err := collector.function(node); err != nil {
					return nil, err
				}
			}
		}
	}
	return collector.raw, nil
}

type declarationCollector struct {
	file           parsedFile
	reachableTypes map[string]bool
	raw            []rawVariant
}

func (c *declarationCollector) genDecl(decl *ast.GenDecl) error {
	switch decl.Tok {
	case token.CONST, token.VAR:
		groupDeclaration, err := formatNode(c.file.fset, decl)
		if err != nil {
			return err
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range valueSpec.Names {
				if !ast.IsExported(name.Name) {
					continue
				}
				c.add(decl.Tok.String(), "", name.Name, groupDeclaration, name.Pos(), valueSpec.End())
			}
		}
	case token.TYPE:
		for _, spec := range decl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if ast.IsExported(typeSpec.Name.Name) {
				declaration, err := formatNode(c.file.fset, typeSpec)
				if err != nil {
					return err
				}
				c.add("type", "", typeSpec.Name.Name, "type "+declaration, typeSpec.Pos(), typeSpec.End())
			}
			if !c.reachableTypes[typeSpec.Name.Name] {
				continue
			}
			if err := c.typeMembers(typeSpec.Name.Name, typeSpec.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *declarationCollector) function(decl *ast.FuncDecl) error {
	copyDecl := &ast.FuncDecl{Recv: decl.Recv, Name: decl.Name, Type: decl.Type}
	declaration, err := formatNode(c.file.fset, copyDecl)
	if err != nil {
		return err
	}
	if decl.Recv == nil {
		c.add("func", "", decl.Name.Name, declaration, decl.Pos(), decl.Type.End())
		return nil
	}
	receiver, err := receiverName(decl.Recv)
	if err != nil {
		return fmt.Errorf("%s: %w", c.file.relativePath, err)
	}
	if c.reachableTypes[receiver] {
		c.add("method", receiver, decl.Name.Name, declaration, decl.Pos(), decl.Type.End())
	}
	return nil
}

func (c *declarationCollector) typeMembers(owner string, expression ast.Expr) error {
	switch node := expression.(type) {
	case *ast.StructType:
		return c.structFields(owner, node)
	case *ast.InterfaceType:
		return c.interfaceFields(owner, node)
	}
	return nil
}

func (c *declarationCollector) structFields(owner string, structure *ast.StructType) error {
	for _, field := range structure.Fields.List {
		declaration, err := formatStructField(c.file.fset, field)
		if err != nil {
			return err
		}
		if len(field.Names) == 0 {
			name := embeddedName(field.Type)
			if ast.IsExported(name) {
				c.add("embedded_field", owner, name, declaration, field.Pos(), field.End())
			}
			continue
		}
		for _, name := range field.Names {
			if !ast.IsExported(name.Name) {
				continue
			}
			c.add("field", owner, name.Name, declaration, name.Pos(), field.End())
			if err := c.anonymousMembers(owner+"."+name.Name, field.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *declarationCollector) interfaceFields(owner string, iface *ast.InterfaceType) error {
	for _, field := range iface.Methods.List {
		declaration, err := formatInterfaceField(c.file.fset, field)
		if err != nil {
			return err
		}
		if len(field.Names) == 0 {
			name := embeddedName(field.Type)
			if ast.IsExported(name) {
				c.add("interface_embed", owner, name, declaration, field.Pos(), field.End())
			}
			continue
		}
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				c.add("interface_method", owner, name.Name, declaration, name.Pos(), field.End())
			}
		}
	}
	return nil
}

func (c *declarationCollector) anonymousMembers(owner string, expression ast.Expr) error {
	switch node := expression.(type) {
	case *ast.StructType:
		return c.nestedStructFields(owner, node)
	case *ast.InterfaceType:
		return c.nestedInterfaceFields(owner, node)
	case *ast.ArrayType:
		return c.anonymousMembers(owner+"[]", node.Elt)
	case *ast.MapType:
		return c.anonymousMembers(owner+"{}", node.Value)
	case *ast.StarExpr:
		return c.anonymousMembers(owner, node.X)
	case *ast.ParenExpr:
		return c.anonymousMembers(owner, node.X)
	case *ast.ChanType:
		return c.anonymousMembers(owner+"<-", node.Value)
	case *ast.Ellipsis:
		return c.anonymousMembers(owner+"[]", node.Elt)
	}
	return nil
}

func (c *declarationCollector) nestedStructFields(owner string, structure *ast.StructType) error {
	for _, field := range structure.Fields.List {
		declaration, err := formatStructField(c.file.fset, field)
		if err != nil {
			return err
		}
		if len(field.Names) == 0 {
			name := embeddedName(field.Type)
			if ast.IsExported(name) {
				c.add("nested_embedded_field", owner, name, declaration, field.Pos(), field.End())
			}
			continue
		}
		for _, name := range field.Names {
			if !ast.IsExported(name.Name) {
				continue
			}
			c.add("nested_field", owner, name.Name, declaration, name.Pos(), field.End())
			if err := c.anonymousMembers(owner+"."+name.Name, field.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *declarationCollector) nestedInterfaceFields(owner string, iface *ast.InterfaceType) error {
	for _, field := range iface.Methods.List {
		declaration, err := formatInterfaceField(c.file.fset, field)
		if err != nil {
			return err
		}
		if len(field.Names) == 0 {
			name := embeddedName(field.Type)
			if ast.IsExported(name) {
				c.add("nested_interface_embed", owner, name, declaration, field.Pos(), field.End())
			}
			continue
		}
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				c.add("nested_interface_method", owner, name.Name, declaration, name.Pos(), field.End())
			}
		}
	}
	return nil
}

func (c *declarationCollector) add(kind, owner, name, declaration string, start, end token.Pos) {
	startPosition := c.file.fset.PositionFor(start, false)
	endPosition := c.file.fset.PositionFor(end, false)
	key := c.file.packagePath + "|" + kind + "|"
	if owner != "" {
		key += owner + "."
	}
	key += name
	c.raw = append(c.raw, rawVariant{
		key:             key,
		kind:            kind,
		packagePath:     c.file.packagePath,
		packageName:     c.file.packageName,
		owner:           owner,
		name:            name,
		declaration:     declaration,
		buildConstraint: c.file.buildConstraint,
		evidence: evidence{
			Source:    c.file.relativePath,
			Line:      startPosition.Line,
			Column:    startPosition.Column,
			EndLine:   endPosition.Line,
			EndColumn: endPosition.Column,
		},
	})
}

func receiverName(fields *ast.FieldList) (string, error) {
	if fields == nil || len(fields.List) != 1 {
		return "", errors.New("method receiver is not a single field")
	}
	name := receiverExpressionName(fields.List[0].Type)
	if name == "" {
		return "", errors.New("cannot determine method receiver name")
	}
	return name, nil
}

func receiverExpressionName(expression ast.Expr) string {
	switch node := expression.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.StarExpr:
		return receiverExpressionName(node.X)
	case *ast.IndexExpr:
		return receiverExpressionName(node.X)
	case *ast.IndexListExpr:
		return receiverExpressionName(node.X)
	case *ast.ParenExpr:
		return receiverExpressionName(node.X)
	}
	return ""
}

func embeddedName(expression ast.Expr) string {
	switch node := expression.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return node.Sel.Name
	case *ast.StarExpr:
		return embeddedName(node.X)
	case *ast.IndexExpr:
		return embeddedName(node.X)
	case *ast.IndexListExpr:
		return embeddedName(node.X)
	case *ast.ParenExpr:
		return embeddedName(node.X)
	}
	return ""
}

func formatNode(fset *token.FileSet, node any) (string, error) {
	var output bytes.Buffer
	if err := format.Node(&output, fset, node); err != nil {
		return "", fmt.Errorf("format declaration: %w", err)
	}
	return output.String(), nil
}

func formatStructField(fset *token.FileSet, field *ast.Field) (string, error) {
	wrapper := &ast.StructType{Fields: &ast.FieldList{List: []*ast.Field{field}}}
	return unwrapSingleField(fset, wrapper)
}

func formatInterfaceField(fset *token.FileSet, field *ast.Field) (string, error) {
	wrapper := &ast.InterfaceType{Methods: &ast.FieldList{List: []*ast.Field{field}}}
	return unwrapSingleField(fset, wrapper)
}

func unwrapSingleField(fset *token.FileSet, wrapper ast.Expr) (string, error) {
	formatted, err := formatNode(fset, wrapper)
	if err != nil {
		return "", err
	}
	opening := strings.IndexByte(formatted, '{')
	closing := strings.LastIndexByte(formatted, '}')
	if opening < 0 || closing <= opening {
		return "", fmt.Errorf("cannot unwrap field from %q", formatted)
	}
	return strings.TrimSpace(formatted[opening+1 : closing]), nil
}

func mergeVariants(raw []rawVariant) ([]record, error) {
	type variantAccumulator struct {
		declaration     string
		buildConstraint string
		evidence        []evidence
	}
	type recordAccumulator struct {
		kind        string
		packagePath string
		packageName string
		owner       string
		name        string
		variants    map[string]*variantAccumulator
	}

	groups := make(map[string]*recordAccumulator)
	for _, item := range raw {
		group := groups[item.key]
		if group == nil {
			group = &recordAccumulator{
				kind:        item.kind,
				packagePath: item.packagePath,
				packageName: item.packageName,
				owner:       item.owner,
				name:        item.name,
				variants:    make(map[string]*variantAccumulator),
			}
			groups[item.key] = group
		} else if group.kind != item.kind || group.packagePath != item.packagePath ||
			group.packageName != item.packageName || group.owner != item.owner || group.name != item.name {
			return nil, fmt.Errorf("inconsistent declarations for key %s", item.key)
		}
		variantKey := item.buildConstraint + "\x00" + item.declaration
		entry := group.variants[variantKey]
		if entry == nil {
			entry = &variantAccumulator{
				declaration:     item.declaration,
				buildConstraint: item.buildConstraint,
			}
			group.variants[variantKey] = entry
		}
		entry.evidence = append(entry.evidence, item.evidence)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	records := make([]record, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		variantKeys := make([]string, 0, len(group.variants))
		for variantKey := range group.variants {
			variantKeys = append(variantKeys, variantKey)
		}
		sort.Strings(variantKeys)
		variants := make([]variant, 0, len(variantKeys))
		var semantic strings.Builder
		semantic.WriteString(key)
		semantic.WriteByte('\n')
		for _, variantKey := range variantKeys {
			entry := group.variants[variantKey]
			sort.Slice(entry.evidence, func(i, j int) bool {
				left, right := entry.evidence[i], entry.evidence[j]
				if left.Source != right.Source {
					return left.Source < right.Source
				}
				if left.Line != right.Line {
					return left.Line < right.Line
				}
				return left.Column < right.Column
			})
			entry.evidence = deduplicateEvidence(entry.evidence)
			variants = append(variants, variant{
				Declaration:     entry.declaration,
				BuildConstraint: entry.buildConstraint,
				Evidence:        entry.evidence,
			})
			semantic.WriteString(entry.buildConstraint)
			semantic.WriteByte('\t')
			semantic.WriteString(entry.declaration)
			semantic.WriteByte('\n')
		}
		digest := sha256Hex(semantic.String())
		records = append(records, record{
			Key:            key,
			Kind:           group.kind,
			Package:        group.packagePath,
			PackageName:    group.packageName,
			Owner:          group.owner,
			Name:           group.name,
			Exported:       true,
			Variants:       variants,
			Identity:       key + "@" + digest,
			IdentitySHA256: digest,
		})
	}
	return records, nil
}

func deduplicateEvidence(items []evidence) []evidence {
	if len(items) < 2 {
		return items
	}
	result := items[:1]
	for _, item := range items[1:] {
		if item != result[len(result)-1] {
			result = append(result, item)
		}
	}
	return result
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func digestLines(lines []string) string {
	copyOfLines := append([]string(nil), lines...)
	sort.Strings(copyOfLines)
	var stream strings.Builder
	for _, line := range copyOfLines {
		stream.WriteString(line)
		stream.WriteByte('\n')
	}
	return sha256Hex(stream.String())
}

func checkPinnedInventory(inv inventory) error {
	if inv.UpstreamRevision != pinnedRevision {
		return fmt.Errorf("revision: got %s, want %s", inv.UpstreamRevision, pinnedRevision)
	}
	if len(inv.Packages) != expectedPackageCount {
		return fmt.Errorf("package count: got %d, want %d", len(inv.Packages), expectedPackageCount)
	}
	if inv.IdentityCount != expectedIdentityCount {
		return fmt.Errorf("identity count: got %d, want %d", inv.IdentityCount, expectedIdentityCount)
	}
	if inv.IdentitySetSHA256 != expectedIdentitySHA256 {
		return fmt.Errorf("identity set SHA-256: got %s, want %s", inv.IdentitySetSHA256, expectedIdentitySHA256)
	}
	if inv.IdentitySetSHA256 != digestLines(inv.Identities) {
		return errors.New("inventory identity digest is internally inconsistent")
	}
	return nil
}

func proveSameCountSubstitutionDetection(identities []string) error {
	if len(identities) == 0 {
		return errors.New("cannot test substitution detection on an empty identity set")
	}
	mutated := append([]string(nil), identities...)
	mutated[0] += "#same-count-substitution"
	if len(mutated) != len(identities) {
		return errors.New("self-test changed identity count")
	}
	if digestLines(mutated) == digestLines(identities) {
		return errors.New("same-count identity substitution was not detected")
	}
	return nil
}
