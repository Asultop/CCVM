// ccvm.go - Cross Compiler Version Manager
// Go语言重构版本，修复了正则表达式等潜在bug

package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	// "time"
)

// 全局配置
type Config struct {
	HomeDir       string
	CCVMHome      string
	Registry      string
	RcFile        string
	ToolchainBase string
	DefaultMirror string
	BaseSysPath   string
}

var gConfig Config

// HTTP客户端（带User-Agent）
var httpClient = &http.Client{}

// httpGet 发送带User-Agent的HTTP GET请求
func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	return httpClient.Do(req)
}

// 缓存条目
type CacheEntry struct {
	Ver       string   `json:"ver"`
	Target    string   `json:"target"`
	Subtarget string   `json:"subtarget"`
	Pkgs      []string `json:"pkgs"`
}

func init() {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "."
	}

	gConfig = Config{
		HomeDir:       homeDir,
		CCVMHome:      filepath.Join(homeDir, ".ccvm"),
		Registry:      filepath.Join(homeDir, ".ccvm", "registry"),
		RcFile:        filepath.Join(homeDir, ".ccvm", "ccvmrc"),
		ToolchainBase: filepath.Join(homeDir, "Toolchains"),
		DefaultMirror: "https://downloads.openwrt.org/releases",
		BaseSysPath:   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

// 工具函数：执行命令并返回输出
func runCapture(cmdStr string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// 工具函数：执行命令
func runCommand(cmdStr string, quiet bool) error {
	if !quiet {
		fmt.Fprintf(os.Stderr, "[执行] %s\n", cmdStr)
	}
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// 工具函数：路径存在性检查
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 工具函数：URL转安全文件名
func urlToSafeFilename(url string) string {
	safe := url
	// 移除协议
	if idx := strings.Index(safe, "://"); idx != -1 {
		safe = safe[idx+3:]
	}
	// 替换特殊字符
	replacer := strings.NewReplacer(
		"/", "_", ":", "_", "?", "_", "&", "_",
		"=", "_", " ", "_", "@", "_",
	)
	safe = replacer.Replace(safe)
	// 限制长度
	if len(safe) > 100 {
		safe = safe[:100]
	}
	return safe
}

// JSON转义
func escapeJSON(s string) string {
	var out strings.Builder
	for _, c := range s {
		switch c {
		case '\\':
			out.WriteString("\\\\")
		case '"':
			out.WriteString("\\\"")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			out.WriteRune(c)
		}
	}
	return out.String()
}

// 保存缓存为NDJSON
func saveCacheNDJSON(path string, entries []CacheEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("无法创建缓存文件: %w", err)
	}
	defer file.Close()

	for _, e := range entries {
		fmt.Fprintf(file, `{"ver":"%s","target":"%s","subtarget":"%s","pkgs":[`,
			escapeJSON(e.Ver), escapeJSON(e.Target), escapeJSON(e.Subtarget))
		for i, pkg := range e.Pkgs {
			if i > 0 {
				file.WriteString(",")
			}
			fmt.Fprintf(file, `"%s"`, escapeJSON(pkg))
		}
		file.WriteString("]}\n")
	}
	return nil
}

// 加载NDJSON缓存
func loadCacheNDJSON(path string) ([]CacheEntry, error) {
	if !pathExists(path) {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []CacheEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// 修复的正则表达式，使用正确的JSON解析
	reVer := regexp.MustCompile(`"ver"\s*:\s*"([^"]*)"`)
	reTarget := regexp.MustCompile(`"target"\s*:\s*"([^"]*)"`)
	reSubtarget := regexp.MustCompile(`"subtarget"\s*:\s*"([^"]*)"`)
	rePkgs := regexp.MustCompile(`"pkgs"\s*:\s*\[([^\]]*)\]`)
	rePkgItem := regexp.MustCompile(`"([^"]*)"`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		var e CacheEntry

		if m := reVer.FindStringSubmatch(line); m != nil {
			e.Ver = m[1]
		}
		if m := reTarget.FindStringSubmatch(line); m != nil {
			e.Target = m[1]
		}
		if m := reSubtarget.FindStringSubmatch(line); m != nil {
			e.Subtarget = m[1]
		}
		if m := rePkgs.FindStringSubmatch(line); m != nil {
			pkgMatches := rePkgItem.FindAllStringSubmatch(m[1], -1)
			for _, pm := range pkgMatches {
				if len(pm) > 1 {
					e.Pkgs = append(e.Pkgs, pm[1])
				}
			}
		}

		if e.Ver != "" && e.Target != "" {
			entries = append(entries, e)
		} else if line != "" {
			fmt.Fprintf(os.Stderr, "警告：缓存文件第 %d 行格式无效，跳过\n", lineNum)
		}
	}

	return entries, scanner.Err()
}

// rsync列表获取（非递归）
func runRsyncList(url string) ([]string, error) {
	// 修复：添加stderr重定向避免管道阻塞
	cmdStr := fmt.Sprintf("rsync --list-only --quiet '%s' 2>&1", url)
	output, err := runCapture(cmdStr)
	if err != nil {
		return nil, err
	}

	var results []string
	// 修复的正则：更精确的rsync输出格式匹配
	reList := regexp.MustCompile(`^([dl-][rwx-]{9})\s+\d+\s+\S+\s+\S+\s+(.+)$`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if matches := reList.FindStringSubmatch(line); matches != nil {
			token := strings.TrimRight(matches[2], "/ \t")
			if token != ".." && token != "." && token != "" {
				if len(token) > 0 && (isAlphaNum(rune(token[0]))) {
					results = append(results, token)
				}
			}
		}
	}

	return results, nil
}

// rsync递归列表获取
func runRsyncRecursiveList(url string) ([]string, error) {
	// 修复：添加stderr重定向和超时控制
	cmdStr := fmt.Sprintf("timeout 30 rsync -rz --list-only '%s' 2>&1", url)
	output, err := runCapture(cmdStr)
	if err != nil && !strings.Contains(output, "openwrt-sdk") {
		return nil, err
	}

	var results []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 跳过欢迎信息
		if len(line) > 0 {
			c := line[0]
			if c != 'd' && c != '-' && c != 'l' {
				continue
			}
		}

		if len(line) < 11 {
			continue
		}

		// 提取路径部分
		fields := strings.Fields(line)
		if len(fields) > 0 {
			token := strings.TrimRight(fields[len(fields)-1], "/ \t")
			if token != ".." && token != "." && token != "" {
				if len(token) > 0 && isAlphaNum(rune(token[0])) {
					results = append(results, token)
				}
			}
		}
	}

	return results, nil
}

// 辅助函数：检查字符是否为字母或数字
func isAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// 列出已注册的编译器
func listRegistry() ([]struct{ Name, Target string }, error) {
	var results []struct{ Name, Target string }

	if !pathExists(gConfig.Registry) {
		return results, nil
	}

	entries, err := ioutil.ReadDir(gConfig.Registry)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(gConfig.Registry, entry.Name())
		info, err := os.Lstat(entryPath)
		if err != nil {
			continue
		}

		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(entryPath)
			if err != nil {
				continue
			}
			results = append(results, struct{ Name, Target string }{
				Name:   entry.Name(),
				Target: target,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results, nil
}

// 查找工具链bin目录
func findToolchainBin(baseDir string) (string, error) {
	if !pathExists(baseDir) {
		return "", fmt.Errorf("目录不存在: %s", baseDir)
	}

	// 检查直接的bin目录
	binPath := filepath.Join(baseDir, "bin")
	if info, err := os.Stat(binPath); err == nil && info.IsDir() {
		// 检查是否非空
		entries, err := ioutil.ReadDir(binPath)
		if err == nil && len(entries) > 0 {
			return binPath, nil
		}
	}

	// 检查staging_dir/toolchain-*/bin
	stagePath := filepath.Join(baseDir, "staging_dir")
	if info, err := os.Stat(stagePath); err == nil && info.IsDir() {
		entries, err := ioutil.ReadDir(stagePath)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "toolchain-") {
					toolchainBin := filepath.Join(stagePath, entry.Name(), "bin")
					if info, err := os.Stat(toolchainBin); err == nil && info.IsDir() {
						return toolchainBin, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("未找到有效的bin目录")
}

// 去重并修复PATH
func dedupBasePath(newPath string) string {
	parts := strings.Split(newPath, ":")
	seen := make(map[string]bool)
	var uniqueParts []string

	for _, part := range parts {
		if part != "" && !seen[part] {
			uniqueParts = append(uniqueParts, part)
			seen[part] = true
		}
	}

	// 确保系统基础路径存在
	baseParts := strings.Split(gConfig.BaseSysPath, ":")
	for _, bp := range baseParts {
		if bp != "" && !seen[bp] {
			uniqueParts = append(uniqueParts, bp)
			seen[bp] = true
		}
	}

	return strings.Join(uniqueParts, ":")
}

// 确保目录存在
func ensureDirs() error {
	dirs := []string{gConfig.CCVMHome, gConfig.Registry, gConfig.ToolchainBase}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败 %s: %w", dir, err)
		}
	}
	return nil
}

// 命令：add
func cmdAdd(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("用法：add <toolchain目录>")
	}

	dir, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("无法获取绝对路径: %w", err)
	}

	if !pathExists(dir) {
		return fmt.Errorf("目录不存在: %s", dir)
	}

	binDir, err := findToolchainBin(dir)
	if err != nil {
		return fmt.Errorf("无法识别工具链目录: %w", err)
	}

	regName := filepath.Base(dir)
	linkPath := filepath.Join(gConfig.Registry, regName)

	suffix := 1
	for pathExists(linkPath) {
		regName = filepath.Base(dir) + "_" + strconv.Itoa(suffix)
		linkPath = filepath.Join(gConfig.Registry, regName)
		suffix++
	}

	if err := os.Symlink(dir, linkPath); err != nil {
		return fmt.Errorf("创建符号链接失败: %w", err)
	}

	fmt.Printf("成功注册工具链：%s\n", regName)
	fmt.Printf("  路径：%s\n", dir)
	fmt.Printf("  Bin目录：%s\n", binDir)
	return nil
}

// 命令：list
func cmdList() error {
	entries, err := listRegistry()
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("暂无已注册的交叉编译器")
		return nil
	}

	fmt.Println("已注册的交叉编译器列表：")
	fmt.Println("-------------------------")
	for i, entry := range entries {
		fmt.Printf("%d) %s\n", i+1, entry.Name)
		fmt.Printf("   路径：%s\n", entry.Target)
	}
	fmt.Println("-------------------------")
	fmt.Printf("总计：%d 个工具链\n", len(entries))
	return nil
}

// 命令：list --online
func cmdListOnline(args []string) error {
	var ver, target, subtarget, mirror string
	mirror = gConfig.DefaultMirror
	useCache := true

	// 解析参数
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--mirror":
			if i+1 < len(args) {
				mirror = args[i+1]
				i++
			}
		case "--no-cache":
			useCache = false
		default:
			if ver == "" {
				ver = args[i]
			} else if target == "" {
				target = args[i]
			} else if subtarget == "" {
				subtarget = args[i]
			}
		}
	}

	cacheSuffix := urlToSafeFilename(mirror)
	cacheFile := filepath.Join(gConfig.CCVMHome, "online_cache_"+cacheSuffix+".json")

	var cacheEntries []CacheEntry
	if useCache {
		// 先尝试加载对应镜像的缓存
		if pathExists(cacheFile) {
			var err error
			cacheEntries, err = loadCacheNDJSON(cacheFile)
			if err == nil && len(cacheEntries) > 0 {
				fmt.Printf("[使用缓存] 加载 %d 条缓存记录\n", len(cacheEntries))
			}
		}
		// 如果没有，尝试加载旧的通用缓存文件
		if len(cacheEntries) == 0 {
			oldCacheFile := filepath.Join(gConfig.CCVMHome, "online_cache.json")
			if pathExists(oldCacheFile) {
				var err error
				cacheEntries, err = loadCacheNDJSON(oldCacheFile)
				if err == nil && len(cacheEntries) > 0 {
					fmt.Printf("[使用旧缓存] 加载 %d 条缓存记录\n", len(cacheEntries))
				}
			}
		}
	}

	// 无版本参数：列出所有版本/目标/子目标
	if ver == "" {
		if len(cacheEntries) > 0 {
			fmt.Println("OpenWrt 可用配置列表（缓存）：")
			fmt.Println("格式: <版本> <目标> <子目标>")
			fmt.Println("-------------------------")
			
			// 按版本排序
			type Entry struct {
				Ver, Target, Subtarget string
			}
			var entries []Entry
			for _, e := range cacheEntries {
				entries = append(entries, Entry{e.Ver, e.Target, e.Subtarget})
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].Ver != entries[j].Ver {
					return entries[i].Ver < entries[j].Ver
				}
				if entries[i].Target != entries[j].Target {
					return entries[i].Target < entries[j].Target
				}
				return entries[i].Subtarget < entries[j].Subtarget
			})
			
			for _, e := range entries {
				fmt.Printf("%s %s %s\n", e.Ver, e.Target, e.Subtarget)
			}
			fmt.Printf("-------------------------\n")
			fmt.Printf("总计：%d 个配置\n", len(entries))
			return nil
		}

		// 在线检索
		fmt.Printf("检索 OpenWrt 版本列表（镜像：%s）...\n", mirror)
		resp, err := httpGet(mirror)
		if err != nil {
			return fmt.Errorf("获取版本列表失败: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		// 修复的正则：支持绝对路径和相对路径的版本号匹配
		reVer := regexp.MustCompile(`href="(?:[^"]*/)?((?:\d+\.)+\d+)/"`)
		matches := reVer.FindAllStringSubmatch(string(body), -1)

		versions := make(map[string]bool)
		for _, m := range matches {
			if len(m) > 1 {
				versions[m[1]] = true
			}
		}

		if len(versions) == 0 {
			return fmt.Errorf("未能检索到版本列表")
		}

		fmt.Println("OpenWrt 版本列表：")
		var sortedVers []string
		for v := range versions {
			sortedVers = append(sortedVers, v)
		}
		sort.Strings(sortedVers)
		for _, v := range sortedVers {
			fmt.Printf("  %s\n", v)
		}
		return nil
	}

	// 有版本，无目标：列出目标
	if target == "" {
		if len(cacheEntries) > 0 {
			targets := make(map[string]bool)
			for _, e := range cacheEntries {
				if e.Ver == ver {
					targets[e.Target] = true
				}
			}
			if len(targets) > 0 {
				fmt.Printf("版本 %s 的目标列表（缓存）：\n", ver)
				for t := range targets {
					fmt.Printf("  %s\n", t)
				}
				return nil
			}
		}

		url := fmt.Sprintf("%s/%s/targets/", mirror, ver)
		fmt.Printf("检索版本 %s 的目标列表...\n", ver)
		resp, err := httpGet(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		// 支持绝对路径和相对路径
		reTarget := regexp.MustCompile(`href="(?:[^"]*/)?((?:[^/"]+))/"`)
		matches := reTarget.FindAllStringSubmatch(string(body), -1)

		targets := make(map[string]bool)
		for _, m := range matches {
			if len(m) > 1 && m[1] != ".." {
				targets[m[1]] = true
			}
		}

		fmt.Printf("版本 %s 的目标列表：\n", ver)
		for t := range targets {
			fmt.Printf("  %s\n", t)
		}
		return nil
	}

	// 有版本和目标，无子目标：列出子目标
	if subtarget == "" {
		url := fmt.Sprintf("%s/%s/targets/%s/", mirror, ver, target)
		fmt.Printf("检索版本 %s 目标 %s 的子目标列表...\n", ver, target)
		resp, err := httpGet(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		// 支持绝对路径和相对路径的子目标匹配
		reSubtarget := regexp.MustCompile(`href="(?:[^"]*/)?((?:[^/"]+))/"`)
		matches := reSubtarget.FindAllStringSubmatch(string(body), -1)

		subtargets := make(map[string]bool)
		for _, m := range matches {
			if len(m) > 1 && m[1] != ".." {
				subtargets[m[1]] = true
			}
		}

		fmt.Printf("版本 %s 目标 %s 的子目标列表：\n", ver, target)
		for s := range subtargets {
			fmt.Printf("  %s\n", s)
		}
		return nil
	}

	// 完整参数：列出SDK包
	url := fmt.Sprintf("%s/%s/targets/%s/%s/", mirror, ver, target, subtarget)
	fmt.Printf("检索 SDK 列表：%s\n", url)
	resp, err := httpGet(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// 修复的正则：更精确的SDK包名匹配，排除空格
	rePkg := regexp.MustCompile(`openwrt-sdk-[^"'<>\s]+\.tar\.(xz|gz)`)
	matches := rePkg.FindAllString(string(body), -1)

	pkgs := make(map[string]bool)
	for _, m := range matches {
		pkgs[m] = true
	}

	if len(pkgs) == 0 {
		return fmt.Errorf("未找到 SDK 包")
	}

	fmt.Println("SDK 列表：")
	for p := range pkgs {
		fmt.Printf("  %s\n", p)
	}
	return nil
}

// 交互式选择编译器
func interactiveChooseName() (string, error) {
	entries, err := listRegistry()
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("无已注册的编译器")
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\n请输入：")
		fmt.Println("  1. 搜索关键词（回车列出全部）")
		fmt.Println("  2. 编号（直接选择编译器）")
		fmt.Print("输入：")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Println("\n编译器列表：")
			for i, name := range names {
				fmt.Printf("  %d) %s\n", i+1, name)
			}
			continue
		}

		// 数字选择
		if idx, err := strconv.Atoi(input); err == nil {
			if idx >= 1 && idx <= len(names) {
				return names[idx-1], nil
			}
			fmt.Println("错误：无效的编号")
			continue
		}

		// 关键词过滤
		filter := strings.ToLower(input)
		var hits []struct {
			Index int
			Name  string
		}
		for i, name := range names {
			if strings.Contains(strings.ToLower(name), filter) {
				hits = append(hits, struct {
					Index int
					Name  string
				}{i + 1, name})
			}
		}

		if len(hits) == 0 {
			fmt.Println("警告：未匹配到任何编译器")
			continue
		}

		fmt.Println("\n匹配结果：")
		for _, h := range hits {
			fmt.Printf("  %d) %s\n", h.Index, h.Name)
		}

		fmt.Print("输入编号选择（或回车返回上一级）：")
		pick, _ := reader.ReadString('\n')
		pick = strings.TrimSpace(pick)

		if pick == "" {
			continue
		}

		if idx, err := strconv.Atoi(pick); err == nil {
			for _, h := range hits {
				if h.Index == idx {
					return h.Name, nil
				}
			}
			fmt.Println("错误：无效的编号")
		}
	}
}

// 命令：use
func cmdUse(args []string) error {
	var name string
	var err error

	if len(args) < 2 {
		name, err = interactiveChooseName()
		if err != nil {
			return err
		}
	} else {
		name = args[1]
	}

	linkPath := filepath.Join(gConfig.Registry, name)
	if !pathExists(linkPath) {
		return fmt.Errorf("编译器不存在: %s", name)
	}

	realDir, err := os.Readlink(linkPath)
	if err != nil {
		return fmt.Errorf("读取符号链接失败: %w", err)
	}

	binDir, err := findToolchainBin(realDir)
	if err != nil {
		return fmt.Errorf("编译器目录无效: %w", err)
	}

	currentPath := os.Getenv("PATH")
	if currentPath == "" {
		currentPath = gConfig.BaseSysPath
	}

	// 移除旧的bin目录
	newPath := strings.ReplaceAll(currentPath, binDir+":", "")
	newPath = strings.ReplaceAll(newPath, ":"+binDir, "")
	if newPath == binDir {
		newPath = ""
	}

	// 前置新bin目录
	newPath = binDir + ":" + newPath
	newPath = dedupBasePath(newPath)

	// 写入rc文件
	rcContent := fmt.Sprintf("# 由 ccvm 自动生成，执行 source %s 生效\nexport PATH=\"%s\"\n",
		gConfig.RcFile, newPath)
	if err := ioutil.WriteFile(gConfig.RcFile, []byte(rcContent), 0644); err != nil {
		return fmt.Errorf("写入rc文件失败: %w", err)
	}

	fmt.Printf("成功切换编译器：%s\n", name)
	fmt.Printf("  路径：%s\n", realDir)
	fmt.Printf("  Bin目录：%s\n", binDir)
	fmt.Println("\n请执行以下命令使环境生效：")
	fmt.Printf("  source %s\n", gConfig.RcFile)
	return nil
}

// 命令：current
func cmdCurrent() error {
	if !pathExists(gConfig.RcFile) {
		fmt.Println("当前未激活任何交叉编译器")
		return nil
	}

	content, err := ioutil.ReadFile(gConfig.RcFile)
	if err != nil {
		return fmt.Errorf("无法读取rc文件: %w", err)
	}

	rePath := regexp.MustCompile(`export PATH="([^"]+)"`)
	matches := rePath.FindStringSubmatch(string(content))
	if matches == nil {
		fmt.Println("当前未激活任何交叉编译器")
		return nil
	}

	pathValue := matches[1]
	binDir := strings.Split(pathValue, ":")[0]

	entries, err := listRegistry()
	if err != nil {
		return err
	}

	compilerName := "未知"
	compilerPath := "未知"
	for _, e := range entries {
		if eBin, err := findToolchainBin(e.Target); err == nil && eBin == binDir {
			compilerName = e.Name
			compilerPath = e.Target
			break
		}
	}

	fmt.Println("当前激活的交叉编译器：")
	fmt.Printf("  名称：%s\n", compilerName)
	fmt.Printf("  路径：%s\n", compilerPath)
	fmt.Printf("  Bin目录：%s\n", binDir)
	return nil
}

// 命令：delete
func cmdDelete(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("用法：delete <名称> [--remove-dir]")
	}

	name := args[1]
	removeDir := false
	for i := 2; i < len(args); i++ {
		if args[i] == "--remove-dir" {
			removeDir = true
		}
	}

	linkPath := filepath.Join(gConfig.Registry, name)
	if !pathExists(linkPath) {
		return fmt.Errorf("编译器不存在: %s", name)
	}

	realDir, err := os.Readlink(linkPath)
	if err != nil {
		return fmt.Errorf("读取符号链接失败: %w", err)
	}

	fmt.Printf("确认删除编译器 \"%s\" 吗？\n", name)
	fmt.Printf("  注册路径：%s\n", linkPath)
	fmt.Printf("  真实路径：%s\n", realDir)
	if removeDir {
		fmt.Println("  （将同时删除真实目录）")
	}
	fmt.Print("输入 y 确认，其他取消：")

	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Println("操作已取消")
		return nil
	}

	if err := os.Remove(linkPath); err != nil {
		return fmt.Errorf("删除注册失败: %w", err)
	}
	fmt.Printf("已删除注册：%s\n", name)

	if removeDir {
		fmt.Println("正在删除真实目录...")
		if err := os.RemoveAll(realDir); err != nil {
			return fmt.Errorf("删除真实目录失败: %w", err)
		}
		fmt.Printf("已删除真实目录：%s\n", realDir)
	}

	return nil
}

// 命令：download
func cmdDownload(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("用法：download <版本> <目标> <子目标> [--mirror <镜像地址>]")
	}

	ver := args[1]
	target := args[2]
	subtarget := args[3]
	mirror := gConfig.DefaultMirror

	for i := 4; i < len(args); i++ {
		if args[i] == "--mirror" && i+1 < len(args) {
			mirror = args[i+1]
			i++
		}
	}

	// 查找SDK文件名
	sdkURL := fmt.Sprintf("%s/%s/targets/%s/%s/", mirror, ver, target, subtarget)
	fmt.Printf("检索 SDK：%s\n", sdkURL)

	resp, err := httpGet(sdkURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	rePkg := regexp.MustCompile(`openwrt-sdk-[^"'<>]+\.tar\.(xz|gz)`)
	matches := rePkg.FindString(string(body))

	if matches == "" {
		return fmt.Errorf("未找到 SDK 包")
	}

	filename := matches
	outPath := filepath.Join(gConfig.ToolchainBase, filename)

	if pathExists(outPath) {
		fmt.Printf("文件已存在：%s\n", outPath)
		fmt.Print("是否覆盖？(y/N)：")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			fmt.Println("操作已取消")
			return nil
		}
	}

	// 下载SDK
	fullURL := sdkURL + filename
	fmt.Printf("使用 wget 下载：%s\n", fullURL)
	downloadCmd := fmt.Sprintf("wget -c --progress=bar:force '%s' -O '%s'", fullURL, outPath)
	if err := runCommand(downloadCmd, false); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	// 解压SDK
	fmt.Printf("解压 SDK：%s\n", filename)
	extractCmd := fmt.Sprintf("tar -C '%s' -xf '%s'", gConfig.ToolchainBase, outPath)
	if err := runCommand(extractCmd, false); err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}

	// 查找解压后的目录
	listCmd := fmt.Sprintf("tar -tf '%s' | head -n 1", outPath)
	tarList, _ := runCapture(listCmd)
	tarList = strings.TrimSpace(strings.TrimRight(tarList, "/"))
	sdkDir := filepath.Join(gConfig.ToolchainBase, tarList)

	if !pathExists(sdkDir) {
		return fmt.Errorf("无法识别解压后的目录")
	}

	// 注册SDK
	addArgs := []string{"add", sdkDir}
	if err := cmdAdd(addArgs); err != nil {
		return err
	}

	fmt.Println("\n下载并注册完成！")
	fmt.Printf("SDK 目录：%s\n", sdkDir)
	return nil
}

// 命令：fetch
func cmdFetch(args []string) error {
	mirror := gConfig.DefaultMirror
	rsyncURL := ""
	maxWorkers := runtime.NumCPU() * 4
	if maxWorkers < 4 {
		maxWorkers = 4
	}

	// 解析参数
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--mirror":
			if i+1 < len(args) {
				mirror = args[i+1]
				i++
			}
		case "--rsync":
			if i+1 < len(args) {
				rsyncURL = args[i+1]
				i++
			}
		case "--jobs":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					maxWorkers = n
				}
				i++
			}
		}
	}

	// 推导rsync地址
	if rsyncURL == "" {
		if strings.HasPrefix(mirror, "http://") {
			rsyncURL = "rsync://" + strings.TrimPrefix(mirror, "http://")
		} else if strings.HasPrefix(mirror, "https://") {
			rsyncURL = "rsync://" + strings.TrimPrefix(mirror, "https://")
		} else if strings.HasPrefix(mirror, "rsync://") {
			rsyncURL = mirror
		}
		if rsyncURL != "" && !strings.HasSuffix(rsyncURL, "/") {
			rsyncURL += "/"
		}
	}

	// 检查rsync可用性
	useRsync := false
	if out, err := runCapture("which rsync"); err == nil && strings.TrimSpace(out) != "" && rsyncURL != "" {
		fmt.Println("测试 rsync 连接...")
		testCmd := fmt.Sprintf("timeout 5 rsync --list-only '%s' 2>&1", rsyncURL)
		testResult, _ := runCapture(testCmd)
		if !strings.Contains(testResult, "failed to connect") &&
			!strings.Contains(testResult, "timed out") &&
			!strings.Contains(testResult, "unreachable") {
			useRsync = true
			fmt.Printf("使用 rsync 加速获取：%s\n", rsyncURL)
		} else {
			fmt.Println("rsync 连接失败，切换到 HTTP 模式")
		}
	}

	if !useRsync {
		fmt.Printf("使用 HTTP 获取：%s\n", mirror)
	}

	// 获取版本列表
	fmt.Println("获取版本列表...")
	resp, err := httpGet(mirror)
	if err != nil {
		return fmt.Errorf("获取版本列表失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// 支持绝对路径和相对路径的版本号匹配
	reVer := regexp.MustCompile(`href="(?:[^"]*/)?((?:\d+\.)+\d+)/"`)
	matches := reVer.FindAllStringSubmatch(string(body), -1)

	versions := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			versions[m[1]] = true
		}
	}

	if len(versions) == 0 {
		return fmt.Errorf("未能获取版本列表")
	}

	fmt.Printf("发现 %d 个版本，开始获取...\n", len(versions))

	// 并行处理版本
	var allEntries []CacheEntry
	var entriesMtx sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)
	processed := 0
	var processedMtx sync.Mutex

	rePkg := regexp.MustCompile(`openwrt-sdk-[^/\s]+\.tar\.(xz|gz)`)

	for v := range versions {
		wg.Add(1)
		go func(ver string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var entries []CacheEntry

			if useRsync {
				// 使用rsync递归获取
				rsyncPath := rsyncURL + ver + "/targets/"
				items, err := runRsyncRecursiveList(rsyncPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "警告：版本 %s rsync 获取失败: %v\n", ver, err)
					return
				}

				targetSubtargetPkgs := make(map[string]map[string]map[string]bool)

				for _, item := range items {
					parts := strings.Split(item, "/")
					if len(parts) >= 3 && rePkg.MatchString(parts[len(parts)-1]) {
						t := parts[0]
						s := parts[1]
						if targetSubtargetPkgs[t] == nil {
							targetSubtargetPkgs[t] = make(map[string]map[string]bool)
						}
						if targetSubtargetPkgs[t][s] == nil {
							targetSubtargetPkgs[t][s] = make(map[string]bool)
						}
						targetSubtargetPkgs[t][s][parts[len(parts)-1]] = true
					}
				}

				for t, sMap := range targetSubtargetPkgs {
					for s, pkgs := range sMap {
						var pkgList []string
						for pkg := range pkgs {
							pkgList = append(pkgList, pkg)
						}
						entries = append(entries, CacheEntry{
							Ver:       ver,
							Target:    t,
							Subtarget: s,
							Pkgs:      pkgList,
						})
					}
				}
			} else {
				// HTTP方式获取
				targetURL := fmt.Sprintf("%s/%s/targets/", mirror, ver)
				resp, err := httpGet(targetURL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "警告：版本 %s 获取失败: %v\n", ver, err)
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
			// 支持绝对路径和相对路径的target匹配
				reTarget := regexp.MustCompile(`href="(?:[^"]*/)?((?:[^/"]+))/"`)
				targetMatches := reTarget.FindAllStringSubmatch(string(body), -1)

				for _, tm := range targetMatches {
					if len(tm) < 2 || tm[1] == ".." {
						continue
					}
					t := tm[1]

					subtargetURL := fmt.Sprintf("%s/%s/targets/%s/", mirror, ver, t)
					resp2, err := httpGet(subtargetURL)
					if err != nil {
						continue
					}

					body2, _ := io.ReadAll(resp2.Body)
					resp2.Body.Close()
					
					// 子目标也需要处理绝对路径
					reSubtarget := regexp.MustCompile(`href="(?:[^"]*/)?((?:[^/"]+))/"`)
					subtargetMatches := reSubtarget.FindAllStringSubmatch(string(body2), -1)
					for _, sm := range subtargetMatches {
						if len(sm) < 2 || sm[1] == ".." {
							continue
						}
						s := sm[1]

						pkgURL := fmt.Sprintf("%s/%s/targets/%s/%s/", mirror, ver, t, s)
						resp3, err := httpGet(pkgURL)
						if err != nil {
							continue
						}

						body3, _ := io.ReadAll(resp3.Body)
						resp3.Body.Close()

						pkgMatches := rePkg.FindAllString(string(body3), -1)
						if len(pkgMatches) > 0 {
							pkgs := make(map[string]bool)
							for _, pkg := range pkgMatches {
								pkgs[pkg] = true
							}
							var pkgList []string
							for pkg := range pkgs {
								pkgList = append(pkgList, pkg)
							}
							entries = append(entries, CacheEntry{
								Ver:       ver,
								Target:    t,
								Subtarget: s,
								Pkgs:      pkgList,
							})
						}
					}
				}
			}

			entriesMtx.Lock()
			allEntries = append(allEntries, entries...)
			entriesMtx.Unlock()

			processedMtx.Lock()
			processed++
			fmt.Printf("进度：[%d/%d] 版本 %s 完成，获取 %d 条记录\n", processed, len(versions), ver, len(entries))
			processedMtx.Unlock()
		}(v)
	}

	wg.Wait()

	// 保存缓存
	cacheSuffix := urlToSafeFilename(mirror)
	cacheFile := filepath.Join(gConfig.CCVMHome, "online_cache_"+cacheSuffix+".json")
	if err := saveCacheNDJSON(cacheFile, allEntries); err != nil {
		return fmt.Errorf("保存缓存失败: %w", err)
	}

	fmt.Println("\n获取完成！")
	fmt.Printf("总计获取 %d 条记录\n", len(allEntries))
	fmt.Printf("缓存文件：%s\n", cacheFile)
	return nil
}

// 命令：gcc/g++ - 直接调用激活的编译器
func cmdCompiler(compiler string, args []string) error {
	// 读取 rc 文件获取 PATH
	if !pathExists(gConfig.RcFile) {
		return fmt.Errorf("未激活任何编译器，请先执行 ccvm use")
	}

	content, err := ioutil.ReadFile(gConfig.RcFile)
	if err != nil {
		return fmt.Errorf("无法读取 rc 文件: %w", err)
	}

	rePath := regexp.MustCompile(`export PATH="([^"]+)"`)
	matches := rePath.FindStringSubmatch(string(content))
	if matches == nil {
		return fmt.Errorf("无法获取编译器路径")
	}

	// 临时设置 PATH
	newPath := matches[1]
	os.Setenv("PATH", newPath)

	// 构建命令，将所有参数传递给编译器
	cmdArgs := []string{compiler}
	if len(args) > 1 {
		cmdArgs = append(cmdArgs, args[1:]...)
	}

	// 执行编译器
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func cmdGcc(args []string) error {
	return cmdCompiler("gcc", args)
}

func cmdGxx(args []string) error {
	return cmdCompiler("g++", args)
}

// 命令：help
func cmdHelp(prog string) {
	fmt.Println("ccvm - 多交叉编译器版本管理工具")
	fmt.Println("=============================================")
	fmt.Println("用法：")
	fmt.Printf("  %s add <toolchain目录>        注册工具链\n", prog)
	fmt.Printf("  %s list                       列出已注册的编译器\n", prog)
	fmt.Printf("  %s list --online [参数]       在线检索编译器列表\n", prog)
	fmt.Println("      可选参数：<版本> <目标> <子目标> --mirror <镜像> --no-cache")
	fmt.Printf("  %s use [名称]                 切换活跃编译器\n", prog)
	fmt.Printf("  %s current                    显示当前激活的编译器\n", prog)
	fmt.Printf("  %s delete <名称> [--remove-dir] 删除编译器\n", prog)
	fmt.Printf("  %s download <版本> <目标> <子目标> [--mirror <镜像>] 下载并注册SDK\n", prog)
	fmt.Printf("  %s fetch [选项]               获取并缓存在线数据\n", prog)
	fmt.Println("      选项：--mirror <镜像> --rsync <地址> --jobs <并发数>")
	fmt.Printf("  %s help                       显示此帮助信息\n", prog)
	fmt.Println()
	fmt.Printf("默认镜像：%s\n", gConfig.DefaultMirror)
	fmt.Printf("配置目录：%s\n", gConfig.CCVMHome)
	fmt.Printf("工具链目录：%s\n", gConfig.ToolchainBase)
}

func main() {
	// 确保目录存在
	if err := ensureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}

	args := os.Args
	if len(args) < 2 {
		cmdHelp(args[0])
		return
	}

	cmd := args[1]
	var err error

	switch cmd {
	case "add":
		err = cmdAdd(args[1:])
	case "list":
		if len(args) > 2 && args[2] == "--online" {
			err = cmdListOnline(args[1:])
		} else {
			err = cmdList()
		}
	case "use":
		err = cmdUse(args[1:])
	case "current":
		err = cmdCurrent()
	case "delete":
		err = cmdDelete(args[1:])
	case "download":
		err = cmdDownload(args[1:])
	case "fetch":
		err = cmdFetch(args[1:])
	case "help":
		cmdHelp(args[0])
	default:
		fmt.Fprintf(os.Stderr, "错误：未知命令 - %s\n", cmd)
		cmdHelp(args[0])
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}
