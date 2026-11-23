package daemon

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"napoli/lib/common"
)

func InitDaemon(f string, runPath string, pidPath string) {
	if len(os.Args) < 2 {
		return
	}
	var args []string
	args = append(args, os.Args[0])
	if len(os.Args) >= 2 {
		args = append(args, os.Args[2:]...)
	}
	args = append(args, "-log=file")
	switch os.Args[1] {
	case "start":
		start(args, f, pidPath, runPath)
		os.Exit(0)
	case "stop":
		stop(f, args[0], pidPath)
		os.Exit(0)
	case "restart":
		stop(f, args[0], pidPath)
		start(args, f, pidPath, runPath)
		os.Exit(0)
	case "status":
		if status(f, pidPath) {
			log.Printf("%s is running", f)
		} else {
			log.Printf("%s is not running", f)
		}
		os.Exit(0)
	case "reload":
		reload(f, pidPath)
		os.Exit(0)
	}
}

// readPID 读取 pid 文件并校验内容是合法进程号。
// 原实现把文件内容直接拼进 /bin/bash -c，pid 文件一旦被写入非数字内容
// 就等同于命令注入，这里只接受正整数。
func readPID(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid pid file content")
	}
	return pid, nil
}

func reload(f string, pidPath string) {
	// 原写法把进程名写死成 "nps"，改名后这个前置检查会被静默跳过，
	// 于是没在运行时也会去 kill 一个过期 pid。这里不再绑定具体名字。
	if !common.IsWindows() && !status(f, pidPath) {
		log.Println("reload fail")
		return
	}
	pid, err := readPID(filepath.Join(pidPath, f+".pid"))
	if err != nil {
		log.Fatalln("reload error,pid file does not exist")
	}
	// 直接调用 kill，不经 shell 解释，参数不会被拼接执行。
	if err := exec.Command("kill", "-30", strconv.Itoa(pid)).Run(); err == nil {
		log.Println("reload success")
	} else {
		log.Println("reload fail")
	}
}

func status(f string, pidPath string) bool {
	pid, err := readPID(filepath.Join(pidPath, f+".pid"))
	if err != nil {
		return false
	}
	if common.IsWindows() {
		// tasklist 按 PID 精确筛选，避免原实现 grep 子串匹配带来的误判。
		out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/NH").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), strconv.Itoa(pid))
	}
	// 信号 0 不投递信号，只做存在性检查，比 grep ps 输出更准确，
	// 也不会把子串相同的无关进程误判为目标进程。
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		// EPERM 说明进程存在但当前用户无权操作，仍算运行中。
		return errors.Is(err, syscall.EPERM)
	}
	return true
}

func start(osArgs []string, f string, pidPath, runPath string) {
	if status(f, pidPath) {
		log.Printf(" %s is running", f)
		return
	}
	cmd := exec.Command(osArgs[0], osArgs[1:]...)
	cmd.Start()
	if cmd.Process.Pid > 0 {
		log.Println("start ok , pid:", cmd.Process.Pid, "config path:", runPath)
		d1 := []byte(strconv.Itoa(cmd.Process.Pid))
		os.WriteFile(filepath.Join(pidPath, f+".pid"), d1, 0600)
	} else {
		log.Println("start error")
	}
}

func stop(f string, p string, pidPath string) {
	if !status(f, pidPath) {
		log.Printf(" %s is not running", f)
		return
	}
	var c *exec.Cmd
	if common.IsWindows() {
		p := strings.Split(p, `\`)
		c = exec.Command("taskkill", "/F", "/IM", p[len(p)-1])
	} else {
		pid, err := readPID(filepath.Join(pidPath, f+".pid"))
		if err != nil {
			log.Fatalln("stop error,pid file does not exist")
		}
		c = exec.Command("kill", "-9", strconv.Itoa(pid))
	}
	if err := c.Run(); err != nil {
		log.Println("stop error,", err)
	} else {
		log.Println("stop ok")
	}
}
