package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	libseccomp "github.com/seccomp/libseccomp-golang"	
)

func main() {
	var regs syscall.PtraceRegs

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}
	cmd.Start()
	if cmd.Process == nil {
		fmt.Fprintf(os.Stderr, "Failed to start command: %s\n", os.Args[1:])
		os.Exit(2)
	}
	err := cmd.Wait()
	if err == nil {
		panic("Failed to wait for  command: %s")
	}

	pid := cmd.Process.Pid
	exit := true

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}

			name, _ := libseccomp.ScmpSyscall(regs.Orig_rax).GetName()
			fmt.Printf("%d %s\n", regs.Orig_rax, name)

		}

		name, _ := libseccomp.ScmpSyscall(regs.Orig_rax).GetName()
		fmt.Printf("%d %s\n", regs.Orig_rax, name)
		
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			panic(err)
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			fmt.Printf("failed\n")
			panic(err)
		}

		exit = !exit
	}
}
