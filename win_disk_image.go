package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/tidwall/gjson"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-cmd/cmd"
	"github.com/kr/pretty"
	"github.com/rekby/mbr"
	"github.com/shirou/gopsutil/disk"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const VShadowExecutor = `vshadow.exe`

const VssTypeDataVolumeRollback = "DataVolumeRollback"

var DiskNumber = flag.Int("disk_number", 0, "for making disk image")

var RegexOriginalVolume = regexp.MustCompile(`\\\\\?\\Volume{(?P<VID>.*?)}\\.*?\[(?P<VOL>\w+):\\\]`)

// ShadowCopyIns 卷影副本结构
type ShadowCopyIns struct {
	DriveLetter   string `json:"vol_letter"`       // Disk letter
	VolID         string `json:"vol_id"`           // Disk identification
	SnapID        string `json:"snap_id"`          // shadow copy ID
	Valid         bool   `json:"existed"`          // Whether the creation is successful
	SCopyPath     string `json:"shadow_copy_path"` // Shadow copy volume name, for example "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5"
	OriginMachine string `json:"origin_machine"`   // Originating machine
	ServerMachine string `json:"server_machine"`   // Service machine
	CreationTime  string `json:"creation_time"`    // Creation time
	Provider      string `json:"provider"`         // Provider
	Type          string `json:"type"`             // Shadow copy type
	Attribute     string `json:"attribute"`        // Attributes, such as “持续|无自动释放|差异”
	Size          uint64 `json:"size"`             // Shadow size
	SizeHuman     string `json:"size_human"`       // readable size
}

func Process(caller, args string) (r int, out string, err error) {
	cs := strings.Fields(args)
	if len(cs) > 0 {
		for i := 0; i < len(cs[1:]); i++ {
			cs[i] = strings.Trim(cs[i], "\"")
		}
	}
	c := cmd.NewCmd(caller, cs...)
	s := <-c.Start()
	out = strings.Join(s.Stdout, "\n")
	ob, err := GBK2UTF8([]byte(out))
	if err == nil {
		out = string(ob)
	}
	return s.Exit, out, s.Error
}

type PowerShell struct {
	powerShell string
}

func NewPS() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

func (p *PowerShell) Execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd_ := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd_.Stdout = &stdout
	cmd_.Stderr = &stderr

	err = cmd_.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return
}

func QueryDiskInfo(DiskNo int) (info string, err error) {
	ps := NewPS()

	script := fmt.Sprintf("Get-Disk -Number %v "+
		"| select-object -property IsBoot,IsClustered,IsSystem,FriendlyName,PartitionStyle,BusType,BootFromDisk,Size,SerialNumber,PhysicalSectorSize | convertto-json", DiskNo)
	info, erro, err := ps.Execute(script)
	if err != nil {
		return "", err
	}
	if erro != "" {
		return "", errors.New("failed to query disk")
	}
	return info, err
}

func QueryAllPartitionsOnDisk(DiskNo int) (info string, err error) {
	ps := NewPS()
	script := fmt.Sprintf("Get-Partition -DiskNumber %v"+
		" | Select-Object -property DiskNumber,PartitionNumber,DriveLetter,IsOffline,IsBoot,IsSystem,IsHidden,DiskID"+
		" | ConvertTo-JSON", DiskNo)
	info, erro, err := ps.Execute(script)
	if err != nil {
		return "", err
	}
	if erro != "" {
		return "", errors.New("failed to query partitions")
	}
	return info, err
}

func QueryVolumeByLetter(DriveLetter string) (info string, err error) {
	ps := NewPS()
	script := fmt.Sprintf(
		"Get-Volume -DriveLetter %v"+
			" | Select-Object -property filesystem"+
			" | Convertto-JSON", DriveLetter)
	info, erro, err := ps.Execute(script)
	if err != nil {
		return "", err
	}
	if erro != "" {
		return "", errors.New("failed to query volume")
	}
	return info, err
}

func VolumeUsage(letter string) (va *disk.UsageStat, err error) {
	parts, err := disk.Partitions(true)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		if !strings.HasPrefix(part.Device, strings.ToUpper(letter)) {
			continue
		}
		va, err = disk.Usage(part.Mountpoint)
		return
	}
	return nil, errors.New("volume usage not fount")
}

func GBK2UTF8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func HumanizeBytes(bytesNum int64) string {
	var size string

	if valPB := bytesNum / (1 << 50); valPB != 0 {
		num1, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(bytesNum)/float64(1<<50)), 64)
		size = fmt.Sprintf("%vPB", num1)
	} else if valTB := bytesNum / (1 << 40); valTB != 0 {
		num2, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(bytesNum)/float64(1<<40)), 64)
		size = fmt.Sprintf("%vTB", num2)
	} else if valGB := bytesNum / (1 << 30); valGB != 0 {
		num3, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(bytesNum)/float64(1<<30)), 64)
		size = fmt.Sprintf("%vGB", num3)
	} else if valMB := bytesNum / (1 << 20); valMB != 0 {
		num4, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(bytesNum)/float64(1<<20)), 64)
		size = fmt.Sprintf("%vMB", num4)
	} else if valKB := bytesNum / (1 << 10); valKB != 0 {
		num5, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(bytesNum)/float64(1<<10)), 64)
		size = fmt.Sprintf("%vKB", num5)
	} else {
		size = fmt.Sprintf("%vB", bytesNum)
	}

	return size
}

func CreateVSS(letter string) (sci ShadowCopyIns, err error) {
	var args string
	var r int
	var o string

	if !strings.HasSuffix(letter, ":") {
		letter += ":"
	}
	args = fmt.Sprintf(`-p -nw %v`, letter)
	sci.Type = VssTypeDataVolumeRollback

	r, o, err = Process(VShadowExecutor, args)
	if r != 0 {
		err = fmt.Errorf("failed to create shadow copy(letter=`%s`) args=`%v` out=%v err=%v", letter, args, o, err)
		return
	}
	if err != nil {
		return sci, err
	}

	for _, line := range strings.Split(o, "\n") {
		line = strings.TrimSpace(line)
		if !(strings.Contains(line, "SNAPSHOT ID")) {
			continue
		}
		snap := strings.Fields(line)[4]
		if snap == "" {
			err = fmt.Errorf(`can't find snap id from "%s"`, snap)
			return
		}
		sci, err = DetailVSS(snap)
		if err != nil {
			return
		}
		return
	}
	err = fmt.Errorf("failed to create shadow copy(letter=`%s`), err=key information was not resolved",
		letter)
	return
}

func DetailVSS(snap string) (sci ShadowCopyIns, err error) {
	cs := fmt.Sprintf(`-s=%s`, snap)
	r, o, err := Process(VShadowExecutor, cs)
	if r != 0 {
		err = fmt.Errorf("failed to detail shadow copy(id=`%s`) out=%s err=%v", snap, o, err)
		return
	}
	if err != nil {
		return sci, err
	}
	__splitter := func(__line string) string {
		return strings.TrimSpace(strings.Split(__line, ":")[1])
	}

	lines := strings.Split(o, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, snap) {
			continue
		}
		match := RegexOriginalVolume.FindStringSubmatch(lines[i+3])
		if len(match) == 1 || len(match) != 3 {
			errMsg := fmt.Sprintf("why not match `%v` from `%v`", RegexOriginalVolume, line[i+3])
			return sci, errors.New(errMsg)
		}
		sci.Valid = true
		sci.DriveLetter = match[2]
		sci.VolID = fmt.Sprintf("{%s}", match[1])
		sci.SnapID = snap
		sci.CreationTime = strings.TrimPrefix(strings.TrimSpace(lines[i+4]), "- Creation Time: ")
		sci.SCopyPath = __splitter(lines[i+5])
		sci.OriginMachine = __splitter(lines[i+6])
		sci.ServerMachine = __splitter(lines[i+7])
		sci.Provider = __splitter(lines[i+9])
		sci.Type = VssTypeDataVolumeRollback
		sci.Attribute = __splitter(lines[i+10])

		va, e := VolumeUsage(sci.DriveLetter)
		if e == nil {
			sci.Size = va.Total
			sci.SizeHuman = HumanizeBytes(int64(sci.Size))
		}
	}
	return
}

func DeleteVSS(snap string) (err error) {
	cs := fmt.Sprintf(` -ds=%s`, snap)
	r, o, err := Process(VShadowExecutor, cs)
	if r != 0 {
		err = fmt.Errorf("failed to delete shadow copy(id=`%s`) out=%s err=%v", snap, o, err)
		return
	}
	return nil
}

func GetDiskPathByNumber(number int) string {
	return fmt.Sprintf("\\\\.\\PhysicalDrive%v", number)
}

func ParseMBRPartitionTable(r *os.File) (p *mbr.MBR, err error) {
	return mbr.Read(r)
}

func GetNotEmptyPartitionCount(header *mbr.MBR) (count int) {
	for i := 0; i < len(header.GetAllPartitions()); i++ {
		p := header.GetAllPartitions()[i]
		if !p.IsEmpty() {
			count += 1
		}
	}
	return
}

type PartitionInfo struct {
	DiskNumber           int64
	PartNumber           int64
	IsOffline            bool
	IsBoot               bool
	IsSystem             bool
	IsHidden             bool
	DiskID               string
	StartLBA             uint32
	EndLBA               uint32
	LBALen               uint32
	DriveLetter          string
	SupportVss           bool
	RecentShadowCopyID   string
	RecentShadowCopyPath string
}

func AnalysisPartitionFilesystem(ps string, header *mbr.MBR) (pis []*PartitionInfo, err error) {
	if !gjson.Valid(ps) {
		return nil, errors.New("invalid Get-Partition output")
	}
	for i := 0; i < GetNotEmptyPartitionCount(header); i++ {
		p := header.GetAllPartitions()[i]
		tmp := new(PartitionInfo)
		tmp.DiskNumber = gjson.Get(ps, fmt.Sprintf("%v.DiskNumber", i)).Int()
		tmp.PartNumber = gjson.Get(ps, fmt.Sprintf("%v.PartitionNumber", i)).Int()
		tmp.DriveLetter = gjson.Get(ps, fmt.Sprintf("%v.DriveLetter", i)).String()
		tmp.IsOffline = gjson.Get(ps, fmt.Sprintf("%v.IsOffline", i)).Bool()
		tmp.IsBoot = gjson.Get(ps, fmt.Sprintf("%v.IsBoot", i)).Bool()
		tmp.IsSystem = gjson.Get(ps, fmt.Sprintf("%v.IsSystem", i)).Bool()
		tmp.IsHidden = gjson.Get(ps, fmt.Sprintf("%v.IsHidden", i)).Bool()
		tmp.DiskID = gjson.Get(ps, fmt.Sprintf("%v.DiskID", i)).String()
		tmp.StartLBA = p.GetLBAStart()
		tmp.EndLBA = p.GetLBALast()
		tmp.LBALen = p.GetLBALen()

		if tmp.DriveLetter != "" {
			vi, e := QueryVolumeByLetter(tmp.DriveLetter)
			if e == nil {
				tmp.SupportVss = gjson.Get(vi, "filesystem").String() == "NTFS"
			}
		}
		pis = append(pis, tmp)
	}
	return pis, nil
}

func CreateSnapshotsOnParts(pis []*PartitionInfo) (err error) {
	success := make([]string, 0)
	defer func() {
		if err == nil {
			return
		}
		for _, id := range success {
			_ = DeleteVSS(id)
		}
	}()

	for _, p := range pis {
		if !p.SupportVss || p.DriveLetter == "" {
			continue
		}
		sci, err := CreateVSS(p.DriveLetter)
		if err != nil {
			return err
		}
		fmt.Printf("对盘【%v】创建卷影副本【%v】(ID=%v)\n", sci.DriveLetter, sci.SCopyPath, sci.SnapID)
		p.RecentShadowCopyID = sci.SnapID
		p.RecentShadowCopyPath = sci.SCopyPath
		success = append(success, p.RecentShadowCopyID)
	}
	return nil
}

func DeleteSnapshotsOnParts(pis []*PartitionInfo) (err error) {
	for _, p := range pis {
		if p.RecentShadowCopyID == "" {
			continue
		}
		_ = DeleteVSS(p.RecentShadowCopyID)
		fmt.Printf("对盘【%v】删除卷影副本%v\n", p.DriveLetter, p.RecentShadowCopyID)
	}
	return nil
}

func InitMirrorDisk(DiskSize int64, TargetDisk string) (err error) {
	target, err := os.OpenFile(TargetDisk, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = target.Truncate(DiskSize); err != nil {
		return
	}
	fi, _ := os.Stat(TargetDisk)
	fmt.Printf("初始化镜像磁盘文件%v, 源磁盘大小%v(%v)，镜像磁盘大小%v(%v)\n",
		TargetDisk, DiskSize, HumanizeBytes(DiskSize), fi.Size(), HumanizeBytes(fi.Size()))
	return nil
}

func CopyHeaderRawRegion2Mirror(
	DiskInfo string, pis []*PartitionInfo, OriginDisk, TargetDisk string) (err error) {
	_ = DiskInfo
	_ = pis
	// TODO support GPT
	origin, err := os.Open(OriginDisk)
	if err != nil {
		return err
	}
	defer origin.Close()
	target, err := os.OpenFile(TargetDisk, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer target.Close()

	// mbr header
	buffer := make([]byte, 512)
	_, err = origin.Read(buffer)
	if err != nil {
		return
	}
	_, err = target.Write(buffer)
	if err != nil {
		return
	}
	return nil
}

func CopyAllPartitionsRawRegion2Mirror(pis []*PartitionInfo, OriginDisk, TargetDisk string) (err error) {
	for _, p := range pis {
		if p.RecentShadowCopyID != "" {
			if err = CopyShadowCopy2Mirror(p, p.RecentShadowCopyPath, TargetDisk); err != nil {
				return
			}
		} else {
			if err = CopyNormalPart2Mirror(p, OriginDisk, TargetDisk); err != nil {
				return
			}
		}
	}
	return nil
}

func CopyShadowCopy2Mirror(pi *PartitionInfo, OriginDisk, TargetDisk string) (err error) {
	origin, err := os.Open(OriginDisk)
	if err != nil {
		return err
	}
	defer origin.Close()
	target, err := os.OpenFile(TargetDisk, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer target.Close()

	_, _ = target.Seek(int64(pi.StartLBA*512), io.SeekStart)
	n, _ := io.Copy(target, origin)

	fmt.Printf("基于卷影副本%v向%v(offset: %v)写入%v字节(%v)数据\n",
		OriginDisk, TargetDisk, pi.StartLBA*512, n, HumanizeBytes(n))
	return nil
}

func CopyNormalPart2Mirror(pi *PartitionInfo, OriginDisk, TargetDisk string) (err error) {
	origin, err := os.Open(OriginDisk)
	if err != nil {
		return err
	}
	defer origin.Close()
	target, err := os.OpenFile(TargetDisk, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer target.Close()

	sr := io.NewSectionReader(origin, int64(pi.StartLBA*512), int64(pi.LBALen*512))
	_, _ = target.Seek(int64(pi.StartLBA*512), io.SeekStart)
	n, _ := io.Copy(target, sr)

	fmt.Printf("基于%v（分区%v->%v）向%v(offset:%v)写入%v字节(%v)数据\n",
		OriginDisk, pi.StartLBA*512, pi.EndLBA*512, TargetDisk, pi.StartLBA*512, n, HumanizeBytes(n))
	return nil
}

func main() {
	flag.Parse()

	// 第一步 校验磁盘
	DiskPath := GetDiskPathByNumber(*DiskNumber)
	DiskPtr, _ := os.Open(DiskPath)
	defer DiskPtr.Close()
	GetDiskInfoOut, err := QueryDiskInfo(*DiskNumber)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:校验磁盘失败，原因:%v", err)
		return
	}
	GetPartitionsOut, err := QueryAllPartitionsOnDisk(*DiskNumber)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:校验分区失败，原因:%v", err)
		return
	}
	pretty.Logf("[1] 磁盘(%v)校验完成`%v`", DiskPath, GetDiskInfoOut)

	// 第二步 解析磁盘头信息
	// 分区项结构 （MBR前512字节、GPT前512 + 512 + 128*128字节）
	DiskHeader, err := ParseMBRPartitionTable(DiskPtr)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:解析磁盘头信息失败，原因:%v", err)
		return
	}
	pretty.Logf("[2] 磁盘头信息（MBR）解析完成")

	// 第三步 检测磁盘分区
	pis, err := AnalysisPartitionFilesystem(GetPartitionsOut, DiskHeader)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:检测磁盘分区失败，原因:%v", err)
		return
	}
	pretty.Log("[3] 检测磁盘分区完成, 得到各分区详细信息\n", pis)

	// 第四步 为磁盘下NTFS分区创建卷影副本
	err = CreateSnapshotsOnParts(pis)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:创建卷影副本集失败，原因:%v", err)
		return
	}
	pretty.Log("[4] 为磁盘下NTFS分区创建卷影副本完成")

	// 第五步 非分区的数据区（磁盘头、磁盘尾）按LBA写入目标映像文件
	DiskMirror := fmt.Sprintf("%v.raw", time.Now().Unix())
	err = InitMirrorDisk(gjson.Get(GetDiskInfoOut, "Size").Int(), DiskMirror)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:初始化镜像磁盘失败，原因:%v", err)
		return
	}
	err = CopyHeaderRawRegion2Mirror(GetDiskInfoOut, pis, DiskPath, DiskMirror)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:非分区的数据区写入目标映像文件失败，原因:%v", err)
		return
	}
	pretty.Log("[5] 非分区的数据区（磁盘头、磁盘尾）按LBA写入目标映像文件写入完成")

	// 第六步 分区数据按LBA写入目标映像文件（NTFS分区则基于其卷影副本写入）
	err = CopyAllPartitionsRawRegion2Mirror(pis, DiskPath, DiskMirror)
	if err != nil {
		_, _ = pretty.Fprintf(os.Stderr, "错误:写入磁盘分区至镜像失败，原因:%v", err)
		return
	}
	pretty.Log("[6] 分区数据按LBA写入目标映像文件完成")

	// 第七步 删除在NTFS分区创建的卷影副本
	_ = DeleteSnapshotsOnParts(pis)
	pretty.Log("[7] 磁盘下所有NTFS分区创建的卷影副本删除完成")

	// 第八步 得到RAW格式的目标映像文件
	fi, _ := os.Stat(DiskMirror)
	pretty.Logf("[8] 得到数据一致性的裸格式镜像磁盘%v, 镜像大小为%v字节(%v)",
		DiskMirror, fi.Size(), HumanizeBytes(fi.Size()))
}
