#NoEnv
	#SingleInstance Force
	; #NoTrayIcon
	; Comparision Phrozen VirusTotal Uploader: +No size-limit 128 Mb, +No internet traffic,
	; if file unrecognized; -No uploads unrecognized files automatically. In this rare case, you can upload it manually.
	#KeyHistory 0
	SetBatchLines -1
	ListLines, Off
	SetWorkingDir, %A_ScriptDir%
	Global InstallDir, AhkPic, VTPic, RadioSendTo, RadioIfShift, NoCompile, InstallButtonid, ExistInstallDir, howerText, installGuiHwnd

if (%0%>0) { ; command line extraction
	Loop, %0%
	{
		param := %A_Index%
	}

	if (param="-uninstall")
		uninstall()
	runURLwithFileHash(param)
	ExitApp
} else {
	; RegRead, PathWithPar, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command
	RegRead, ExistInstallDir, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, InstallLocation
	if ErrorLevel
		guiShow()
	else {  ;SubStr(SubStr(PathWithPar,1, -6),2) - not unsuitable for non-compiled C:\ahk.exe" "C:\scr.ahk
		guiShow(ExistInstallDir) ;(ExistInstallDir := RegExReplace(PathWithPar, "^.+""([^\""]+\\)[^\""\\]+"" ""%1""", "$1"))
	}
}
Return

guiShow(ExistInstallDir:="") {
	;holding down  (shift + right-click). then hold down SHIFT key;  if you hold down the Shift key while/when clicking. Holding the shift key when calling up a context menu
	lngCodeList := {0419:"ru"}
	lng := lngCodeList[A_Language] ? lngCodeList[A_Language] : "en"
	titleText:={en:"VirusTotal Hash Checker Setup",ru:"Установка VirusTotal HashChecker"}[lng]
	howerText:={en:"wikipedia.org/wiki/Checksum",ru:"wikipedia.org/wiki/Контрольная сумма"}[lng]
	explanationText := {en:"allow you to check file for malware`,`nby calculating the <a href=""https://en.wikipedia.org/wiki/Checksum"">checksum</a> and search it on VirusTotal",ru:"позволяет проверить файл на вирусы`nпутем вычисления <a href=""https://ru.wikipedia.org/wiki/%D0%9A%D0%BE%D0%BD%D1%82%D1%80%D0%BE%D0%BB%D1%8C%D0%BD%D0%B0%D1%8F_%D1%81%D1%83%D0%BC%D0%BC%D0%B0"">хеша</a> файла и его поиска среди хешей `nуже проверенных файлов на VirusTotal."}[lng]
	; `nПоскольку сам файл при этом никуда не отправляется, `nэто происходит быстро и без расхода траффика.
	installationText := {en:"After intallation, you'll have item in context menu`,`nhowever you can check files without installation, by dragging and dropping`nyour files onto program exe file or onto this window.",ru:"Установка добавляет пункт в контектное меню проводника`,`nоднако можно проверять и без установки, перетаскивая файлы`,`nлибо на exe файл программы, либо на это окно."}[lng]
	displayConMenText := {en:"Display context menu item",ru:"Отображать в контекстном меню"}[lng]
	showSendToText := {en:"in |Send to > | submenu",ru:"В подменю |Отправить > |"}[lng]
	showExtendText := {en:"if the [SHIFT] is pressed",ru:"При зажатом [SHIFT]'е"}[lng]
	DestinationFolderText := {en:"Destination Folder",ru:"Папка установки"}[lng]
	RegRead, DisplayScale, HKEY_CURRENT_USER, Control Panel\Desktop\WindowMetrics, AppliedDPI
	If (DisplayScale=96) {
		ContextImage:="ContextMenu"
		AhkImage:="ahk_logo"
		VTImage:="VTlogo"
	} else {
		ContextImage:="ContextMenu120"
		AhkImage:="ahk_logo120"
		VTImage:="VTlogo120"
	}
	disabledIfInst := ExistInstallDir ? "disabled" : ""
	InstallDir := ExistInstallDir ? ExistInstallDir : DefInstallDir := ProgramFiles "\VirusTotalHashChecker\"

	HBITMAP := Create_%AhkImage%_png()
	Gui, installGui: Add, Text, w280 h43 gGotoAhksite HwndAhkPic
	Bitmap_SetImage(AhkPic, HBITMAP)
	HBITMAP := Create_%VTImage%_png()
	Gui, installGui: Add, Text, w280 h44 gGotoVTsite HwndVTPic
	Bitmap_SetImage(VTPic, HBITMAP)
	HBITMAP := Create_%ContextImage%_png()
	Gui, installGui: Add, Text, w100 h92 ym+4 HwndConPic
	Bitmap_SetImage(ConPic, HBITMAP)

	Gui, installGui: Add, Link, xm c0x444444, VirusTotal HashChecker %explanationText%
	Gui, installGui: Add, Text, c0x444444 y+5, % installationText
	Gui, installGui: Add, GroupBox, w390 h60 xm, %displayConMenText%:
	Gui, installGui: Add, Radio, vRadioSendTo gChangeRadioDisplayItemOpt HwndRadioSendToId xp+10 yp+18, %showSendToText%
	Gui, installGui: Add, Radio, vRadioIfShift gChangeRadioDisplayItemOpt checked, %showExtendText%
	If ExistInstallDir {
		RegRead extendContextKey, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command
		If !extendContextKey
			Control Check,,, ahk_id %RadioSendToId%
	}
	Gui, installGui: Add, GroupBox, xm w390 h46, %DestinationFolderText%
	Gui, installGui: Add, Edit, vinstallDir W290 xp+10 yp+16 %disabledIfInst%, %InstallDir%
	EditButtonName := ExistInstallDir ? "&Open" : "B&rowse.."
	EditButtonL := ExistInstallDir ? "GOpenInstDir" : "GBrowseInstDir"
	Gui, installGui: Add, Button, %EditButtonL% w70 xp+300, %EditButtonName%
	Gui, installGui: add, text, w390 h1 xm y+25 0x7
	Gui, installGui: Add, Button, GCancel w70 xm, Ca&ncel
	rightButName:= ExistInstallDir ? "&Uninstall" : "&Install"
	rightButL := ExistInstallDir ? "GUninstall": "GInstall"
	Gui, installGui: Add, Button, %rightButL% w70 xp+320 HwndInstallButtonid, %rightButName%
	GuiButtonIcon(InstallButtonid, "imageres.dll", 74, "a0 l2")
	Gui, installGui: Font, S9
	Gui, installGui: Add, Link, c0x0F75BC xm+150 yp+3 ,<a href="http://ahkscript.org/">ste@lzy</a>, 2016
	; Gui, installGui: -Theme
	Gui, installGui: +HwndinstallGuiHwnd
	Gui, installGui: Show, ,%titleText%
	ControlFocus,, ahk_id %InstallButtonid%
	OnMessage(0x200, "Hower")
	OnMessage(0x20, "Hower")
	Return

	GotoVTsite:
		Run http://www.virustotal.com
		Return
	GotoAhksite:
		Run http://ahkscript.org/
		Return
	ChangeRadioDisplayItemOpt:
		RegRead, ExistInstallDir, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, InstallLocation
		If ExistInstallDir {
			Gui, installGui: Submit, NoHide
			RegRead extendContextKey, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command
			If ((extendContextKey && RadioSendTo) || (Not extendContextKey && RadioIfShift))
			{
				GuiControl, installGui:, % InstallButtonid, A&pply
				ApplyButtonOn := true
			} else {
				GuiControl, installGui:, % InstallButtonid, &Uninstall
				ApplyButtonOn := false
			}
		}
		Return
	BrowseInstDir:
		FileSelectFolder, InstallDir, %ProgramFiles%,1,Choose installation directory
		if InstallDir
			GuiControl, installGui:, installDir, %InstallDir%\VirusTotalHashChecker\
		Return
	Install:
		Gui, installGui: Submit
		install(InstallDir, RadioIfShift, RadioSendTo)
		Return
	Uninstall:
		if ApplyButtonOn {
			apply(RadioIfShift, RadioSendTo)
		} else {
			uninstall()
		}
		Return
	OpenInstDir:
		Run explorer.exe %InstallDir%
		Return
	RemoveToolTip:
		ToolTip
		Return
	Cancel:
	installGuiGuiClose:
	installGuiGuiEscape:
		ExitApp
	installGuiGuiDropFiles:
		Loop, parse, A_GuiEvent, `n
		{
			FileGetAttrib, Attributes, %A_LoopField%
			IfInString, Attributes, D
				Continue
			runURLwithFileHash(A_LoopField)
		}
		Return
}
Hower(wParam, lParam, msg, hwnd) {
	static hCurs, hover, WM_SETCURSOR := 0x20, WM_MOUSEMOVE := 0x200
	hCurs:=DllCall("LoadCursor","UInt",0,"Int",32649,"UInt") ;IDC_HAND

	MouseGetPos, , , , ClassNNControlUnderM
	MouseGetPos, , , , idControlUnderM, 2

	If (msg = WM_SETCURSOR) && hover
		return 1

	if (msg = WM_MOUSEMOVE)
	{
		if (idControlUnderM=AhkPic || idControlUnderM=VTPic) {
			hover := true
			DllCall("SetCursor","UInt",hCurs)
			TT((idControlUnderM=AhkPic) ? "ahkscript.org" : "virustotal.com", 1)
		} else if (!(idControlUnderM=AhkPic || idControlUnderM=VTPic)) {
			hover := false
			TT(, 1)
		}

		if (ClassNNControlUnderM = "SysLink1")
			if (A_Cursor != "Arrow") {
				TT(howerText, 2)
			} else {
				TT(, 2)
			}
	}

	Return
}
TT(text:="", numTT:="", show:=false) {
	static textOld, numTTOld

	if show
	{
		ToolTip % textOld,,, % numTTOld
		Return
	}

	if (!text) {
		SetTimer, ShowTT, Off
		ToolTip,,,, % numTT
	} else if (text!=textOld) {
		SetTimer, ShowTT, Off
		SetTimer, ShowTT, -400
	}

	textOld:=text
	numTTOld:=numTT
	Return

	ShowTT:
		TT(,, true)
		Return
}
install(InstallDir, RadioIfShift, RadioSendTo) {
	InstallDir := RegExReplace(InstallDir, "(.*[^\\]$)", "$1\")
	FileCreateDir, %InstallDir%
	if ErrorLevel
		MsgBox Can't create dir in %InstallDir%
	; else
	; 	MsgBox Created %InstallDir%
	FileCopy %A_ScriptName%, %InstallDir%, 1
	If !A_IsCompiled
		FileCopy vt.ico, %InstallDir%
	InstPath := InstallDir A_ScriptName

	NoCompile := A_IsCompiled ? "" : """" A_AhkPath """" " "
	; "%A_AhkPath% "
	PathWithPar := """" InstPath """" " ""%1""" ;(A_IsCompiled) ? ("""" InstPath """" " ""%1""") : (NoCompile """" InstPath """" " ""%1""")
	; "A_ScriptPath" "%1"
	if RadioIfShift {
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command, , %NoCompile%%PathWithPar%
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Extended
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Icon, % A_IsCompiled ? InstPath : (InstallDir . "vt.ico")
		if ErrorLevel
			MsgBox Can't write in registry HKEY_CLASSES_ROOT
	} else if RadioSendTo {
		RegRead, SendToDir, HKEY_CURRENT_USER, Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, SendTo
		SplitPath, A_ScriptName,,,, A_ScriptNameNoExt
		Args := A_IsCompiled ? "" : A_ScriptFullPath " "
		Target := A_IsCompiled ? A_ScriptFullPath : A_AhkPath
		FileCreateShortcut %Target%, %SendToDir%\%A_ScriptNameNoExt%.lnk,, %Args%
	}
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, UninstallString
	, %NoCompile%"%InstPath%" -uninstall
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, DisplayName
	, VirusTotal Hash Checker
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, DisplayIcon, %InstPath%
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, DisplayVersion, 1.0
	RegWrite, REG_BINARY, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, EstimatedSize, 0xFB000
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, Publisher, stealzy
	RegWrite, REG_BINARY, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, NoRepair, 1
	RegWrite, REG_SZ, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, InstallLocation, %InstallDir%
	if ErrorLevel
		MsgBox Can't write in registry HKEY_LOCAL_MACHINE
	ExitApp
	Return
}
apply(RadioIfShift, RadioSendTo) {
	Global ApplyButtonOn
	RegRead, InstallDir, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, InstallLocation
	InstPath := InstallDir A_ScriptName
	NoCompile := A_IsCompiled ? "" : """" A_AhkPath """" " "
	PathWithPar := """" InstPath """" " ""%1""" ;(A_IsCompiled) ? ("""" InstPath """" " ""%1""") : (NoCompile """" InstPath """" " ""%1""")
	If RadioIfShift {
		RegRead, SendToDir, HKEY_CURRENT_USER, Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, SendTo
		SplitPath, A_ScriptName,,,, A_ScriptNameNoExt
		FileDelete, %SendToDir%\%A_ScriptNameNoExt%.lnk

		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command, , %NoCompile%%PathWithPar%
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Extended
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Icon, % A_IsCompiled ? InstPath : (InstallDir . "vt.ico")
		if ErrorLevel
			MsgBox Can't write in registry HKEY_CLASSES_ROOT
	} else {
		RegDelete, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check

		RegRead, SendToDir, HKEY_CURRENT_USER, Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, SendTo
		SplitPath, A_ScriptName,,,, A_ScriptNameNoExt
		Args := A_IsCompiled ? "" : A_ScriptFullPath " "
		Target := A_IsCompiled ? A_ScriptFullPath : A_AhkPath
		FileCreateShortcut % Target, %SendToDir%\%A_ScriptNameNoExt%.lnk,, % Args,, % A_IsCompiled ? InstPath : (InstallDir . "vt.ico")
	}
	Control, Disable,,, ahk_id %InstallButtonid%
	Sleep 1000
	Control, Enable,,, ahk_id %InstallButtonid%
	GuiControl, installGui:, % InstallButtonid, &Uninstall
	ApplyButtonOn := false
}
uninstall() {
	; Shift
	RegDelete, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check
	econtext:=ErrorLevel
	; SendTo
	RegRead, SendToDir, HKEY_CURRENT_USER, Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, SendTo
	SplitPath, A_ScriptName,,,, A_ScriptNameNoExt
	FileDelete, %SendToDir%\%A_ScriptNameNoExt%.lnk
	esendto:=ErrorLevel

	; Files
	RegRead, InstallDir, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker, InstallLocation
	; FileDelete % InstallDir . A_ScriptName

	; Loop, %InstallDir%*, 1
	; 	FilesInDir := true
	; If !FilesInDir
	; 	FileRemoveDir % InstallDir

	; InstallSoftwareList
	RegDelete, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker
	If !A_IsCompiled
		FileDelete % InstallDir . "vt.ico"
	euninst:=ErrorLevel

	; MsgBox Uninstall complete`ncontext: %econtext%, sendto: %esendto%, ProgramFiles: %epf%, uninst: %euninst%
	Run, %comspec% /c del "%InstallDir%%A_ScriptName%" & rd "%InstallDir%",, Hide ; hack - change A_ScriptName to regestry note
	ExitApp
}

runURLwithFileHash(filePath) {
	hash:= LowCase(HashFile(filePath, "SHA256"))
	Run https://www.virustotal.com/ru/file/%hash%/analysis/
}

LowCase(string) {
	StringLower low_string, string
	Return low_string
}
HashFile(filePath,hashType=2) { ; By Deo, http://www.autohotkey.com/forum/viewtopic.php?t=71133
	PROV_RSA_AES := 24
	CRYPT_VERIFYCONTEXT := 0xF0000000
	BUFF_SIZE := 1024 * 1024 ; 1 MB
	HP_HASHVAL := 0x0002
	HP_HASHSIZE := 0x0004

	HASH_ALG := (hashType = "MD2") ? (CALG_MD2 := 32769) : HASH_ALG
	HASH_ALG := (hashType = "MD5") ? (CALG_MD5 := 32771) : HASH_ALG
	HASH_ALG := (hashType = "SHA") ? (CALG_SHA := 32772) : HASH_ALG
	HASH_ALG := (hashType = "SHA256") ? (CALG_SHA_256 := 32780) : HASH_ALG   ;Vista+ only
	HASH_ALG := (hashType = "SHA384") ? (CALG_SHA_384 := 32781) : HASH_ALG   ;Vista+ only
	HASH_ALG := (hashType = "SHA512") ? (CALG_SHA_512 := 32782) : HASH_ALG   ;Vista+ only

	f := FileOpen(filePath,"r","CP0")
	if !IsObject(f)
		return 0
	if !hModule := DllCall( "GetModuleHandleW", "str", "Advapi32.dll", "Ptr" )
		hModule := DllCall( "LoadLibraryW", "str", "Advapi32.dll", "Ptr" )
	if !dllCall("Advapi32\CryptAcquireContextW"
			,"Ptr*",hCryptProv
			,"Uint",0
			,"Uint",0
			,"Uint",PROV_RSA_AES
			,"UInt",CRYPT_VERIFYCONTEXT )
		Gosub,HashTypeFreeHandles

	if !dllCall("Advapi32\CryptCreateHash"
			,"Ptr",hCryptProv
			,"Uint",HASH_ALG
			,"Uint",0
			,"Uint",0
			,"Ptr*",hHash )
		Gosub, HashTypeFreeHandles

	VarSetCapacity(read_buf,BUFF_SIZE,0)

	hCryptHashData := DllCall("GetProcAddress", "Ptr", hModule, "AStr", "CryptHashData", "Ptr")
	While (cbCount := f.RawRead(read_buf, BUFF_SIZE))
	{
		if (cbCount = 0)
			break

		if !dllCall(hCryptHashData
				,"Ptr",hHash
				,"Ptr",&read_buf
				,"Uint",cbCount
				,"Uint",0 )
			Gosub, HashTypeFreeHandles
	}

	if !dllCall("Advapi32\CryptGetHashParam"
			,"Ptr",hHash
			,"Uint",HP_HASHSIZE
			,"Uint*",HashLen
			,"Uint*",HashLenSize := 4
			,"UInt",0 )
		Gosub, HashTypeFreeHandles

	VarSetCapacity(pbHash,HashLen,0)
	if !dllCall("Advapi32\CryptGetHashParam"
			,"Ptr",hHash
			,"Uint",HP_HASHVAL
			,"Ptr",&pbHash
			,"Uint*",HashLen
			,"UInt",0 )
		Gosub, HashTypeFreeHandles

	SetFormat,integer,Hex
	loop,%HashLen%
	{
		num := numget(pbHash,A_index-1,"UChar")
		hashval .= substr((num >> 4),0) . substr((num & 0xf),0)
	}
	SetFormat,integer,D

	HashTypeFreeHandles:
	f.Close()
	DllCall("FreeLibrary", "Ptr", hModule)
	dllCall("Advapi32\CryptDestroyHash","Ptr",hHash)
	dllCall("Advapi32\CryptReleaseContext","Ptr",hCryptProv,"UInt",0)
	return hashval
}
GuiButtonIcon(Handle, File, Index := 1, Options := "") {
	RegExMatch(Options, "i)w\K\d+", W), (W="") ? W := 16 :
	RegExMatch(Options, "i)h\K\d+", H), (H="") ? H := 16 :
	RegExMatch(Options, "i)s\K\d+", S), S ? W := H := S :
	RegExMatch(Options, "i)l\K\d+", L), (L="") ? L := 0 :
	RegExMatch(Options, "i)t\K\d+", T), (T="") ? T := 0 :
	RegExMatch(Options, "i)r\K\d+", R), (R="") ? R := 0 :
	RegExMatch(Options, "i)b\K\d+", B), (B="") ? B := 0 :
	RegExMatch(Options, "i)a\K\d+", A), (A="") ? A := 4 :
	Psz := A_PtrSize = "" ? 4 : A_PtrSize, DW := "UInt", Ptr := A_PtrSize = "" ? DW : "Ptr"
	VarSetCapacity( button_il, 20 + Psz, 0 )
	NumPut( normal_il := DllCall( "ImageList_Create", DW, W, DW, H, DW, 0x21, DW, 1, DW, 1 ), button_il, 0, Ptr )	; Width & Height
	NumPut( L, button_il, 0 + Psz, DW )		; Left Margin
	NumPut( T, button_il, 4 + Psz, DW )		; Top Margin
	NumPut( R, button_il, 8 + Psz, DW )		; Right Margin
	NumPut( B, button_il, 12 + Psz, DW )	; Bottom Margin
	NumPut( A, button_il, 16 + Psz, DW )	; Alignment
	SendMessage, BCM_SETIMAGELIST := 5634, 0, &button_il,, AHK_ID %Handle%
	return IL_Add( normal_il, File, Index )
}
Bitmap_SetImage(hCtrl, hBitmap) {
	; STM_SETIMAGE = 0x172, IMAGE_BITMAP = 0x00, SS_BITMAP = 0x0E
	WinSet, Style, +0x0E, ahk_id %hCtrl%
	SendMessage, 0x172, 0x00, %hBitmap%, , ahk_id %hCtrl%
	Return ErrorLevel
}

/*
	HKEY_CLASSES_ROOT\*\shell\VirusTotal hash check
		Extended=""
		Icon=C:\Program Files\VirusTotal Hash Checker\VirusTotalHashChecker.exe,0
		command
			@=C:\Program Files\VirusTotal Hash Checker\VirusTotalHashChecker.exe "%1"

	DirInst := %ProgramFiles%
	HKEY_LOCAL_MACHINE\SOFTWARE\VirusTotalHashChecker
	; HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\VirusTotalHashChecker ; for 32 in 64
		;Install_Dir=%DirInst%\VirusTotalHashChecker    -    пишут для себя
	HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VirusTotalHashChecker
		DisplayName=VirusTotal Uploader
		DisplayIcon=C:\Program Files (x86)\VirusTotalHashChecker\VirusTotalHashChecker.exe,0
		DisplayVersion=1.0
		EstimatedSize=:dw:000FB000
		InstallLocation="C:\Program Files (x86)\VirusTotal Hash Checker"
		NoModify=:dw01
		NoRepair=:dw01
		Publisher=stealzy
		UninstallString="C:\Program Files (x86)\VirusTotalHashChecker\VirusTotalHashChecker.exe" -uninstall

	проверка сущ файла из буфера обмена при запуске без пар
	запускать от админа по нажатию кнопки + pass submit dir & choice in param
*/

Create_ahk_logo_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 25108 << !!A_IsUnicode)
B64 := "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"
B64 .= "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
CreateBitMap(B64) {
	If !DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", 0, "UInt", 0x01, "Ptr", 0, "UIntP", DecLen, "Ptr", 0, "Ptr", 0)
			Return False
	VarSetCapacity(Dec, DecLen, 0)
	If !DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", 0, "UInt", 0x01, "Ptr", &Dec, "UIntP", DecLen, "Ptr", 0, "Ptr", 0)
			Return False
	hData := DllCall("Kernel32.dll\GlobalAlloc", "UInt", 2, "UPtr", DecLen, "UPtr")
	pData := DllCall("Kernel32.dll\GlobalLock", "Ptr", hData, "UPtr")
	DllCall("Kernel32.dll\RtlMoveMemory", "Ptr", pData, "Ptr", &Dec, "UPtr", DecLen)
	DllCall("Kernel32.dll\GlobalUnlock", "Ptr", hData)
	DllCall("Ole32.dll\CreateStreamOnHGlobal", "Ptr", hData, "Int", True, "PtrP", pStream)
	hGdip := DllCall("Kernel32.dll\LoadLibrary", "Str", "Gdiplus.dll", "UPtr")
	VarSetCapacity(SI, 16, 0), NumPut(1, SI, 0, "UChar")
	DllCall("Gdiplus.dll\GdiplusStartup", "PtrP", pToken, "Ptr", &SI, "Ptr", 0)
	DllCall("Gdiplus.dll\GdipCreateBitmapFromStream",  "Ptr", pStream, "PtrP", pBitmap)
	DllCall("Gdiplus.dll\GdipCreateHBITMAPFromBitmap", "Ptr", pBitmap, "PtrP", hBitmap, "UInt", 0)
	DllCall("Gdiplus.dll\GdipDisposeImage", "Ptr", pBitmap)
	DllCall("Gdiplus.dll\GdiplusShutdown", "Ptr", pToken)
	DllCall("Kernel32.dll\FreeLibrary", "Ptr", hGdip)
	DllCall(NumGet(NumGet(pStream + 0, 0, "UPtr") + (A_PtrSize * 2), 0, "UPtr"), "Ptr", pStream)
	Return hBitmap
}
Create_ahk_logo120_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 30376 << !!A_IsUnicode)
B64 := "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"
B64 .= "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
Create_ContextMenu_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 10480 << !!A_IsUnicode)
B64 := "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
Create_ContextMenu120_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 5792 << !!A_IsUnicode)
B64 := "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
Create_VTlogo_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 2020 << !!A_IsUnicode)
B64 := "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
Create_VTlogo120_png(NewHandle := False) {
Static hBitmap := 0
If (NewHandle)
		hBitmap := 0
If (hBitmap)
		Return hBitmap
VarSetCapacity(B64, 2200 << !!A_IsUnicode)
B64 := "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"
hBitmap := CreateBitMap(B64)
Return hBitmap
}
