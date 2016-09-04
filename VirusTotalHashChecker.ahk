#NoEnv
	#SingleInstance Force
	; #NoTrayIcon
	; Comparision Phrozen VirusTotal Uploader: +No size-limit 128 Mb, +No internet traffic,
	; if file unrecognized; -No uploads unrecognized files automatically. In this rare case, you can upload it manually.
	#KeyHistory 0
	SetBatchLines -1
	ListLines, Off
	SetWorkingDir, %A_ScriptDir%
	OnExit, ExitSub
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
	lng := (A_Language=0419) ? "ru" : "en"
	TitleText:={en:"VirusTotal Hash Checker Setup",ru:"Установка VirusTotal HashChecker"}[lng]
	howerText:={en:"wikipedia.org/wiki/Checksum",ru:"wikipedia.org/wiki/Контрольная сумма"}[lng]
	explanationText := {en:"allow you `nto check file for malware`, by calculating the <a href=""https://en.wikipedia.org/wiki/Checksum"">checksum</a> and search it on VirusTotal",ru:"позволяет проверить файл на вирусы`nпутем вычисления его <a href=""https://ru.wikipedia.org/wiki/%D0%9A%D0%BE%D0%BD%D1%82%D1%80%D0%BE%D0%BB%D1%8C%D0%BD%D0%B0%D1%8F_%D1%81%D1%83%D0%BC%D0%BC%D0%B0"">хеша</a> и сопоставления с хешами `nуже проверенных файлов на VirusTotal.`nПоскольку сам файл при этом никуда не отправляется, `nэто происходит быстро и без расхода траффика."}[lng]
	installationText := {en:"allow you `nto scanner widespread files for malware.",ru:"Установка добавляет пункт в контектное меню проводника`,`nоднако можно проверять и без установки, перетаскивая файлы`,`nлибо на exe файл программы, либо на это окно."}[lng]
	displayConMenText := {en:"Display context menu item",ru:"Отображать в контекстном меню"}[lng]
	ShowInSendToText:={en:"in <Send to> submenu",ru:"В подменю |Отправить > |"}[lng]
	ShowIfShiftText := {en:"when clamped SHIFT",ru:"При зажатом [SHIFT]'е"}[lng]
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
	Gui, installGui: Add, Picture, w280 h43 gGotoAhksite HwndAhkPic, %AhkImage%.png
	Gui, installGui: Add, Picture, w280 h44 gGotoVTsite HwndVTPic, %VTImage%.png
	Gui, installGui: Add, Picture, w100 h92 ym+4, %ContextImage%.png
	Gui, installGui: Add, Link, xm c0x444444, VirusTotal HashChecker %explanationText%
	Gui, installGui: Add, Text, c0x444444 y+5, % installationText
	Gui, installGui: Add, GroupBox, w390 h60 xm, %displayConMenText%:
	Gui, installGui: Add, Radio, vRadioSendTo gChangeRadioDisplayItemOpt HwndRadioSendToId xp+10 yp+18, %ShowInSendToText%
	Gui, installGui: Add, Radio, vRadioIfShift gChangeRadioDisplayItemOpt checked, %ShowIfShiftText%
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
	Gui, installGui: Show, ,%TitleText%
	ControlFocus,, ahk_id %InstallButtonid%
	OnMessage(0x200, "Hower")
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
				; Control Enable,,, ahk_id %InstallButtonid%
				GuiControl, installGui:, % InstallButtonid, A&pply
			} else {
				; Control Disable,,, ahk_id %InstallButtonid%
				GuiControl, installGui:, % InstallButtonid, &Uninstall
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
		uninstall()
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
install(InstallDir, RadioIfShift, RadioSendTo) {
	InstallDir := RegExReplace(InstallDir, "(.*[^\\]$)", "$1\")
	FileCreateDir, %InstallDir%
	if ErrorLevel
		MsgBox Can't create dir in %InstallDir%
	; else
	; 	MsgBox Created %InstallDir%
	FileCopy, %A_ScriptName%, %InstallDir%, 1
	InstPath := InstallDir A_ScriptName

	NoCompile := A_IsCompiled ? "" : """" A_AhkPath """" " "
	; "%A_AhkPath% "
	PathWithPar := """" InstPath """" " ""%1""" ;(A_IsCompiled) ? ("""" InstPath """" " ""%1""") : (NoCompile """" InstPath """" " ""%1""")
	; "A_ScriptPath" "%1"
	; MsgBox % NoCompile "`n" PathWithPar
	if RadioIfShift {
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\command, , %NoCompile%%PathWithPar%
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Extended
		RegWrite, REG_SZ, HKEY_CLASSES_ROOT, *\shell\VirusTotal hash check\, Icon, %InstPath%
		if ErrorLevel
			MsgBox Can't write in registry HKEY_CLASSES_ROOT
	} else if RadioSendTo {
		RegRead, SendToDir, HKEY_CURRENT_USER, Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, SendTo
		SplitPath, A_ScriptName,,,, A_ScriptNameNoExt
		Args := A_IsCompiled ? "" : A_ScriptFullPath " "
		Target := A_IsCompiled ? A_ScriptFullPath : A_AhkPath
		; MsgBox % Target "`n" Args "`n" SendToDir "\" A_ScriptNameNoExt
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
	euninst:=ErrorLevel

	; MsgBox Uninstall complete`ncontext: %econtext%, sendto: %esendto%, ProgramFiles: %epf%, uninst: %euninst%
	Run, %comspec% /c del "%InstallDir%%A_ScriptName%" & rd "%InstallDir%",, Hide ; hack - change A_ScriptName to regestry note
	ExitApp
}
runURLwithFileHash(filePath) {
	hash:= LowCase(HashFile(filePath, "SHA256"))
	Run https://www.virustotal.com/ru/file/%hash%/analysis/
}
Hower() {
	static cursor_hand
	MouseGetPos, , , , ClassNNControlUnderM
	MouseGetPos, , , , idControlUnderM, 2

	if (idControlUnderM=AhkPic || idControlUnderM=VTPic) {
		if !cursor_hand
		{
			SetSystemCursor("IDC_HAND")
			cursor_hand := true
			SetTimer, CheckCursorStillOnWindow, 100
		}
		ToolTip % (idControlUnderM=AhkPic) ? "ahkscript.org" : "virustotal.com"
	} else if (!(idControlUnderM=AhkPic || idControlUnderM=VTPic)) {
		if cursor_hand
		{
			SetSystemCursor("Restore")
			cursor_hand := false
			SetTimer, CheckCursorStillOnWindow, off
		}
		ToolTip
	}

	if (ClassNNControlUnderM = "SysLink1")
		if (A_Cursor != "Arrow")
			ToolTip % howerText
		else
			ToolTip

	Return


	CheckCursorStillOnWindow:
		MouseGetPos,,, winID
		if (winID != installGuiHwnd) {
			SetSystemCursor("Restore")
			ToolTip
		}
		Return
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
SetSystemCursor( Cursor = "", cx = 0, cy = 0 ) {	; by Serenity. Minor modification by Learning one.
	; http://www.autohotkey.com/forum/topic35600.html
	if Cursor = Restore
	{
		DllCall( "SystemParametersInfo", UInt,0x57, UInt,0, UInt,0, UInt,0 )
		Return
	}
	BlankCursor := 0, SystemCursor := 0, FileCursor := 0 ; init
	SystemCursors = 32512IDC_ARROW,32513IDC_IBEAM,32514IDC_WAIT,32515IDC_CROSS
	,32516IDC_UPARROW,32640IDC_SIZE,32641IDC_ICON,32642IDC_SIZENWSE
	,32643IDC_SIZENESW,32644IDC_SIZEWE,32645IDC_SIZENS,32646IDC_SIZEALL
	,32648IDC_NO,32649IDC_HAND,32650IDC_APPSTARTING,32651IDC_HELP
	If Cursor = ; empty, so create blank cursor
	{
		VarSetCapacity( AndMask, 32*4, 0xFF ), VarSetCapacity( XorMask, 32*4, 0 )
		BlankCursor = 1 ; flag for later
	}
	Else If SubStr( Cursor,1,4 ) = "IDC_" ; load system cursor
	{
		Loop, Parse, SystemCursors, `,
		{
			CursorName := SubStr( A_Loopfield, 6, 15 ) ; get the cursor name, no trailing space with substr
			CursorID := SubStr( A_Loopfield, 1, 5 ) ; get the cursor id
			SystemCursor = 1
			If ( CursorName = Cursor )
			{
				CursorHandle := DllCall( "LoadCursor", Uint,0, Int,CursorID )
				Break
			}
		}
		If CursorHandle = ; invalid cursor name given
		{
			Msgbox,, SetCursor, Error: Invalid cursor name
			CursorHandle = Error
		}
	}
	Else If FileExist( Cursor )
	{
		SplitPath, Cursor,,, Ext ; auto-detect type
		If Ext = ico
			uType := 0x1
		Else If Ext in cur,ani
			uType := 0x2
		Else ; invalid file ext
		{
			Msgbox,, SetCursor, Error: Invalid file type
			CursorHandle = Error
		}
		FileCursor = 1
	}
	Else
	{
		Msgbox,, SetCursor, Error: Invalid file path or cursor name
		CursorHandle = Error ; raise for later
	}
	If CursorHandle != Error
	{
		Loop, Parse, SystemCursors, `,
		{
			If BlankCursor = 1
			{
				Type = BlankCursor
				%Type%%A_Index% := DllCall( "CreateCursor"
				, Uint,0, Int,0, Int,0, Int,32, Int,32, Uint,&AndMask, Uint,&XorMask )
				CursorHandle := DllCall( "CopyImage", Uint,%Type%%A_Index%, Uint,0x2, Int,0, Int,0, Int,0 )
				DllCall( "SetSystemCursor", Uint,CursorHandle, Int,SubStr( A_Loopfield, 1, 5 ) )
			}
			Else If SystemCursor = 1
			{
				Type = SystemCursor
				CursorHandle := DllCall( "LoadCursor", Uint,0, Int,CursorID )
				%Type%%A_Index% := DllCall( "CopyImage"
				, Uint,CursorHandle, Uint,0x2, Int,cx, Int,cy, Uint,0 )
				CursorHandle := DllCall( "CopyImage", Uint,%Type%%A_Index%, Uint,0x2, Int,0, Int,0, Int,0 )
				DllCall( "SetSystemCursor", Uint,CursorHandle, Int,SubStr( A_Loopfield, 1, 5 ) )
			}
			Else If FileCursor = 1
			{
				Type = FileCursor
				%Type%%A_Index% := DllCall( "LoadImageA"
				, UInt,0, Str,Cursor, UInt,uType, Int,cx, Int,cy, UInt,0x10 )
				DllCall( "SetSystemCursor", Uint,%Type%%A_Index%, Int,SubStr( A_Loopfield, 1, 5 ) )
			}
		}
	}
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
ExitSub:
	SetSystemCursor("Restore")
	ExitApp

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
	перетаскивание на окно
	без параметров запускать от админа / запускать от админа по нажатию кнопки + pass submit dir & choice in param