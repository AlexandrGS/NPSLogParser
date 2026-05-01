 Param (
#Папка куда складываются *.csv с результатами.
#Если равен $ResultPathNone, то файлы не создаются.
#Если равен пустой строке, то в текущей папке создается папка с текущим временем в названии
	$ResultPath = "",
#Список IN*.LOG файлов созданных службой NPS, или одна папка где искать IN*.LOG файлы. Формат файлов DTS-XML.
#Если указаны несколько файлов, то они разделяются любым из символов из переменной $DelimiterOfFilesList
	$LogFiles = ".",
#Что отправляется в выходной поток скрипта. Статистика по сессиям или по пользователям. По умолчанию по сессиям
#Может принимать значения $StatTypePerSessions или $StatTypePerUsers.
    $StatType = "",
 #Проксі-сервер для доступа в інет. Якщо посто, то намагаеться напрямую в інет
    $Proxy = "",
#Файл з ІР адресами і їх геопозиціями. Файл создается программой https://github.com/AlexandrGS/NPSLogOnline_HTML
    $IPGeoLoc_FileName = "\\10.6.105.30\c$\inetpub\vpnstat\data\IPAndGeoLocation.csv",
#Следующие параметры определяют диапазон даты-времени за который будут анализироваться записи в логах
#Нижний диапазон даты-времени
    $MinYear = 1970,#Год в формате YYYY, 4 цифры. Должен быть больше чем 1970
    $MinMonth = 1,  #Месяц
    $MinDay = 1,    #День
    $MinHour = 0,   #Час в 24-часовом формате
    $MinMin = 0,    #Минуты
    $MinSec = 0,    #Секунды
    $MinMSec = 0,   #Миллисекунды 3 цифры
#Верхний диапазон даты-времени
    $MaxYear = 9999,#Год в формате YYYY, 4 цифры.
    $MaxMonth = 12, #
    $MaxDay = 31,   #
    $MaxHour = 23,  #
    $MaxMin = 59,   #
    $MaxSec = 59,   #
    $MaxMSec = 999  #
)

$StatTypePerSessions="Sessions"
$StatTypePerUsers="Users"

$ResultSessionsFile = "ResultSessions"
$ResultUsersFile = "ResultUsage"

$DelimiterOfFilesList = ",;"

$PatternNPSLogFiles = "in*.log"

$ResultPathNone = "none" #Если эта строка передана в входном параметре $ResultPath, то *.csv и путь ResultPath НЕ создавать

function PrintHelp(){

}

#Импортирует весь CSV-файл и возвращает объект с его содержимым
function ImportObjectFromCSV($CSVFileName) {
    $Object = Import-CSV -Path $CSVFileName -Delimiter ';' -Encoding UTF8
    Return $Object
}

#Добавляет объект в CSV-файл 
function ExportObjectToCSV ($Object,$FN) {
    $FileName = $ResultPath + "\" + $FN + ".csv"
    $Object | Export-CSV -Path $FileName -Delimiter ';' -Encoding UTF8 -NoTypeInformation -Append
}

function PrintResult($Object,$FileName){
    ExportObjectToCSV $Object $FileName
    Return $Object
}

#Подсчитывает сколько в данном числе секунд часов минут секунд
#Получает количество секунд
#Возвращает строку вида 11:23:59 hh:mm:ss
function DurationSecToHourMinSec ([string]$strDurationSec){
    $Result = ""
    $SecInMin = 60
    $SecInHour = 60 * $SecInMin

    try{
        [uint64]$DurationSec = [Convert]::ToUInt64($strDurationSec)
    }
    catch{
        $Msg = "DurationSecToHourMinSec: не удалось преобразовать входной параметр-" + $strDurationSec + "-в беззнаковое целое число"
        Write-Warning $Msg
        Return $Result
    }

    if($DurationSec -lt 0){
        Write-Warning "  DurationSecToHourMinSec: Получено неверное число секунд: $DurationSec"
    } else {
        [int]$Hours   = [math]::Truncate( $DurationSec / $SecInHour )
        [int]$Minutes = [math]::Truncate( ($DurationSec % $SecInHour) / $SecInMin )
        [int]$Seconds = $DurationSec % $SecInMin
        $Result = [string]$Hours+ ":" + [string]$Minutes + ":" + [string]$Seconds
    }

#    [int]$Hours   = [math]::Truncate($DurationSec / 3600)
#    [int]$Minutes = [math]::Truncate( ( $DurationSec - $Hours*3600  ) / 60)
#    [int]$Seconds = $DurationSec - $Hours * 3600 - $Minutes * 60
#    if($Hours   -gt 0){ $Result += [string]$Hours + ":" }
#    if($Minutes -gt 0){ $Result += [string]$Minutes + ":"}
#    $Result += [string]$Seconds

    Return $Result    
}

#Получает строку с датой временем вида MM/DD/YYYY hh:mm:ss.___ Например 02/01/2020 14:32:05.812
#Возвращаетколичество секунд от 01.01.1970 до этой даты
function ToSecFrom1970([datetime]$DateTime){
    $Result = Get-Date -UFormat %s -Year $DateTime.Year -Month $DateTime.Month -Day $DateTime.Day -Hour $DateTime.Hour -Minute $DateTime.Minute -Second $DateTime.Second -Millisecond $DateTime.Millisecond
    Return $Result #???
}


#Packet-Type
$AccessRequest = 1
$AccessAccept = 2
$AccessReject = 3
$AccountingRequest = 4
$AccountingResponse = 5
$AccessChallenge = 11
$StatusServer = 12
$StatusClient = 13
$DisconnectRequest = 40
$DisconnectACK = 41
$DisconnectNAK = 42
$ChangeOfAuthorizationRequest = 43
$ChangeOfAuthorizationACK = 44
$ChangeOgAuthorizationNAK = 45

#ACCT-Status-Type
$Start = 1
$Stop = 2
$InterimUpdate = 3
$AccountingOn = 7
$AccountingOff = 8

#Получает код причины прекращения VPN-сессии. Соответствует полю Acct-Terminate-Cause
#Возвращает строку с развернутым описанием
function GetTerminateCause([int]$Cause){
    $TerminateCause= 
        @{Code=1;  Description="1 User Request"},
        @{Code=2;  Description="2 Lost Carrier"},
        @{Code=3;  Description="3 Lost Service"},
        @{Code=4;  Description="4 Idle Timeout"},
        @{Code=5;  Description="5 Session Timeout"},
        @{Code=6;  Description="6 Admin Reset"},
        @{Code=7;  Description="7 Admin Reboot"},
        @{Code=8;  Description="8 Port Error"},
        @{Code=9;  Description="9 NAS Error"},
        @{Code=10; Description="10 NAS Request"},
        @{Code=11; Description="11 NAS Reboot"},
        @{Code=12; Description="12 Port Unneeded"},
        @{Code=13; Description="13 Port Preempted"},
        @{Code=14; Description="14 Port Suspended"},
        @{Code=15; Description="15 Service Unavailable"},
        @{Code=16; Description="16 Callback"},
        @{Code=17; Description="17 User Error"},
        @{Code=18; Description="18 Host Request"}
    $Result = [string]$Cause
    if( ($Cause -ge 1) -and ($Cause -le $TerminateCause.Count) ){
        ForEach($I in $TerminateCause){
            if($I.Code -eq $Cause){
                $Result = $I.Description
                Break
            }
        }
    }
    Return $Result
}

function GetAuthenticationType([int]$AuthID){
    $AllAuthTypes=
         @{Code=1;  Description="PAP"},
         @{Code=2;  Description="CHAP"},
         @{Code=3;  Description="MS-CHAP v1"},
         @{Code=4;  Description="MS-CHAP v2"},
         @{Code=5;  Description="EAP"},
         @{Code=6;  Description="ARAP"},
         @{Code=7;  Description="Unauthenticated"},
         @{Code=8;  Description="Extension"},
         @{Code=9;  Description="MS-CHAP v1 CPW"},
         @{Code=10;  Description="MS-CHAP v2 CPW"},
         @{Code=11;  Description="PEAP"}

    $Result = ""
    if( ($AuthID -gt 0) -and ($AuthID -le $AllAuthTypes.Count) ){
        ForEach($I in $AllAuthTypes){
            $Result = $I.Description
            Break
        }
    }
    Return $Result
}

#----- Геолокация по IP адресу -----

#Флаг включения геолокации
[bool]$Global:isIPGeoLocationEnable = $True
#Флаг первой проверки геолокации. Во время первой проверки проверяется связь с сайтом, выдающим геолокацию
[bool]$Script:isFirstIPGeoLocationTest = $True
#Чи отримувати дані про геолокацію із файла
[bool]$Script:isIPGeoLocFileEnable = $True
#Содержит результаты предыдущих запросов IP локации в виде @{IP=""; Country=""; City = ""; Latitude = ""; Longitude = ""; ASN = ""; Organization = ""; ISP = ""}
[array]$Global:IPAndGeoLocation = @{}

$Script:CountHitToIPAndGeoArray = 0
$Script:CountResolvingIPGeo = 0

#Приватні IP адреси
[string[]]$PrivateIPs = 
"10.",
"192.168.",
"172.16.",
"172.17.",
"172.18.",
"172.19.",
"172.20.",
"172.21.",
"172.22.",
"172.23.",
"172.24.",
"172.25.",
"172.26.",
"172.27.",
"172.28.",
"172.29.",
"172.30.",
"172.31."

#Отримуе ІР адресу. Повертае истину якщо ІР з приватної мережі
function boolPrivateIP($IP){
    [bool]$boolIsPrivateIP = $false

    foreach($I in $PrivateIPs){
        if($IP.StartsWith($I)){
            $boolIsPrivateIP = $true
            break
        }
    }

    return $boolIsPrivateIP
}

#Получае IP адресу. Повертае строку з геолокаціею
function GetGeoByIPFromInet($IP){
    if(($Proxy -eq "") -or ($Proxy -eq $null)){
        $Result = Invoke-RestMethod -method Get -Uri "https://ipwhois.app/xml/$IP" #| Out-Null
    }else{
        $Result = Invoke-RestMethod -method Get -Uri "https://ipwhois.app/xml/$IP" -Proxy $Proxy -ProxyUseDefaultCredentials #| Out-Null
    }
    return $Result
}

#Получает один элемент массива $Global:IPAndGeoLocation, возвращает строку с геопозицией в человеческом виде
function FormingIPGeoString($IPGeoLocationItem){
    $Result = $IPGeoLocationItem.Country + "," + 
              $IPGeoLocationItem.Region + "," + 
              $IPGeoLocationItem.City + 
              ",latitude:" + $IPGeoLocationItem.Latitude + 
              ",longitude:" + $IPGeoLocationItem.Longitude + 
              ",asn:" + $IPGeoLocationItem.ASN + 
              ",org:" + $IPGeoLocationItem.Organization + 
              ",isp:" + $IPGeoLocationItem.ISP
    Return $Result
}

#Получает IP адрес. Возвращает строку с географичесим положением country region city latitude longitude asn org isp
function GetIPGeoLocation([string]$IP){
    [string]$Result = ""
    [bool]$ErrorOnTestingGeoLocServer = $False
    
    if(($IP -eq "0.0.0.0") -or ($IP -eq "") -or ($IP -eq $null) -or (boolPrivateIP $IP)){
        return ""
    }

    #При первом вызове проверяем есть ли доступ к сайту где проверяется локация по IP
    if(($Script:isFirstIPGeoLocationTest) -and ($Global:isIPGeoLocationEnable)){
        
        Write-Host "Перевірка звязку з сервісом геолокації http://ipwhois.app"
        try{
            $FirstTest = [xml](GetGeoByIPFromInet "8.8.8.8") 
        }
        catch{
            $ErrorOnTestingGeoLocServer = $True
        }
        if( ($FirstTest.query.success -eq 1) -and ( -not $ErrorOnTestingGeoLocServer) ){
            Write-Host "Перевірка звязку з сервісом геолокації  вдала. Геолокація по IP буде увімкнена. Безоплатно можливо перевірити до 10000 адрес за місяць"
            $Global:isIPGeoLocationEnable = $True
        } else {
            Write-Warning "Спроба перевірити звязок з сервісом геолокації не вдалася. Геолокація по IP буде вимкнена"
            $Global:isIPGeoLocationEnable = $False
        }

        if(($IPGeoLoc_FileName -ne "") -and ($IPGeoLoc_FileName -ne $null)){
            Write-Host "Перевірка файла " $IPGeoLoc_FileName " - " -NoNewline
            if(Test-Path -Path $IPGeoLoc_FileName -PathType Leaf ){
                Write-Host "файл знайдено. Імпортую його."
                $Global:IPAndGeoLocation = ImportObjectFromCSV $IPGeoLoc_FileName
                $Script:isIPGeoLocFileEnable = $True
            }else{
                Write-Host "файл не знайдено. Будьмо працювати без нього"
                $Script:isIPGeoLocFileEnable = $False
            }#if(Test-Path -Path $IPGeoLoc_FileName
        }

        $Script:isFirstIPGeoLocationTest = $False
    }

    #Ищем геолокацию IP адреса
    if($Global:isIPGeoLocationEnable -or $Script:isIPGeoLocFileEnable){
        $isIPInArray = $False
        ForEach($I in $Global:IPAndGeoLocation){
            if($I.IP -eq $IP){
                $Script:CountHitToIPAndGeoArray++
                $Result = FormingIPGeoString $I
                $isIPInArray = $True
            }
        }
        if( (-not $isIPInArray) -and ($Global:isIPGeoLocationEnable) ){
            $XMLWebRequest = [xml](GetGeoByIPFromInet $IP)
            if(($XMLWebRequest.query.success -eq 1) -or ($XMLWebRequest.query.success -eq "true") -or ($XMLWebRequest.query.success -eq $True)){
                $Script:CountResolvingIPGeo++
                $Global:IPAndGeoLocation += @{IP=$IP; Country=$XMLWebRequest.query.country; Region = $XMLWebRequest.query.region; City = $XMLWebRequest.query.city; Latitude = $XMLWebRequest.query.latitude; Longitude = $XMLWebRequest.query.longitude; ASN = $XMLWebRequest.query.asn; Organization = $XMLWebRequest.query.org; ISP = $XMLWebRequest.query.isp}
                $Result = FormingIPGeoString $XMLWebRequest.query
            }
        }
    }
    Return $Result
}

#----- Конец функций геолокации по IP -----

[string[]]$Script:NPSLog = $()

function GetNPSLogFilesContent([string]$NPSLogFiles){
    Write-Host "Чтение лог-файлов NPS-Radius сервера"
    $CountFiles = 0
    if($NPSLogFiles.Length -eq 0 ){
     Write-Warning " GetNPSLogContent: ожидает параметром строку"
    }
    $FileNames = $NPSLogFiles.Split($DelimiterOfFilesList)
    if($FileNames.Count -eq 1){
        Write-Host " На входе получили одну папку или файл."
        if(Test-Path $FileNames -PathType Leaf){
        #Получен один файл
            Write-Host " Читаем файл" $FileNames
            $Script:NPSLog = Get-Content $FileNames
            $CountFiles = 1
        }else{
            if(Test-Path $FileNames -PathType Container) {
                #Получена папка, будем искать там in*.log файлы
                Write-Host " В папке $FileNames ищем $PatternNPSLogFiles файлы"
                $FNs =  Get-ChildItem $FileNames | Where {$_.Name -like $PatternNPSLogFiles} | Select FullName | Sort-Object FullName
                ForEach($I in $FNs.FullName){
                    Write-Host " Читаем файл $I"
                    $Script:NPSLog += Get-Content $I
                    $CountFiles++
                }
            }
        }
        
    }else{
        #Получено несколько файлов логов
        Write-Host " Получено несколько файлов логов."
        ForEach($I in $FileNames){
            if(Test-Path $FileNames -PathType Leaf){
                Write-Host " Читаем файл" $I
                $Script:NPSLog += Get-Content $I
                $CountFiles++
            } else {
                Write-Warning "Файл" $I "не найден"
            }
        }
    }
    Write-Host " Прочитано " $Script:NPSLog.Count "строк из" $CountFiles "файлов"
}

#Тут хранится список VPN сессий с первыми Access и Accounting  и последним Accounting пакетом каждой сессии. Состоит из объектов $OneVPNSessionData
[array]$Script:VPNSessionsData = @() 

#Получает одну XML запись лога Радиус-сервера и $OneVPNSession (объект типа $OneVPNSessionData) содержащем нужные пакеты из одной сессии
#И одна ХМЛ запись и объект должны содержыть данные одной ВПН сессии, иначе ошибка
#Обновляет объект $OneVPNSession по данным xml строки
function UpdateOneVPNSessionFromAllVPNSessions([xml]$LineXML,$OneVPNSession){
    if($LineXML.Event."Class"."#text" -ne $OneVPNSession.Class){
        $Msg = "Функция UpdateOneVPNSessionFromAllVPNSessions: Поля Class должны совпадать. Запись лога:" + $LineXML
        Write-Warning $Msg
        Return
    }
    $PacketType = $LineXML.Event."Packet-Type"."#text"
    $AccountingType = $LineXML.Event."Acct-Status-Type"."#text"
    if($PacketType -eq $AccessRequest){
        $OneVPNSession.FirstAccessPacketXML = $LineXML
    }elseif(($PacketType -eq $AccessAccept) -or ($PacketType -eq $AccessReject) -or ($PacketType -eq $AccessChallenge) ){ #Нужна ли проверка $AccessChallenge
        $OneVPNSession.SecondAccessPacketXML = $LineXML
    }elseif($AccountingType.Length -gt 0){        #(($PacketType -eq $AccountingRequest){
        [bool]$isFirstOne = $False
        if($OneVPNSession.FirstAcctPacketXML  -eq ""){
            $OneVPNSession.FirstAcctPacketXML = $LineXML
            $isFirstOne=$True
        }
        if($OneVPNSession.LastAcctPacketXML  -eq ""){
            $OneVPNSession.LastAcctPacketXML = $LineXML
            $isFirstOne=$True
        }
        if(-not $isFirstOne){
            $TimeStamp = $LineXML.Event."Timestamp"."#text"
            $TimeStampSec = ToSecFrom1970 $TimeStamp
            $ITimeStampSec = ToSecFrom1970 $OneVPNSession.FirstAcctPacketXML.Event."Timestamp"."#text"
            #Проверить является ли эта запись по времени более ранней чем первый пакет
            if( $TimeStampSec -lt $ITimeStampSec ){
                #Если более ранняя то сохранить ее как первый пакет VPN сессии
                $OneVPNSession.FirstAcctPacketXML = $LineXML
            }
            #Проверить является ли эта запись более старой чем последний пакет
            $ITimeStampSec = ToSecFrom1970 $I.LastAcctPacketXML.Event."Timestamp"."#text"
            if( $TimeStampSec -gt $ITimeStampSec){
                #Если более старый, то сохранить как последний пакет VPN сессии
                $OneVPNSession.LastAcctPacketXML = $LineXML
            }
       } #if(-not $isFirstOne){
    } #}elseif($AccountingType.Length -gt 0)
#    Return $OneVPNSession
}

#Получает строку Line с одной записью из Радиус-лога
#В Массиве $Script:VPNSessionsData ищет информацию о VPN сессии к которой принадлежит строка Line и обновляет данные в массиве
function PrepareOneStringFromLogs([string]$Line, $DateTimeMinSec, $DateTimeMaxSec)
{
    try{
        $LineXML = [xml]$Line
    }
    catch{
        Write-Warning "----- Не удалось преобразовать к XML следующую строку в логах ----- "
        for($I = 2; ($I+2) -le $Line.Length; $I=$I+2){
            [string]$strOneByte = [string]"0x" + [string]$Line[$I] + [string]$Line[$I + 1]
            $Msg = [char][byte]$strOneByte
            Write-Host $Msg -NoNewline
        }
        Write-Host "" #Просто перейти на новую строку
        return
    }

    #----- Пропуск тех кто засоряет логи неудачными сессиями. НЕКРАСИВО ВЫГЛЯДИТ !!! ???
#    if($LineXML.Event."Fully-Qualifed-User-Name"."#text" -ieq "pridn\p.ag-inturist"){
#    if($LineXML.Event."SAM-Account-Name"."#text"         -ieq "PRIDN\p.ag-inturist"){
#        Return
#    }
    #----- End Пропуск тех кто засоряет логи неудачными сессиями

    $TimeStamp = $LineXML.Event."Timestamp"."#text"
    $TimeStampSec = ToSecFrom1970 $TimeStamp
    $Class = $LineXML.Event."Class"."#text"
    if($Class.Length -gt 0){                  #Если в записи лога есть поле Class, то обрабатываем дальше. Иначе пропускаем
        if( ($TimeStampSec -ge $DateTimeMinSec) -and ($TimeStampSec -le $DateTimeMaxSec) ){ # Попадает ли запись в нужный диапазон времени
            #Найти есть ли уже сессия к которой принадлежит запись лога $Line
            $isVPNSessionExist = $False
            ForEach($I in $Script:VPNSessionsData){
                if($I.Class -eq $Class){
                    $isVPNSessionExist = $True
                    UpdateOneVPNSessionFromAllVPNSessions $LineXML $I 
                    Break
                }
            } #ForEach($I in $Script:VPNSessionsData){
            #Если же сессия новая, то сохранить ее
            if(-not $isVPNSessionExist){
               $OneVPNSessionData =  New-Object -Type PSObject -Property @{
                    Class = $Class  #Уникальное для каждой VPN сессии Поле. Берется из Class
                    FirstAccessPacketXML = "";   #Первый Access пакет этой VPN сессии. Самый первый пакет
                    SecondAccessPacketXML = "";  #Второй Access пакет этой VPN сессии. Второй пакет
                    FirstAcctPacketXML = ""; #Первый Accounting пакет этой VPN сессии
                    LastAcctPacketXML  = ""; #Последний Accounting пакет этой VPN сессии
              }
              UpdateOneVPNSessionFromAllVPNSessions $LineXML $OneVPNSessionData
            $Script:VPNSessionsData += $OneVPNSessionData
            } #if(-not $isVPNSessionExist){
        }#if($Class.Length -gt 0){
    } #if( ($TimeStampSec -ge $DateTimeMinSec) -and ($TimeStampSec -le $DateTimeMaxSec) ){
}

#Получает построчный массив Radius-лога и диапазон времени за который искать данные в секундах с 01.01.1970
#Ищет в логе только те записи которые интересны для дальнейшей обработки
#Тут и в подфункциях заполняется массив $Script:VPNSessionsData
function PrepareNeedData($DateTimeMinSec,$DateTimeMaxSec){
    Write-Host "Подсчет предварительных данных"
    if($DateTimeMinSec -gt $DateTimeMaxSec){
        Write-Warning " PrepareNeedData: Минимальное значение времени должно быть меньше или равно максимальному"
        Return
    }
    #Прогресс-бар подготовка
    $k = 0
    $CountLinesToNPSLog = $Script:NPSLog.Count
    $MaxIter = $CountLinesToNPSLog /1000
    if($MaxIter -eq 0){ $MaxIter = 10 }
    $Iter = $MaxIter
    #
    ForEach($Line in $Script:NPSLog){
        #Прогрес-бар
        if($Iter-- -le 0){
            $Iter = $MaxIter
            $percentComplete = ($k / $CountLinesToNPSLog) * 100
            Write-Progress -Activity 'Предварительная подготовка' -Status "Сбор сведений о VPN-сессиях" -PercentComplete $percentComplete
        }
        $k++
        #
        PrepareOneStringFromLogs $Line $DateTimeMinSec $DateTimeMaxSec
    }#ForEach($Line in $Script:NPSLog){
    Write-Progress -Activity 'Предварительная подготовка' -Status "Сбор сведений о VPN-сессиях завершен" -Completed
}

#Извлекает параметры одной VPN сессии
#Получает объект $OneVPNSessionData, содержащий нужные пакеты  одной VPN сессии
#Возвращает объект $VPNSessionDesc, содержащий все характеристики этой сессии
function GetStatOneVPNSession($OneSession){
    $FirstRecordXML = $OneSession.FirstAcctPacketXML
    $LastRecordXML  = $OneSession.LastAcctPacketXML
    $VPNSessionDesc = New-Object -Type PSObject -Property ([ordered]@{
        UserName            = [string]""; #Имя пользователя этой сессии
        UserDevName         = [string]$FirstRecordXML.Event."Tunnel-Client-Auth-ID"."#text"; #Имя устройства VPN-клиента
        DurationSec         = [uint64]$LastRecordXML.Event."Acct-Session-Time"."#text"; #Длительность сессии в секундах. Подсчитывается NAS-сервером
                                                                                    # и может быть больше диапазона DateTimeStart-DateTimeEnd
        DurationHourMinSec  = [string]"";                                            #Длительность сессии в часы:минуты:секунды
        DurationSecFromBeginTime        = [uint64]$LastRecordXML.Event."Acct-Session-Time"."#text" - $FirstRecord.Event."Acct-Session-Time"."#text"; #Длительность
                                                                                             # сессии в секундах начиная от временногго диапазона DateTimeStart
        DurationHourMinSecFromBeginTime = [string]"";                                  #Длительность сессии в часы:минуты:секунды от начала временного диапазона
        isFirstPacket       = [bool]$false;      #Равен Истине, если это первый пакет в ВПН сессии. ACCT-Status-Type = Start
        isLastPacket        = [bool]$False;      #Равен Истине если это последний пакет в сессии. ACCT-Status-Type = Stop
        DateTimeStart       = [string]$FirstRecordXML.Event."Timestamp"."#text";     #ДатаВремя первого найденого пакета в этой ВПН сессии
        DateTimeEnd         = [string]$LastRecordXML.Event."Timestamp"."#text";      #ДатаВремя последнего найденого пакета в этой ВПН сессии
        RadiusServerName    = [string]$FirstRecordXML.Event."Computer-Name"."#text";         #Имя Радиус-сервера, который первым принял эту сессию
        AuthenticationType  = [string] "";
        TunnelType          = [string]$FirstRecordXML.Event."Tunnel-Assignment-ID"."#text";  #Тип туннеля
        UserExternalIP      = [string]$FirstRecordXML.Event."Tunnel-Client-Endpt"."#text";   #Наружный IP адрес VPN-клиента
        NASServerExternalIP = [string]$FirstRecordXML.Event."Tunnel-Server-Endpt"."#text";   #Наружный IP адрес NAS сервера-Radius клиента
        UserExternalIPGeolocation = [string]""; #Географическое расположение IP адреса клиента из поля UserExternalIP
        TunnelClientIP      = [string]$LastRecordXML.Event."Framed-IP-Address"."#text";      #IP адрес VPN-клиента внутри VPN-туннеля
        NASServerInternalIP = [string]$FirstRecordXML.Event."NAS-IP-Address"."#text";        #IP адрес NAS сервера-Radius клиента внутри VPN-туннеля
        InputOctets         = [uint64]$LastRecordXML.Event."Acct-Input-Octets"."#text";     #Число входящих байт
        InputOctetsFromBeginTime = [uint64]$LastRecordXML.Event."Acct-Input-Octets"."#text" - [uint64]$FirstRecord.Event."Acct-Input-Octets"."#text";    #Число входящих байт от начала временного диапазона
        InputPackets        = [uint64]$LastRecordXML.Event."Acct-Input-Packets"."#text";    #Число входящих пакетов
        InputPacketsFromBeginTime = [uint64]$LastRecordXML.Event."Acct-Input-Packets"."#text" - [uint64]$FirstRecord.Event."Acct-Input-Packets"."#text"; #Число входящих пакетов от начала временного диапазона
        OutputOctets        = [uint64]$LastRecordXML.Event."Acct-Output-Octets"."#text";    #Число исходящих байт
        OutputOctetsFromBeginTime = [uint64]$LastRecordXML.Event."Acct-Output-Octets"."#text" - [uint64]$FirstRecord.Event."Acct-Output-Octets"."#text";    #Число исходящих байт от начала временного диапазона
        OutputPackets       = [uint64]$LastRecordXML.Event."Acct-Output-Packets"."#text";   #Число исходящих пакетов
        OutputPacketsFromBeginTime = [int64]$LastRecordXML.Event."Acct-Output-Packets"."#text" - [uint64]$FirstRecord.Event."Acct-Output-Packets"."#text"; #Число исходящих пакетов от начала временного диапазона
        Class               = $OneSession.Class;                   #Уникальный номер VPN сессии. Соответствует полю Class
        SessionID           = $LastRecordXML.Event."Acct-Session-Id"."#text";               #Почти уникальный номер VPN сессии. Соответствует полю Acct-Session-Id
        TerminateCause      = [string]"";                                  #Причина завершения сеанса. Соответствует полю Acct-Terminate-Cause
        isAccounting        = $True;           # Есть ли у этой VPN сессии Accounting
    })

    #Найти имя пользователя
    $UserNameFromAccessPacket = $OneSession.FirstAccessPacketXML.Event."User-Name"."#text"
    $UserNameFromAccountingPacket = $FirstRecordXML.Event."User-Name"."#text"
    if($UserNameFromAccessPacket.Length -gt 0){
        $VPNSessionDesc.UserName = $UserNameFromAccessPacket
    }else{
        $VPNSessionDesc.UserName = $UserNameFromAccountingPacket
    }
    
    #Найти длительность сессии в часах:минутах:секундах, тип аутентификации (PAP, CHAP, MSCHAP ...), георасположение по IP адресу
    $VPNSessionDesc.DurationHourMinSec  = DurationSecToHourMinSec $VPNSessionDesc.DurationSec   #Почему-то внутри объекта эта команда выдает неверные цифры (нули)
    $VPNSessionDesc.DurationHourMinSecFromBeginTime  = DurationSecToHourMinSec $VPNSessionDesc.DurationSecFromBeginTime #За компанию к предыдущей
    $VPNSessionDesc.AuthenticationType = GetAuthenticationType $OneSession.FirstAccessPacketXML.Event."Authentication-Type"."#text"
    $VPNSessionDesc.UserExternalIPGeolocation = GetIPGeoLocation $VPNSessionDesc.UserExternalIP                         #На всякий случай и эту команду сюда
    
    #Установить признак нашли ли мы самый первый и самый последний Accounting-пакет сессии. 
    #Такое бывает если ВПН сессия началась раньше чем заданный временной диапазон или закончилась позже.
    if(($FirstRecordXML.Event."Packet-Type"."#text" -eq $AccountingRequest) -and 
       ($FirstRecordXML.Event."Acct-Status-Type"."#text" -eq $Start)){
        $VPNSessionDesc.isFirstPacket = $True
    }else{
        $VPNSessionDesc.isFirstPacket = $False    
    }
    if(($LastRecordXML.Event."Packet-Type"."#text" -eq $AccountingRequest) -and 
       ($LastRecordXML.Event."Acct-Status-Type"."#text" -eq $Stop)){
        $VPNSessionDesc.isLastPacket = $True
        $VPNSessionDesc.TerminateCause = GetTerminateCause $LastRecordXML.Event."Acct-Terminate-Cause"."#text"
    }else{
        $VPNSessionDesc.isLastPacket = $False    
    }
    
    #Есть ли у этой сессии Accounting-этап. Это когда сессия успешно началась
    if($OneSession.FirstAcctPacketXML -eq ""){
        $VPNSessionDesc.isAccounting = $False
    }else{
        $VPNSessionDesc.isAccounting = $True
    }
    
    #Если Accounting-этапа нет, то вытащить из Access-этапа все данные что пригодятся
    if($VPNSessionDesc.isAccounting -eq $False){
        $VPNSessionDesc.RadiusServerName    = $OneSession.FirstAccessPacketXML.Event."Computer-Name"."#text"
#        $VPNSessionDesc.NASServerExternalIP = $OneSession.FirstAccessPacketXML.Event."Tunnel-Server-Endpt"."#text"  # В Access-пакетах это поле отсутствует
        $VPNSessionDesc.NASServerInternalIP = $OneSession.FirstAccessPacketXML.Event."NAS-IP-Address"."#text"
#        $VPNSessionDesc.TunnelClientIP      = $OneSession.SecondAccessPacketXML.Event."Framed-IP-Address"."#text" #тут IP адрес будет только если тип второго пакета будет Packet-Type -eq Access-Accept НУЖНА ЛИ ЭТА СТРОКА?
        $VPNSessionDesc.DateTimeStart       = $OneSession.FirstAccessPacketXML.Event."Timestamp"."#text"
        $VPNSessionDesc.DateTimeEnd         = $OneSession.SecondAccessPacketXML.Event."Timestamp"."#text"
    }
    
    #Если IP адрес пользователя в туннеле нет в пакетах Accounting то искать их в Access-пакетах, которые первые два. 
    #Такое бывает, если VPN-сессия продолжалась очень короткое время. IP адрес пльзователя в тунеел появляется только начиная со второго Accounting-пакета
    $ClientIP = $VPNSessionDesc.TunnelClientIP
    if(($ClientIP -eq "") -or ($ClientIP -eq $null) ){
        $VPNSessionDesc.TunnelClientIP = $OneSession.SecondAccessPacketXML.Event."Framed-IP-Address"."#text"
    }

    Return $VPNSessionDesc
}

[array]$Script:AllVPNSessions = $()

#Извлекает характеристики всех VPN сессий 
#Получает массив объектов $OneVPNSessionData, содержащие нужные пакеты одной VPN сессии
#Возвращает объекты $VPNSessionDesc, содержащие все характеристики этой сессии
function GetAllVPNSessions(){
    Write-Host "Подсчет статистики по VPN-сессиям"
    if($Script:VPNSessionsData.Count -eq 0){
        Write-Warning " GetAllSessionsStat: Получено ноль записей в массиве VPN-сессий. Искать информацию о VPN-сессиях негде."
    }
    #Прогресс-бар подготовка
    $k = 0
    $CountSessions = $Script:VPNSessionsData.Count
    $MaxIter = $CountSessions / 100
    if($MaxIter -eq 0){ $MaxIter = 10 }
    $Iter = $MaxIter
    #
    ForEach($OneSession in $Script:VPNSessionsData){
        #Прогрес-бар
        if($Iter-- -le 0){
            $Iter = $MaxIter
            $percentComplete = ($k / $CountSessions) * 100
            Write-Progress -Activity "Подсчет данных" -Status "Сбор сведений о VPN-сессиях" -PercentComplete $percentComplete
        }
        $k++
        #Работа
        $Script:AllVPNSessions += GetStatOneVPNSession $OneSession
    }
    Write-Progress -Activity "Подсчет данных" -Status "Сбор сведений о VPN-сессиях завершен" -Completed
}

$Script:UsersStat = @()

#Подсчет сколько времени, байт, соединений .. было у каждого пользователя
#На основе данных из $Script:AllVPNSessions
#Возвращает массив объектов $StatForUser с статистикой всех сессий каждого поьзователя
function GetStatistic(){  
    if($Script:AllVPNSessions.Count -eq 0){
        Write-Warning " GetUsageStat: получен входной массив нулевой длины"
    }
    ForEach($VPNSession in $Script:AllVPNSessions){
        #Проверить есть ли в массиве статистики запись для этого пользователя
        $isVPNUserRecordExist = $False
        ForEach($I in $Script:UsersStat){
            #Если есть, то обновить
            if($I.UserName -ieq $VPNSession.UserName){
                $isError = $False
#                $I.Connections++
                #если у VPN сессии есть Accounting-этап, то добавляем его статистику
                if($VPNSession.isAccounting -eq $True){
                    $I.ConnectionsOk++
                    $I.DurationSec += $VPNSession.DurationSec
                    $I.DurationHourMinSec = DurationSecToHourMinSec $I.DurationSec
                    $I.DurationSecFromBeginTime += $VPNSession.DurationSecFromBeginTime
                    $I.DurationHourMinSecFromBeginTime  = DurationSecToHourMinSec $I.DurationSecFromBeginTime
                    $VPNSessionDTStartSec = ToSecFrom1970 $VPNSession.DateTimeStart
                    $VPNSessionDTEndSec   = ToSecFrom1970 $VPNSession.DateTimeEnd

                    $IDT = $I.DateTimeFirst
                    if($IDT -eq ""){
                        $I.DateTimeFirst = $VPNSession.DateTimeStart
                    }else{
                        $IDateTimeFirstSec = ToSecFrom1970 $IDT
                        if($VPNSessionDTStartSec -lt $IDateTimeFirstSec){
                            $I.DateTimeFirst = $VPNSession.DateTimeStart
                        }
                    }

                    $IDT = $I.DateTimeLast
                    if($IDT -eq ""){
                        $I.DateTimeLast = $VPNSession.DateTimeEnd
                    }else{
                        $IDateTimeLastSec  = ToSecFrom1970 $IDT
                        if($VPNSessionDTEndSec -gt $IDateTimeLastSec) {
                            $I.DateTimeLast = $VPNSession.DateTimeEnd
                        }
                    }
                    $I.InputOctets                += $VPNSession.InputOctets
                    $I.InputOctetsFromBeginTime   += $VPNSession.InputOctetsFromBeginTime
                    $I.InputPackets               += $VPNSession.InputPackets
                    $I.InputPacketsFromBeginTime  += $VPNSession.InputPacketsFromBeginTime
                    $I.OutputOctets               += $VPNSession.OutputOctets
                    $I.OutputOctetsFromBeginTime  += $VPNSession.OutputOctetsFromBeginTime
                    $I.OutputPackets              += $VPNSession.OutputPackets
                    $I.OutputPacketsFromBeginTime += $VPNSession.OutputPacketsFromBeginTime
                }else{
                    $I.ConnectionsBad++
                }
                $isVPNUserRecordExist = $True
                Break
            }
        }
        #Если пользователь не найден, добавить его в массив статистики
        if(-not $isVPNUserRecordExist){
            $StatForUser =  New-Object -Type PSObject -Property ([ordered]@{
                UserName      = [string]$VPNSession.UserName;
#                Connections   = [uint32]1;
                ConnectionsOk  = [uint32]0;
                ConnectionsBad = [uint32]0;
                DurationSec   = [uint64]0;
                DurationSecFromBeginTime = [uint64]0;
                DurationHourMinSec = [string]"";
                DurationHourMinSecFromBeginTime = [string]"";
                DateTimeFirst = [string]"";
                DateTimeLast  = [string]"";
                InputOctets                = [uint64]0;
                InputOctetsFromBeginTime   = [uint64]0;
                InputPackets               = [uint64]0;
                InputPacketsFromBeginTime  = [uint64]0;
                OutputOctets               = [uint64]0;
                OutputOctetsFromBeginTime  = [uint64]0;
                OutputPackets              = [uint64]0;
                OutputPacketsFromBeginTime = [uint64]0;
            })
            if($VPNSession.isAccounting -eq $True){
                $StatForUser.ConnectionsOk++
                $StatForUser.DurationSec   = [uint64]$VPNSession.DurationSec;
                $StatForUser.DurationSecFromBeginTime = [uint64]$VPNSession.DurationSecFromBeginTime;
                $StatForUser.DurationHourMinSec = DurationSecToHourMinSec $VPNSession.DurationSec;                 #???
                $StatForUser.DurationHourMinSecFromBeginTime = DurationSecToHourMinSec $VPNSession.DurationSecFromBeginTime;
                $StatForUser.DateTimeFirst = [string]$VPNSession.DateTimeStart;
                $StatForUser.DateTimeLast  = [string]$VPNSession.DateTimeEnd;
                $StatForUser.InputOctets                = [uint64]$VPNSession.InputOctets;
                $StatForUser.InputOctetsFromBeginTime   = [uint64]$VPNSession.InputOctetsFromBeginTime;
                $StatForUser.InputPackets               = [uint64]$VPNSession.InputPackets;
                $StatForUser.InputPacketsFromBeginTime  = [uint64]$VPNSession.InputPacketsFromBeginTime;
                $StatForUser.OutputOctets               = [uint64]$VPNSession.OutputOctets;
                $StatForUser.OutputOctetsFromBeginTime  = [uint64]$VPNSession.OutputOctetsFromBeginTime;
                $StatForUser.OutputPackets              = [uint64]$VPNSession.OutputPackets;
                $StatForUser.OutputPacketsFromBeginTime = [uint64]$VPNSession.OutputPacketsFromBeginTime;
            }else{
                $StatForUser.ConnectionsBad++
            }
            $Script:UsersStat += $StatForUser
        }
    }
}

$Script:ResultOnScreen = @()

function NPSLogParser($NPSLogFiles,$DateTimeMinSec,$DateTimeMaxSec){
    $isConditionsOk = $False
    if($DateTimeMinSec -gt $DateTimeMaxSec){
        Write-Warning "NPSLogParser: нижняя граница времени должна быть меньше верхней границы времени"
    } else{
        if($ResultPath -ieq $ResultPathNone){
            $isConditionsOk = $True
        }else{
            if (Test-Path -Path $ResultPath -PathType Container){
                Write-Host "Папка $ResultPath уже существует. Используем ее"
            } else {
                Write-Host " Создание папки $ResultPath"
                New-Item -Path $ResultPath -ItemType "directory" | Out-Null
            }
            if (Test-Path -Path $ResultPath -PathType Container) {
                if( ($StatType -eq $StatTypePerSessions) -or
                    ($StatType -eq $StatTypePerUsers) -or
                    ($StatType -eq "") ){
                    $isConditionsOk = $True
                }else{
                    Write-Warning "Входной параметр StatType должен содержать или $StatTypePerSessions или $StatTypePerUsers"
                }
            }else{
                Write-Warning "Папку $ResultPath не удалось создать"
            }
        }
    }
    if ($isConditionsOk) {
#!!! Потом откоментировать. Эта строка должна быть откоментирована для полноценной работы
        GetNPSLogFilesContent $LogFiles # В массив строк $Script:NSLog сохраняется содержимое NPS-лог файлов 
#!!! Одновременно закоментировать это. Эта строка ТОЛЬКО ДЛЯ ТЕСТОВЫХ целей. В работе должна быть закоментирована
#        $Script:NPSLog = Get-Content $NPSLogFiles -TotalCount 20000
        if($Script:NPSLog.Count -eq 0){
            Write-Warning " NPSLogParser: Прочитано ноль записів. Аналізувати нічого"
        }else{
            Write-Host " Количество записей в логах" $Script:NPSLog.Count
            PrepareNeedData $DateTimeMinSec $DateTimeMaxSec #В массив $Script:VPNSessionsDataзаносит покаждой сессии только пакеты которые потом нужны для анализа
            GetAllVPNSessions                               #В массив $Script:AllVPNSessions обектов $VPNSessionDesc заполняет характеристиками каждой VPN сессии
            GetStatistic                                    #Из масива $Script:AllVPNSessions сводит статистику по пользователю в массив $Script:UsersStat
            if($ResultPath -ine $ResultPathNone){
                Write-Host "Сохраняю результаты работы в файлы $ResultSessionsFile и $ResultUsersFile"
                ExportObjectToCSV $Script:AllVPNSessions $ResultSessionsFile
                ExportObjectToCSV $Script:UsersStat $ResultUsersFile
            }
            switch($StatType){
                $StatTypePerSessions { $Script:ResultOnScreen = $Script:AllVPNSessions }
                $StatTypePerUsers    { $Script:ResultOnScreen = $Script:UsersStat }
                Default              { $Script:ResultOnScreen = $Script:AllVPNSessions }
            }
            
        }
    }
}

Write-Host "Аналіз DTS-логов NPS-Radius сервера Windows."
Write-Host "https://github.com/AlexandrGS/NPSLogParser"
$PSVersionMajor = $PSVersionTable.PSVersion.Major
if ($PSVersionMajor -lt 3){
    Write-Warning "Для виконаня скрипта потрібен мінімум Powershell v3, а встановлен " $PSVersionMajor
}else{
    if($ResultPath -ine $ResultPathNone){
        if ($ResultPath -eq ""){
            $ResultPath = ".\Result_" + (Get-Date -Format "yyyy_MM_dd_HH_mm_ss")
        }
    }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $watch.Start() #Запуск таймера

    $DateTimeMinSec = Get-Date -UFormat %s -Year $MinYear -Month $MinMonth -Day $MinDay -Hour $MinHour -Minute $MinMin -Second $MinSec -Millisecond $MinMSec
    $DateTimeMaxSec = Get-Date -UFormat %s -Year $MaxYear -Month $MaxMonth -Day $MaxDay -Hour $MaxHour -Minute $MaxMin -Second $MaxSec -Millisecond $MaxMSec
    NPSLogParser $LogFiles $DateTimeMinSec $DateTimeMaxSec
    $Script:ResultOnScreen

    $watch.Stop() #Остановка таймера
    Write-Host "Час виконаня скрипта" $watch.Elapsed #Время выполнения
    if( $Global:isIPGeoLocationEnable ){
        Write-Host "При пошуку геопозиції по IP адресу " $Script:CountResolvingIPGeo " адрес було знайдено через інтернет, а " $Script:CountHitToIPAndGeoArray " адрес знайдено во внутрішньому буфері"
    }
}
