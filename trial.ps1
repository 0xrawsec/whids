$version = "v1.2.1"
$url = "https://github.com/0xrawsec/whids/releases/download/$version"
$arch = $ENV:PROCESSOR_ARCHITECTURE
$bin = "$PWD\"+"whids.exe"
$remoteBinBase = "whids-$version-"

If ( $arch -eq "AMD64" ) {
  $url = $url + "/$remoteBinBase" + "amd64.exe"
} else {
  $url = $url + "/$remoteBinBase" + "386.exe"
}

Write-Output "Downloading: $url"
Write-Output "WHIDS Path: $bin"
[Net.ServicePointManager]::SecurityProtocol = "tls12"
$client = New-Object System.Net.WebClient
$client.DownloadFile($url, $bin)

& $bin -v
& $bin -t 1 -u -c all
