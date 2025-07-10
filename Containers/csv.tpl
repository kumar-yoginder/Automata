"Package","Version Installed","Vulnerability ID","Severity"
{{- range $ri, $r := . }}
{{- range $vi, $v := .Vulnerabilities }}
"{{ $v.PkgName }}","{{$v.InstalledVersion }}","{{ $v.VulnerabilityID }}","{{$v.Severity}}"  
{{- end}}
{{- end }}
