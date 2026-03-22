rule Suspicious_Executable
{
    meta:
        description = "Phát hiện file thực thi (EXE/DLL) ẩn"
        author = "Local_APT_Module"
        severity = "High"
    
    strings:
        // 'MZ' là dấu hiệu nhận biết (Magic Bytes) của mọi file .exe trên Windows
        $mz_header = { 4D 5A } 
        
        // Các chuỗi lệnh thường bị hacker lạm dụng trong file macro/script
        $cmd1 = "powershell.exe -nop -w hidden" nocase
        $cmd2 = "WScript.Shell" nocase

    condition:
        // Báo động nếu file bắt đầu bằng MZ hoặc chứa các lệnh nguy hiểm
        ($mz_header at 0) or $cmd1 or $cmd2
}