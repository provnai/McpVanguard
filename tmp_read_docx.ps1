Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead("C:\Users\quint\Desktop\McpVanguard_Submission_Checklist.docx")
$entry = $zip.Entries | Where-Object { $_.FullName -eq "word/document.xml" }
$stream = $entry.Open()
$reader = New-Object System.IO.StreamReader($stream)
$content = $reader.ReadToEnd()
$reader.Close()
$stream.Close()
$zip.Dispose()
$content | Out-File -FilePath "C:\Users\quint\Desktop\provnai\McpVanguard\checklist_content.xml" -Encoding utf8
