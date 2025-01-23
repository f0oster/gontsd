$sd = Get-Acl "./file-for-sd-domain.txt"
[IO.File]::WriteAllBytes(".\sd-domain.bin", $sd.GetSecurityDescriptorBinaryForm())