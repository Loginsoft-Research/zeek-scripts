# @load-sigs ./cve_2021_1675.sig

@load base/protocols/smb
@load base/frameworks/notice


module Print_nightmare;

export{
	redef enum Notice::Type +={
		windows_print_spooler,
	};
	global suspicious_operations: set[string] =   {"RpcAsyncAddPrinterDriver","RpcAddPrinterDriverEx","AddPrinterDriverEx"};
}


event dce_rpc_response(c:connection,fid:count,ctx_id:count,opnum:count,stub_len:count)
{	
	if (c$dce_rpc$operation in suspicious_operations)	
		{
			local test1=match_pattern(c$dce_rpc$endpoint,/spoolss/);
			if(test1$matched)
			{
				NOTICE([$note=windows_print_spooler,
				$conn=c,
				$msg=fmt("Possible CVE-2021-1675 (PrintNightmare) Exploit - SpoolSS RpcAddPrinterDriver")
				]);
				}
			}
	else		
	
		print("Nothing seems to be malicious....");
}
