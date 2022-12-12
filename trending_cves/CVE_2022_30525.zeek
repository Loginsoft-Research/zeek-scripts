@load base/protocols/http
@load base/frameworks/notice

module CVE_2022_30525;

export{
	redef enum Notice::Type +={
		CVE_2022_30525_exploit,
	};
	global post_data_command_pattern:pattern =/setWanPortSt/;
	global post_data_mtu_pattern:pattern=/ping/;
	global post_data:pattern=/command/;
	global post_data_match:pattern=/mtu/;
}
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{	
	if(c$http$method == "POST" && c$http$uri == "/ztp/cgi-bin/handler")		
	{
		if(post_data in data && post_data_match in data)			
		{
			if(post_data_command_pattern in data && post_data_mtu_pattern in data)
			{
				NOTICE([$note=CVE_2022_30525_exploit,
				$conn=c,
				$sub="Possible Zyxel ZTP setWanPortSt mtu Exploit",
				$msg="Misc-attack"
				]);
			}
		}
	}

}



#https://github.com/ProngedFork/CVE-2022-30525/blob/main/CVE-2022-30525.py