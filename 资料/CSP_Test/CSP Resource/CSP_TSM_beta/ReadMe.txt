����csp�������̣�
1��ѡ����windowsXP SP2 �н���csp�������谲װTSM��

2����csp��Ҫǩ����֤�����Խ�"advapi32.dll"�滻��"c:\windows\system32"Ŀ¼�¡�ע������������ڰ�ȫģʽ�½����滻��������Ҫ��dos������������:
	��1 ��"advapi32.dll"������C�̸�Ŀ¼�£�
	��2 dos������ 
	cd c:\windows\system32
	expand advapi32.dll advapi32.dll__
	copy c:\advapi32.dll 

3> �� "csp.dll"��"csp.sig"����"cspSign.exe" �� ����"c:\windows\system32"�£���"Install CspDll.bat"����"csp.dll"ע�ᵽע����С�

4> ����"Install CspDll.bat",csp�������ϣ����� "testcsp.exe" ���ɡ�

�ļ��嵥��
csp.dll
csp.sig 
cspSign.exe 
advapi32.dll 
testcsp.exe 
Install CspDll.bat
