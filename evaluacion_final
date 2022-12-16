/* -------------------------
------ Remcos RAT-----------
--------------------------- */

rule RemcosRATByName
{
meta:
 author = "@neonprimetime"
 description = "Remcos RAT"
strings:
 $string0 = "Software\\Remcos" nocase
 $string1 = "\\remcos\\" nocase
 $string2 = "REMCOS v" nocase
 $string4 = "Remcos_" nocase
condition:
 1 of them
}

rule EmailGenericPhishing
{
strings:
 $eml_1="From:"
 $eml_2="To:"
 $eml_3="Subject:"

$greeting_1="Hello sir/madam" nocase
 $greeting_2="Attention" nocase
 $greeting_3="Dear user" nocase
 $greeting_4="Account holder" nocase

$url_1="Click" nocase
 $url_2="Confirm" nocase
 $url_3="Verify" nocase
 $url_4="Here" nocase
 $url_5="Now" nocase
 $url_6="Change password" nocase 

$lie_1="Unauthorized" nocase
 $lie_2="Expired" nocase
 $lie_3="Deleted" nocase
 $lie_4="Suspended" nocase
 $lie_5="Revoked" nocase
 $lie_6="Unable" nocase
 
condition:
 all of ($eml*) and
 any of ($greeting*) and
 any of ($url*) and
 any of ($lie*)
}

rule extortion_email
{
  meta:
    author = "milann shrestha <Twitter - @x0verhaul>"
		description = "Detects the possible extortion scam on the basis of subjects and keywords"
		data = "12th May 2020"

	strings:
	  $eml1="From:"
    $eml2="To:"
    $eml3="Subject:"
		
		// Common Subjects scammer keep for luring the targets 
    $sub1 = "Hackers know password from your account."
    $sub2 = "Security Alert. Your accounts were hacked by a criminal group."
    $sub3 = "Your account was under attack! Change your credentials!"
    $sub4 = "The decision to suspend your account. Waiting for payment"
    $sub5 = "Fraudsters know your old passwords. Access data must be changed."
    $sub6 = "Your account has been hacked! You need to unlock it."
    $sub7 = "Be sure to read this message! Your personal data is threatened!"
    $sub8 = "Password must be changed now."
		// Keywords used for extortion
    $key1 = "BTC" nocase
    $key2 = "Wallet" nocase
    $key3 = "Bitcoin" nocase
    $key4 = "hours" nocase
    $key5 = "payment" nocase
    $key6 = "malware" nocase
    $key = "bitcoin address" nocase
    $key7 = "access" nocase
    $key8 = "virus" nocase
	condition: 
    all of ($eml*) and
    any of ($sub*) and
    any of ($key*)
}

rule RemcosRATByKeyword
{
meta:
 author = "@neonprimetime"
 description = "Remcos RAT"
strings:
 $string1 = "Keylogger Started" nocase
 $string2 = "Connected to C&C" nocase
 $string3 = "Screenshots" nocase
 $string4 = "OpenCamera" nocase
 $string5 = "Uploading file to C&C" nocase
 $string6 = "Initializing connection to C&C" nocase
 $string7 = "cleared!]" nocase
 $string8 = "EnableLUA /t REG_DWORD /d 0" nocase
 $string9 = "RemWatchdog" nocase
 $string10 = "restarted by watchdog" nocase
condition:
 3 of them
}

rule office_document_vba : maldoc
{
	meta:
		description = "Office document with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
		reference = "https://github.com/jipegit/"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"
		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"
	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule MIME_MSO_ActiveMime_base64 : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso and $activemime
}

rule IP {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
        $ipv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/ wide ascii
    condition:
        any of them
}

rule RemcosCustom{

strings:
 $s1 = "b1df072eba923c472e461200b35823fde7f8e640bfb468ff5ac707369a2fa35e"
 $s2 = "[Content_Types].xml"
 $s3 = "ePK"
 $hash = "61393cc2ed5c3e69c914089e2d1eafc2"
 $PK = "PK"
 
condition:
 1 of them
 }
