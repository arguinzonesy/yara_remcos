/* REGLAS PARA DETECCIÓN DE POTENCIAL RAT REMCOS */

rule Email_Phishing {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Potencial Email Phishing con Contenido Codificado Base64"

strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"

  $hi_1="Hola sr/sra" nocase 
  $hi_2="Hello sir/madam" nocase
  $hi_3="Atencion" nocase
  $hi_4="Attention" nocase
  $hi_5="Dear user" nocase
  $hi_6="Account holder" nocase

  $key_1 = "BTC" nocase
  $key_2 = "Wallet" nocase
  $key_3 = "Bitcoin" nocase
  $key_4 = "hours" nocase
  $key_5 = "payment" nocase
  $key_6 = "malware" nocase
  $key_7 = "bitcoin address" nocase
  $key_8 = "access" nocase
  $key_9 = "virus" nocase

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

  $mime = "MIME-Version:"
  $base64 = "Content-Transfer-Encoding: base64"
  $mso = "Content-Type: application/x-mso" 

condition:
  all of ($eml*) and
  any of ($hi*) and 
  any of ($key*) or 
  any of ($url*) or 
  any of ($lie*) and ($mime at 0 and $base64 and $mso)
}



rule Archivo_Sospechoso {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Patrones de Archivos con VBA y que contengan codificación Base64"

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


/*

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
*/
