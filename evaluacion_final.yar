/* REGLAS PARA DETECCIÓN DE POTENCIAL RAT REMCOS */

rule Email_Phishing {

meta:
  author = "Grupo 10 - USACH"
  date = "18-12-2022"
  description = "Busca Potencial Email Phishing con Contenido Codificado Base64"

strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"
  
  $key_1 = "BTC" nocase
  $key_2 = "Wallet" nocase
  $key_3 = "Bitcoin" nocase
  $key_4 = "hours" nocase
  $key_5 = "payment" nocase
  $key_6 = "malware" nocase
  $key_7 = "bitcoin address" nocase
  $key_8 = "access" nocase
  $key_9 = "virus" nocase

  $mime = "MIME-Version:"
  $base64 = "Content-Transfer-Encoding: base64"
  $mso = "Content-Type: application/x-mso" 

condition:
  all of ($eml*) and
  ((any of ($key*)) and $mime and ($base64 or $mso))
}

/*--------------------------------------------------------------------------------------------------------*/

rule Archivo_Sospechoso {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Patrones de Archivos con VBA sospechosos"

strings:
  $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
  $zipmagic = "PK"
  $vba1 = "_VBA_PROJECT_CUR" wide
  $vba2 = "VBAProject"
  $vba3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
  $xmlstr1 = "vbaProject.bin"
  $xmlstr2 = "vbaData.xml"
  $string1 = "[Content_Types].xml"

condition:
  ($officemagic at 0 and any of ($vba*)) or ($zipmagic at 0 and any of ($xmlstr*) or $string1)
}

/*--------------------------------------------------------------------------------------------------------*/

rule Conexiones_Sospechosas {

meta:
  author = "Grupo 10 - USACH"
  date = "18-12-2022"
  description = "Busca conexiones sospechosas en capturas de trafico PCAP"

strings:
  $ip1 = "13.107.42.13"
  $ip2 = "64.188.19.241"
  $ip3 = "104.223.119.167"
  $ip4 = "79.134.225.79"  

  $url1 ="http://64.188.19.241/atcn.jpg"
  $url2 ="http://104.223.119.167/calient.jpg"
  $url3 ="shiestynerd.dvrlists.com"  

condition:
  any of them
}
