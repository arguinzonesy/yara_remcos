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

rule IP_Sospechosa 

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca IP en la captura de Trafico"
  
strings:
  $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
  
condition:
  any of them
}
