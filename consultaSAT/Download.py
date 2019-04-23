import requests
from datetime import datetime, timedelta
from base64 import b64encode

from . import Utils


class DownloadRequest:
    soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar'
    url = 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc'
    
    def soapRequest(self, certificate: bytes, keyPEM: str, token: str, id_paquete: str, path: str):
        xml = self.getSOAPBody(certificate=certificate, keyPEM=keyPEM, id_paquete=id_paquete)
        headers = Utils.headers(xml=xml, soapAction=self.soap_action, token=token)
        soap_request = requests.post(url=self.url,data=xml,headers=headers)
        
        xmlResponse = soap_request.text
        
        tree = Utils.xml_etree(xmlResponse)

        DownloadResultElement = tree.find('Body/RespuestaDescargaMasivaTercerosSalida/Paquete')
        fault = tree.find('Body/Fault')

        if DownloadResultElement is not None:
            #Cambiar por NamedTuples
            b64_data = DownloadResultElement.text
            
            filename = path + id_paquete + '.zip'
            
            Utils.saveBase64File(filename=filename, data=b64_data)
            
            return filename
        elif fault is not None:
            #raise error
            fault_dict = {
                'code': fault.find('faultcode').text,
                'message': fault.find('faultstring').text
            }
            return None
        else:
            return None
            # Raise error

        #return soap_request
        
        
    def getSOAPBody(self, certificate: bytes, keyPEM: str, id_paquete: str):
        
        rfc = Utils.rfc_from_certificate(certificate)

        data = '<des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">' \
               '<des:peticionDescarga IdPaquete="{id_paquete}" RfcSolicitante="{rfc}"></des:peticionDescarga>' \
               '</des:PeticionDescargaMasivaTercerosEntrada>'.format(id_paquete=id_paquete, rfc=rfc)
        
        digest_value = Utils.b64_sha1_digest(data)
        
        dataToSign = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod ' \
                     'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod ' \
                     'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI="">' \
                     '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>' \
                     '</Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
                     '<DigestValue>{digest_value}</DigestValue></Reference>' \
                     '</SignedInfo>'.format(digest_value=digest_value)
        
        signature = Utils.b64_signature_pkey(dataToSign, keyPEM)
        
        b64certificate = Utils.b64_certificate(certificate)
        serial_number = Utils.certificate_serial_number(certificate)
        issuer_data_string = Utils.issuer_data_string(certificate)
        
        xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' \
              'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">' \
              '<s:Header/><s:Body><des:PeticionDescargaMasivaTercerosEntrada><des:peticionDescarga ' \
              'IdPaquete="{id_paquete}" RfcSolicitante="{rfc}"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' \
              '<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' \
              '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="">' \
              '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' \
              '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
              '<DigestValue>{digest_value}</DigestValue></Reference></SignedInfo>' \
              '<SignatureValue>{signature}</SignatureValue><KeyInfo><X509Data><X509IssuerSerial>' \
              '<X509IssuerName>{issuer_data}</X509IssuerName>' \
              '<X509SerialNumber>{certificate_serial}</X509SerialNumber></X509IssuerSerial>' \
              '<X509Certificate>{b64_certificate}</X509Certificate></X509Data></KeyInfo></Signature>' \
              '</des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada></s:Body>' \
              '</s:Envelope>'.format(id_paquete=id_paquete, rfc=rfc, digest_value=digest_value, signature=signature,
                                     issuer_data=issuer_data_string, certificate_serial=serial_number,
                                     b64_certificate=b64certificate)
        
        xml = xml.encode('utf-8')
        
        return xml