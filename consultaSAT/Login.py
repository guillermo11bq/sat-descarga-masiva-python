import requests
from datetime import datetime, timedelta
from base64 import b64encode

from . import Utils

class TokenRequest:

    soap_action = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica'
    url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc'
    
    def soapRequest(self, certificate: bytes, keyPEM: str):
        xml = self.getSOAPBody(certificate, keyPEM)
        headers = Utils.headers(xml=xml, soapAction=self.soap_action)
        
        soap_request = requests.post(url=self.url, data=xml, headers=headers, timeout=10)
        xmlResponse = soap_request.text
        
        tree = Utils.xml_etree(xmlResponse)
        
        AutenticaResultElement = tree.find('Body/AutenticaResponse/AutenticaResult')
        
        if AutenticaResultElement is not None:
            sat_token = AutenticaResultElement.text
            return sat_token
        else:
            print(xmlResponse)
            return None
            #Raise error
        
        
    def getSOAPBody(self, cert, keyPEM):
        
        uuid = Utils.generateUUID()
        
        fecha_inicial = datetime.today().utcnow()
        fecha_final =  fecha_inicial + timedelta(minutes=5)
        
        fecha_inicial = fecha_inicial.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        fecha_final = fecha_final.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        data = '<u:Timestamp ' \
               'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ' \
               'u:Id="_0">' \
               '<u:Created>{created}</u:Created>' \
               '<u:Expires>{expires}</u:Expires>' \
               '</u:Timestamp>'.format(created=fecha_inicial, expires=fecha_final)
        
        digest_value = Utils.b64_sha1_digest(data)
        
        dataToSign = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' \
                     '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">' \
                     '</CanonicalizationMethod>' \
                     '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1">' \
                     '</SignatureMethod><Reference URI="#_0">' \
                     '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">' \
                     '</Transform></Transforms>' \
                     '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
                     '<DigestValue>{digest_value}</DigestValue>' \
                     '</Reference></SignedInfo>'.format(digest_value=digest_value)
        
        signature = Utils.b64_signature_pkey(dataToSign, keyPEM)
        
        b64certificate = b64encode(cert).decode('ascii')
        
        xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' \
              'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' \
              '<s:Header><o:Security s:mustUnderstand="1" ' \
              'xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' \
              '<u:Timestamp u:Id="_0"><u:Created>{created}</u:Created>' \
              '<u:Expires>{expires}</u:Expires></u:Timestamp>' \
              '<o:BinarySecurityToken u:Id="{uuid}" ' \
              'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" ' \
              'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0' \
              '#Base64Binary">{b64certificate}</o:BinarySecurityToken>' \
              '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>' \
              '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' \
              '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0">' \
              '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' \
              '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' \
              '<DigestValue>{digest_value}</DigestValue></Reference></SignedInfo>' \
              '<SignatureValue>{b64signature}</SignatureValue>' \
              '<KeyInfo><o:SecurityTokenReference><o:Reference ' \
              'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" ' \
              'URI="#{uuid}"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header>' \
              '<s:Body><Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/></s:Body></s:Envelope>'.format(
            created = fecha_inicial,
            expires = fecha_final,
            uuid = uuid,
            b64certificate = b64certificate,
            digest_value = digest_value,
            b64signature = signature
        )

        xml = xml.encode('utf-8')

        return xml