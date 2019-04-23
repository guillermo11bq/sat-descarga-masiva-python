import requests
import collections
from datetime import datetime, timedelta
from base64 import b64encode

from . import Utils


Verification = collections.namedtuple(typename='Verification', field_names='ready paquetes error')

class VerifyRequest:
    XML_FACTURAS = 'CFDI'
    METADATOS = 'METADATA'
    
    soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga'
    url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc'
    
    def soapRequest(self, certificate: bytes, keyPEM: str, token: str, id_solicitud: str):
        xml = self.getSOAPBody(certificate=certificate, keyPEM=keyPEM, id_solicitud=id_solicitud)
        headers = Utils.headers(xml=xml, soapAction=self.soap_action, token=token)
        soap_request = requests.post(url=self.url,data=xml,headers=headers)
        
        xmlResponse = soap_request.text
        
        tree = Utils.xml_etree(xmlResponse)

        VerificaResultElement = tree.find('Body/VerificaSolicitudDescargaResponse/VerificaSolicitudDescargaResult')
        fault = tree.find('Body/Fault')

        if VerificaResultElement is not None:
            verifica_dict = VerificaResultElement.attrib
            
            if verifica_dict['EstadoSolicitud'] == '3':
                verifica_dict['IdsPaquetes'] = VerificaResultElement.find('IdsPaquetes').text
                if verifica_dict['IdsPaquetes']:
                    lista_paquetes = verifica_dict['IdsPaquetes'].split(',')
                else:
                    lista_paquetes = None
                
                verificacion = Verification(ready=True, paquetes=lista_paquetes, error=None)
                return verificacion
            
            verificacion = Verification(ready=False, paquetes=None, error=None)
        
        elif fault is not None:
            #raise error
            fault_dict = {
                'code': fault.find('faultcode').text,
                'message': fault.find('faultstring').text
            }
            verificacion = Verification(ready=False, paquetes=None, error=fault_dict)
        else:
            verificacion = Verification(ready=False, paquetes=None, error=True)
            # Raise error

        return verificacion
        
        
    def getSOAPBody(self, certificate: bytes, keyPEM: str, id_solicitud: str):
        
        rfc = Utils.rfc_from_certificate(certificate)

        data = '<des:VerificaSolicitudDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">' \
               '<des:solicitud IdSolicitud="{id_solicitud}" RfcSolicitante="{rfc}"></des:solicitud>' \
               '</des:VerificaSolicitudDescarga>'.format(id_solicitud=id_solicitud, rfc=rfc)
        
        digest_value = Utils.b64_sha1_digest(data)
        
        dataToSign = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod ' \
                     'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>' \
                     '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>' \
                     '<Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">' \
                     '</Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">' \
                     '</DigestMethod><DigestValue>{digest_value}</DigestValue></Reference>' \
                     '</SignedInfo>'.format(digest_value=digest_value)
        
        signature = Utils.b64_signature_pkey(dataToSign, keyPEM)
        
        b64certificate = Utils.b64_certificate(certificate)
        serial_number = Utils.certificate_serial_number(certificate)
        issuer_data_string = Utils.issuer_data_string(certificate)
        
        xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' \
              'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">' \
              '<s:Header/><s:Body><des:VerificaSolicitudDescarga><des:solicitud IdSolicitud="{id_solicitud}" ' \
              'RfcSolicitante="{rfc}"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>' \
              '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod ' \
              'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform ' \
              'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod ' \
              'Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
              '<DigestValue>{digest_value}</DigestValue></Reference></SignedInfo>' \
              '<SignatureValue>{signature}</SignatureValue><KeyInfo><X509Data><X509IssuerSerial>' \
              '<X509IssuerName>{issuer_data}</X509IssuerName><X509SerialNumber>{serial}</X509SerialNumber>' \
              '</X509IssuerSerial><X509Certificate>{b64_certificate}</X509Certificate></X509Data></KeyInfo>' \
              '</Signature></des:solicitud></des:VerificaSolicitudDescarga></s:Body>' \
              '</s:Envelope>'.format(id_solicitud=id_solicitud, rfc=rfc, digest_value=digest_value,
                                     signature=signature, issuer_data=issuer_data_string,
                                     serial=serial_number, b64_certificate=b64certificate)
        
        xml = xml.encode('utf-8')
        
        return xml