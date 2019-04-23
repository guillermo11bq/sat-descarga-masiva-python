import requests
from datetime import datetime, timedelta
from base64 import b64encode

from . import Utils


class RequestDownloadRequest:
    XML_FACTURAS = 'CFDI'
    METADATOS = 'METADATA'
    
    soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga'
    url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc'
    
    # La documentacion oficial no ha sido suficiente para determinar si se debe solicitar utilizando
    # la zona horaria UTC, por lo que se hace la solicitud sin zona horaria, la interpretacion de la misma
    # depende del SAT
    def soapRequest(self, certificate: bytes, keyPEM: str, token: str, start_date: datetime, end_date: datetime,
                    tipo_solicitud = XML_FACTURAS):
        xml = self.getSOAPBody(certificate=certificate, keyPEM=keyPEM, start_date=start_date, end_date=end_date,
                               tipo_solicitud=tipo_solicitud)
        headers = Utils.headers(xml=xml, soapAction=self.soap_action, token=token)
        soap_request = requests.post(url=self.url,data=xml,headers=headers)
        
        xmlResponse = soap_request.text
        
        tree = Utils.xml_etree(xmlResponse)

        SolicitaResultElement = tree.find('Body/SolicitaDescargaResponse/SolicitaDescargaResult')
        fault = tree.find('Body/Fault')

        if SolicitaResultElement is not None:
            #Cambiar por NamedTuples
            solicitud_dict = SolicitaResultElement.attrib
            return solicitud_dict
        elif fault is not None:
            code = fault.find('faultcode').text
            message = fault.find('faultstring').text
            
            raise Exception(
                'El servidor repondio con el error {code}: {message}'.format(code=code, message=message)
            )
        else:
            raise Exception('El servidor no respondio, revisa tus parametros e intenta mas tarde')
        #return soap_request
        
        
    def getSOAPBody(self, certificate: bytes, keyPEM: str, start_date: datetime, end_date: datetime,
                    tipo_solicitud = XML_FACTURAS):
        
        rfc = Utils.rfc_from_certificate(certificate)
        fecha_inicial = start_date.strftime('%Y-%m-%dT%H:%M:%S')
        fecha_final = end_date.strftime('%Y-%m-%dT%H:%M:%S')

        data = '<des:SolicitaDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">' \
               '<des:solicitud RfcEmisor="{rfc}" RfcSolicitante="{rfc}" FechaInicial="{fecha_inicial}" ' \
               'FechaFinal="{fecha_final}" TipoSolicitud="{tipo_solicitud}"></des:solicitud>' \
               '</des:SolicitaDescarga>'.format(rfc=rfc, fecha_inicial=fecha_inicial, fecha_final=fecha_final,
                                                tipo_solicitud=tipo_solicitud)
        
        digest_value = Utils.b64_sha1_digest(data)
        
        dataToSign = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod ' \
                     'Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>' \
                     '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>' \
                     '<Reference URI=""><Transforms><Transform ' \
                     'Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms>' \
                     '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
                     '<DigestValue>{digest_value}</DigestValue></Reference>' \
                     '</SignedInfo>'.format(digest_value=digest_value)
        
        signature = Utils.b64_signature_pkey(dataToSign, keyPEM)
        
        b64certificate = Utils.b64_certificate(certificate)
        serial_number = Utils.certificate_serial_number(certificate)
        issuer_data_string = Utils.issuer_data_string(certificate)
        
        xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' \
              'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">' \
              '<s:Header/><s:Body><des:SolicitaDescarga><des:solicitud RfcEmisor="{rfc}" RfcSolicitante="{rfc}" ' \
              'FechaFinal="{fecha_final}" FechaInicial="{fecha_inicial}" TipoSolicitud="{tipo_solicitud}">' \
              '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod ' \
              'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod ' \
              'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI="#_0">' \
              '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms>' \
              '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' \
              '<DigestValue>{digest_value}</DigestValue></Reference></SignedInfo>' \
              '<SignatureValue>{signature_value}</SignatureValue><KeyInfo><X509Data><X509IssuerSerial>' \
              '<X509IssuerName>{issuer_data}</X509IssuerName><X509SerialNumber>{serial_number}</X509SerialNumber>' \
              '</X509IssuerSerial><X509Certificate>{b64_certificate}</X509Certificate></X509Data></KeyInfo>' \
              '</Signature></des:solicitud></des:SolicitaDescarga></s:Body>' \
              '</s:Envelope>'.format(rfc=rfc,fecha_inicial=fecha_inicial,fecha_final=fecha_final,
                                     tipo_solicitud=tipo_solicitud,digest_value=digest_value,
                                     signature_value=signature,issuer_data=issuer_data_string,
                                     b64_certificate=b64certificate,serial_number=serial_number)
        
        xml = xml.encode('utf-8')
        
        return xml