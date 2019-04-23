from io import StringIO, BytesIO
import random
import base64
import chilkat2
import sys
from lxml import etree
from OpenSSL import crypto
import hashlib

def generateUUID():
    uuid = '{normal:04x}{normal:04x}-{normal:04x}-{0:04x}-{1:04x}-{normal:04x}{normal:04x}{normal:04x}'.format(
        random.randint(0, 0x0fff) | 0x4000,
        random.randint(0, 0x3fff) | 0x8000,
        normal=random.randint(0, 0xffff),
    )
    
    uuid = 'uuid-' + uuid + '-1'
    
    return uuid


def headers(xml, soapAction, token=None):
    dictHeaders = {
        'Content-type': 'text/xml;charset="utf-8"',
        'Accept': 'text/xml',
        'cache-control': 'no-cache',
        'SOAPAction': soapAction,
        #'Content-length': str(sys.getsizeof(xml)),
    }
    
    if token is not None:
        dictHeaders.update({'Authorization': 'WRAP access_token="{token}"'.format(token=token)})
    
    return dictHeaders


def saveBase64File(filename, data):
    with open(filename, 'wb') as file:
        file.write(base64.b64decode(data))
    
    return True


def derToPemCertificate(DERData):
    """
    public static function derToPem($der_data, $type = 'CERTIFICATE')
{
    $pem = chunk_split(base64_encode($der_data), 64, "\n");
    $pem = "-----BEGIN " . $type . "-----\n" . $pem . "-----END " . $type . "-----\n";
    return $pem;
}
    :return:
    """
    
    certificate = chilkat2.Cert()
    certificate.LoadFromBinary(DERData)
    
    return certificate.ExportCertPem()


def purifySatXml(xml):
    forgettable_characters = ['s', 'o', 'u', 'h']
    strings_to_erase = ['%s:' % (character) for character in forgettable_characters]
    '''
    for string in strings_to_erase:
        xml = xml.replace(string, '')
        '''
    #xml = '<?xml version="1.0" encoding="utf-8"?>' + xml
    return xml


def xml_etree(xml):
    
    #https://stackoverflow.com/questions/14853243/parsing-xml-with-namespace-in-python-via-elementtree
    # http://wiki.tei-c.org/index.php/Remove-Namespaces.xsl
    xslt_remove_namespaces = '''<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="xml" indent="no"/>
    <xsl:template match="/|comment()|processing-instruction()">
        <xsl:copy>
          <xsl:apply-templates/>
        </xsl:copy>
    </xsl:template>
    <xsl:template match="*">
        <xsl:element name="{local-name()}">
          <xsl:apply-templates select="@*|node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="@*">
        <xsl:attribute name="{local-name()}">
          <xsl:value-of select="."/>
        </xsl:attribute>
    </xsl:template>
    </xsl:stylesheet>
    '''
    xslt_doc = etree.parse(BytesIO(xslt_remove_namespaces.encode('ascii')))
    remove_namespaces = etree.XSLT(xslt_doc)
    
    xml = purifySatXml(xml)
    xmlStream = StringIO(xml)

    tree = etree.parse(xmlStream)
    tree = remove_namespaces(tree)
    
    return tree


def b64_signature_pkey(dataToSign, pkeyPEM) -> str:
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, pkeyPEM)
    signature = crypto.sign(private_key, dataToSign, 'sha1')
    signature = base64.b64encode(signature).decode('ascii')
    
    return signature


def b64_sha1_digest(data):
    digest_value = base64.b64encode(hashlib.sha1(data.encode()).digest()).decode('ascii')
    return digest_value


def issuer_data_string(certificate: bytes) -> str:
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
    issuer = certificate.get_issuer()

    data_string = ','.join(
        map(
            lambda tuple: b'='.join(tuple).decode('utf-8'),
            issuer.get_components()
        )
    )
    
    return data_string


def get_subject_utf8components(certificate: bytes) -> dict:
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
    subject = certificate.get_subject()
    components = subject.get_components()
    
    components_dictionary = dict(
        [(component_tpl[0].decode('utf-8'), component_tpl[1].decode('utf-8')) for component_tpl in components]
    )
    return components_dictionary


def rfc_from_certificate(certificate: bytes) -> str:
    components_dictionary = get_subject_utf8components(certificate)
    rfc = components_dictionary['x500UniqueIdentifier']
    
    return rfc


def certificate_serial_number(certificate: bytes) -> int:
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
    serial_number = certificate.get_serial_number()
    
    return serial_number


def b64_certificate(certificate: bytes) -> str:
    return base64.b64encode(certificate).decode('ascii')


def pkey_to_pem(public_key_path: str, password: str) -> str:
    key = chilkat2.PrivateKey()
    
    key.LoadPkcs8EncryptedFile(public_key_path, password)
    keyPEM = key.GetPkcs8Pem()
    
    return keyPEM


def pkey_buffer_to_pem(private_key: BytesIO, password: str) -> str:
    key = chilkat2.PrivateKey()
    # Si suben un archivo muy grande (las .key no lo son) la siguiente linea puede sobrecargar el servidor
    view = memoryview(private_key.read())
    
    key.LoadPkcs8Encrypted(view, password)
    keyPEM = key.GetPkcs8Pem()
    
    return keyPEM

def read_as_bytes(path: str):
    with open(path, 'rb') as data:
        bytes_data = data.read()
    return bytes_data
